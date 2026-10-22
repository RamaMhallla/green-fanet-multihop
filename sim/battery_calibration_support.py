"""Capture and traffic support for the new protected-queue source calibration.

Only owned bounded jobs are stopped. Packet captures are interface observations,
not application acknowledgements or synchronized one-way-delay measurements.
This module never imports a legacy trial script and has no automatic main.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time
import uuid

from config import params as P
from core.battery_live_support import command


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def capture(directory, name, arguments):
    value = command(arguments)
    (directory / name).write_text(value, encoding="utf-8")
    return value


def read_log(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""

def clock_mark():
    # Bracket the wall-clock sample; monotonic_ns is shared by host processes.
    before = time.monotonic_ns()
    wall = time.time_ns()
    after = time.monotonic_ns()
    return {"monotonic_ns": before, "wall_ns": wall,
            "wall_sample_bracket_end_ns": after}


class OutputPump:
    """Preserve raw stdout and separately timestamp each observed complete line.

    A line can be delayed by iperf, docker, pipes, and host scheduling. Never
    reinterpret observed_monotonic_ns as the receiver interval's exact end.
    """
    def __init__(self, process, raw_handle, timing_path):
        self.process = process
        self.raw_handle = raw_handle
        self.timing_path = timing_path
        self.error = None
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        try:
            with self.timing_path.open("x", encoding="utf-8") as timing:
                for number, line in enumerate(self.process.stdout, 1):
                    observed = time.monotonic_ns()
                    self.raw_handle.write(line)
                    self.raw_handle.flush()
                    timing.write(json.dumps({"line_number": number,
                        "observed_monotonic_ns": observed,
                        "text": line.rstrip("\r\n")}, ensure_ascii=True) + "\n")
                    timing.flush()
        except Exception as error:
            self.error = error
        finally:
            self.process.stdout.close()

    def drain(self):
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("Log observer did not finish: %s" % self.timing_path)
        if self.error is not None:
            raise RuntimeError("Log observer failed: %s" % self.error)


def container_pid(name):
    fields = command(["sudo", "-n", "docker", "inspect", "--format",
                      "{{.State.Running}} {{.State.Pid}}", name]).split()
    if len(fields) != 2 or fields[0] != "true" or not fields[1].isdigit() or int(fields[1]) <= 1:
        raise ValueError("Topology container is not running: " + name)
    return int(fields[1])


class Capture:
    def __init__(self, directory, name, pid, interface, packet_filter):
        self.name = name
        self.pcap = directory / (name + ".pcap")
        self.log = directory / (name + "-tcpdump.log")
        self.pidfile = directory / (name + "-capture.pid")
        self.handle = self.log.open("w")
        self.argv = ["sudo", "-n", "env", "LC_ALL=C", shutil.which("nsenter"),
            "--target", str(pid), "--net", "/bin/sh", "-c",
            'echo $$ > "$1"; shift; exec "$@"', "fanet-capture", str(self.pidfile),
            "timeout", "--signal=INT", "--kill-after=3", "420",
            shutil.which("tcpdump"), "-n", "-i", interface, "-s", "128",
            "-B", "4096", "-U", "-Z", pwd.getpwuid(os.getuid()).pw_name,
            "-w", str(self.pcap), packet_filter]
        self.process = subprocess.Popen(self.argv, stdout=self.handle, stderr=subprocess.STDOUT)

    def ready(self):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Capture exited during setup: " + self.log.read_text())
            if (self.pidfile.exists() and self.pcap.exists()
                    and "listening on " in self.log.read_text()):
                return
            time.sleep(.05)
        raise RuntimeError("Capture readiness not confirmed; inspect " + str(self.log))

    def stop(self):
        try:
            if self.process.poll() is None:
                value = self.pidfile.read_text().strip()
                if not value.isdigit() or int(value) <= 1:
                    raise RuntimeError("Invalid owned capture PID")
                argv = (Path("/proc") / value / "cmdline").read_bytes()
                if str(self.pcap).encode() not in argv or b"timeout" not in argv:
                    raise RuntimeError("Capture PID identity changed; not signalled")
                command(["sudo", "-n", "kill", "-INT", value])
                self.process.wait(timeout=8)
        finally:
            self.handle.close()


def pcap_records(path):
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
               b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError("Not a supported classic pcap: " + str(path))
        endian, fraction_scale = formats[header[:4]]
        major, minor, _, _, snaplen, network = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4) or network != 1:
            raise ValueError("Expected Ethernet pcap version 2.4")
        while True:
            row = handle.read(16)
            if not row:
                return
            if len(row) != 16:
                raise ValueError("Truncated pcap record header")
            sec, fraction, captured, original = struct.unpack(endian + "IIII", row)
            if captured > min(snaplen, 1_048_576) or captured > original:
                raise ValueError("Invalid pcap capture length")
            packet = handle.read(captured)
            if len(packet) != captured:
                raise ValueError("Truncated pcap packet")
            yield sec * 1_000_000_000 + fraction * fraction_scale, packet


def decode_packet(packet):
    if len(packet) < 14:
        raise ValueError("Short Ethernet header")
    offset, ethertype = 14, struct.unpack_from("!H", packet, 12)[0]
    while ethertype in (0x8100, 0x88a8):
        if len(packet) < offset + 4:
            raise ValueError("Short VLAN header")
        ethertype = struct.unpack_from("!H", packet, offset + 2)[0]
        offset += 4
    if ethertype != 0x0800:
        return None
    if len(packet) < offset + 20:
        raise ValueError("Short IPv4 header")
    ihl = (packet[offset] & 15) * 4
    length = struct.unpack_from("!H", packet, offset + 2)[0]
    fragment = struct.unpack_from("!H", packet, offset + 6)[0]
    if packet[offset] >> 4 != 4 or ihl < 20 or length < ihl:
        raise ValueError("Invalid IPv4 header")
    if fragment & 0x3fff:
        raise ValueError("Fragmented IPv4 is outside this diagnostic decoder")
    source = socket.inet_ntoa(packet[offset+12:offset+16])
    destination = socket.inet_ntoa(packet[offset+16:offset+20])
    protocol = packet[offset+9]
    start = offset + ihl
    if len(packet) < start + 8:
        raise ValueError("Short transport header")
    sport, dport = struct.unpack_from("!HH", packet, start)
    result = {"source": source, "destination": destination, "sport": sport, "dport": dport}
    if protocol == 17:
        udp_length = struct.unpack_from("!H", packet, start+4)[0]
        if udp_length < 8 or udp_length > length - ihl:
            raise ValueError("Invalid UDP length")
        result.update(protocol="UDP", payload_length=udp_length-8)
        if udp_length == 1208:
            if len(packet) < start+20:
                raise ValueError("UDP snapshot too short for iperf sequence")
            # iperf3 3.9 default: 32-bit sequence after sec/usec (8 bytes).
            result["sequence"] = struct.unpack_from("!I", packet, start+16)[0]
    elif protocol == 6:
        if len(packet) < start + 20:
            raise ValueError("Short TCP header")
        thl = (packet[start+12] >> 4) * 4
        if thl < 20 or length < ihl + thl:
            raise ValueError("Invalid TCP header length")
        payload_length = length - ihl - thl
        result.update(protocol="TCP", payload_length=payload_length,
                      tcp_sequence=struct.unpack_from("!I", packet, start+4)[0])
        if payload_length == 1:
            if len(packet) <= start+thl:
                raise ValueError("Short TCP state byte")
            result["state_byte"] = packet[start+thl]
    else:
        return None
    return result


def read_capture(path, source_ip, destination_ip):
    streams = {5201: {"ids": {}, "datagrams": 0, "source_ports": set(), "end_markers": []},
               5202: {"ids": {}, "datagrams": 0, "source_ports": set(), "end_markers": []}}
    total = 0
    for stamp, raw in pcap_records(path):
        total += 1
        packet = decode_packet(raw)
        if not packet or packet["source"] != source_ip or packet["destination"] != destination_ip:
            continue
        port = packet["dport"]
        if port not in streams:
            continue
        stream = streams[port]
        if packet["protocol"] == "UDP" and packet.get("payload_length") == 1200:
            sequence = packet["sequence"]
            if sequence == 0:
                raise ValueError("Unexpected zero iperf data sequence")
            stream["datagrams"] += 1
            stream["source_ports"].add(packet["sport"])
            stream["ids"].setdefault(sequence, stamp)
        elif packet["protocol"] == "TCP" and packet.get("state_byte") == 4:
            # Only an unambiguous single-byte TEST_END message; no TCP
            # reassembly. Missing/coalesced control markers stay unknown.
            stream["end_markers"].append(stamp)
    for stream in streams.values():
        if len(stream["source_ports"]) > 1:
            raise ValueError("Multiple UDP flows used one test port; audit is ambiguous")
    return total, streams


def tcpdump_stats(text):
    captured = re.findall(r"(?m)^(\d+) packets? captured\s*$", text)
    dropped = re.findall(r"(?m)^(\d+) packets? dropped by kernel\s*$", text)
    if not captured or not dropped:
        raise ValueError("No complete tcpdump capture/drop statistics")
    return {"captured": int(captured[-1]), "kernel_dropped": int(dropped[-1])}


PROFILES = (
    {"name": "VOICE", "port": 5201, "rate_mbps": 1.2, "tos": 184},
    {"name": "VIDEO", "port": 5202, "rate_mbps": 4.2, "tos": 136},
)


RECORD = re.compile(
    r"^\[\s*(?:\d+|SUM)\]\s+([0-9.]+)-\s*([0-9.]+)\s+sec\s+"
    r"[0-9.]+\s+\S+\s+([0-9.]+)\s+([KMG]?bits/sec)\s+"
    r"([0-9.]+)\s+ms\s+(\d+)\s*/\s*(\d+)\s+"
    r"\(\s*([0-9.]+)%\)\s*(sender|receiver)?\s*$", re.MULTILINE,
)


def udp_records(text):
    records = []
    units = {"bits/sec": 1, "Kbits/sec": 1e3, "Mbits/sec": 1e6, "Gbits/sec": 1e9}
    for match in RECORD.finditer(text):
        start, end, rate, unit, jitter, lost, total, percent, role = match.groups()
        values = {"start_s": float(start), "end_s": float(end),
                  "bitrate_mbps": float(rate) * units[unit] / 1e6,
                  "jitter_ms": float(jitter), "lost_packets": int(lost),
                  "total_packets": int(total), "displayed_loss_percent": float(percent),
                  "role": role or "interval"}
        if (not all(math.isfinite(values[k]) and values[k] >= 0 for k in
                    ("start_s", "end_s", "bitrate_mbps", "jitter_ms", "displayed_loss_percent"))
                or values["end_s"] < values["start_s"]
                or not 0 <= values["lost_packets"] <= values["total_packets"]):
            raise ValueError("Invalid iperf UDP record")
        records.append(values)
    return records


def receiver_summary(text):
    summaries = [row for row in udp_records(text) if row["role"] == "receiver"]
    if not summaries:
        raise ValueError("No complete UDP receiver summary; inspect server log")
    summary = dict(summaries[-1])
    if summary["total_packets"] <= 0:
        raise ValueError("Receiver summary has no packets")
    summary["loss_percent"] = 100.0 * summary["lost_packets"] / summary["total_packets"]
    reorder = re.search(r"(\d+) datagrams received out-of-order", text)
    summary["out_of_order_reported"] = int(reorder[1]) if reorder else None
    return summary


def root_drops(text):
    block = re.search(r"^qdisc htb [^\n]*\broot\b[^\n]*\n(.*?)(?=^qdisc |\Z)",
                      text, re.MULTILINE | re.DOTALL)
    match = re.search(r"\bdropped (\d+)", block[1]) if block else None
    if match is None:
        raise ValueError("Cannot read root HTB drop counter")
    return int(match[1])


def queue_snapshot(directory, phase):
    drops = {}
    for drone in P.DRONES:
        for index in (0, 1):
            interface = drone.lower() + "-eth" + str(index)
            text = capture(directory, "queue-%s-%s.txt" % (phase, interface),
                           ["sudo", "-n", "docker", "exec", "mn." + drone.lower(),
                            "tc", "-s", "qdisc", "show", "dev", interface])
            drops[interface] = root_drops(text)
    return drops


def listener(port):
    return command(["sudo", "-n", "docker", "exec", "mn.gs", "ss", "-H", "-ltn",
                    "sport = :%d" % port], timeout=5).strip()


SOURCE_CONTAINER = "mn.u1"


SOURCE_INTERFACE = "u1-eth0"


SOURCE_HANDLE = "7f00:"


SOURCE_FQ_OPTIONS = ["limit", "1000", "flow_limit", "1000",
                     "quantum", "1514", "initial_quantum", "1514", "pacing"]


def source_tc(*arguments):
    return ["sudo", "-n", "docker", "exec", SOURCE_CONTAINER,
            "tc"] + list(arguments)


def root_qdisc(text):
    rows = json.loads(text)
    roots = [row for row in rows if row.get("root") is True]
    if len(roots) != 1:
        raise ValueError("Expected exactly one sender root qdisc")
    return roots[0]


def read_source_qdisc():
    return command(source_tc("-j", "-s", "qdisc", "show", "dev", SOURCE_INTERFACE))


def validate_owned_fq(row):
    if row.get("kind") != "fq" or row.get("handle") != SOURCE_HANDLE:
        raise ValueError("Sender qdisc changed; expected this trial's fq handle")
    options = row.get("options", {})
    for key, expected in (("limit", 1000), ("flow_limit", 1000),
                          ("quantum", 1514), ("initial_quantum", 1514)):
        if options.get(key) != expected:
            raise ValueError("Sender fq option not verified: " + key)
    if options.get("pacing", True) not in (1, True):
        raise ValueError("Sender fq pacing is not enabled")
    for key in ("drops", "qlen", "backlog"):
        if type(row.get(key)) is not int or row[key] < 0:
            raise ValueError("Missing/noninteger sender fq statistic: " + key)
    return row


def source_snapshot(directory, phase):
    text = capture(directory, "source-qdisc-" + phase + ".json",
                   source_tc("-j", "-s", "qdisc", "show", "dev", SOURCE_INTERFACE))
    return validate_owned_fq(root_qdisc(text))


def restore_source_qdisc(directory):
    current = root_qdisc(read_source_qdisc())
    # Deleting an fq root on this veth returns the kernel's noqueue root.
    # Never delete any externally changed root.
    if current.get("kind") == "fq" and current.get("handle") == SOURCE_HANDLE:
        capture(directory, "source-qdisc-before-cleanup.json",
                source_tc("-j", "-s", "qdisc", "show", "dev", SOURCE_INTERFACE))
        command(source_tc("qdisc", "del", "dev", SOURCE_INTERFACE,
                          "root", "handle", SOURCE_HANDLE))
    elif current.get("kind") != "noqueue":
        raise RuntimeError("Sender root changed externally; left untouched")
    restored = capture(directory, "source-qdisc-restored.json",
                       source_tc("-j", "-s", "qdisc", "show", "dev", SOURCE_INTERFACE))
    if root_qdisc(restored).get("kind") != "noqueue":
        raise RuntimeError("Sender noqueue restoration was not verified")


CALIBRATION_POLICY = {
    "version": 1,
    "mean_rate_tolerance_fraction": 0.05,
    "interior_one_second_rate_tolerance_fraction": 0.10,
    "maximum_interior_captured_gap_ms": 100.0,
    "interior_trim_s": 5,
    "basis": "Predeclared engineering calibration criteria, not standardized QoS requirements",
    "bin_origin": "Each endpoint/stream's first captured UDP data packet; not application start",
}


def stream_statistics(stream, duration):
    stamps = sorted(stream["ids"].values())
    if len(stamps) < 2:
        raise ValueError("Insufficient UDP data for rate/gap calibration")
    origin = stamps[0]
    elapsed = [(stamp-origin)/1e9 for stamp in stamps]
    bins = [0] * duration
    for value in elapsed:
        if 0 <= value < duration:
            bins[int(value)] += 1
    trim = CALIBRATION_POLICY["interior_trim_s"]
    lower, upper = trim, duration-trim
    # Include a pause straddling either interior boundary: consider the
    # length of each inter-packet gap intersected with the interior window.
    gaps = [max(0.0, min(b, upper)-max(a, lower)) * 1000
            for a, b in zip(elapsed, elapsed[1:])]
    # Also detect a stream stopping before the end of the interior window.
    gaps.append(max(0.0, upper-max(elapsed[-1], lower)) * 1000)
    end = min(stream["end_markers"], default=None)
    return {
        "unique_packets": len(stamps),
        "duplicate_observations": stream["datagrams"]-len(stamps),
        "first_to_last_data_s": elapsed[-1],
        "payload_mbps_normalized_to_requested_duration": len(stamps)*1200*8/duration/1e6,
        "one_second_payload_mbps": [n*1200*8/1e6 for n in bins],
        "interior_bin_indices": [lower, upper],
        "maximum_interior_captured_gap_ms": max(gaps),
        "packets_beyond_first_packet_plus_duration": sum(t >= duration for t in elapsed),
        "single_byte_test_end_observed": end is not None,
        "packets_captured_after_test_end": sum(t > end for t in stamps) if end is not None else None,
        "last_data_minus_test_end_ms": (stamps[-1]-end)/1e6 if end is not None else None,
    }


class Job:
    """A bounded, named job inside one container, with a private PID file."""
    def __init__(self, directory, token, container, name, arguments, bound):
        self.container = container
        self.name = name
        self.pidfile = "/tmp/fanet-%s-%s.pid" % (token, name)
        self.path = directory / (name + ".log")
        self.handle = self.path.open("w", encoding="utf-8")
        self.argv = ["sudo", "-n", "docker", "exec", "-e", "LC_ALL=C", container,
                     "sh", "-c", 'echo $$ > "$1"; shift; exec "$@"',
                     "fanet-job", self.pidfile, "timeout", "-s", "INT", "-k", "3",
                     str(bound)] + arguments
        self.launch_mark = clock_mark()
        self.launched = self.launch_mark["monotonic_ns"] / 1e9
        try:
            self.process = subprocess.Popen(self.argv, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1)
            self.pump = OutputPump(self.process, self.handle,
                                   directory / (name + ".timing.jsonl"))
        except BaseException:
            try:
                self.stop()
            except Exception:
                self.handle.close()
            raise

    def stop(self):
        if getattr(self, "process", None) is not None and self.process.poll() is None:
            try:
                pid = command(["sudo", "-n", "docker", "exec", self.container,
                               "cat", self.pidfile], timeout=3).strip()
                if pid.isdigit() and int(pid) > 1:
                    command(["sudo", "-n", "docker", "exec", self.container,
                             "sh", "-c", 'kill -INT "$1"', "fanet-cleanup", pid], timeout=3)
                    self.process.wait(timeout=3)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                pass  # Remote timeout still bounds a job if the topology vanished.
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
        try:
            if getattr(self, "pump", None) is not None:
                self.pump.drain()
        finally:
            self.handle.close()
        try:
            command(["sudo", "-n", "docker", "exec", self.container,
                     "rm", "-f", "--", self.pidfile], timeout=3)
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            pass


def assess_source(stream, sender, duration, target):
    stats = stream_statistics(stream, duration)
    expected = set(range(1, sender["total_packets"] + 1))
    issues, failed = [], []
    if set(stream["ids"]) != expected:
        issues.append("Source capture IDs do not match the complete sender sequence range")
    observed = list(stream["ids"].values())
    if any(b < a for a, b in zip(observed, observed[1:])):
        issues.append("Source capture timestamps are nonmonotonic")
    if stats["duplicate_observations"]:
        issues.append("Duplicate source observations require sequence review")
    if abs(sender["end_s"] - sender["start_s"] - duration) > .1:
        issues.append("Sender summary duration differs by over 0.1s")
    mean = sender["total_packets"] * 1200 * 8 / duration / 1e6
    error = mean / target - 1
    if abs(error) > CALIBRATION_POLICY["mean_rate_tolerance_fraction"] + 1e-12:
        failed.append("Generated mean is outside target +/-5%")
    lower, upper = stats["interior_bin_indices"]
    bad = [i for i in range(lower, upper) if abs(stats["one_second_payload_mbps"][i] / target - 1)
           > CALIBRATION_POLICY["interior_one_second_rate_tolerance_fraction"] + 1e-12]
    if bad:
        failed.append("Interior 1s bins outside target +/-10%: " + str(bad))
    if stats["maximum_interior_captured_gap_ms"] > CALIBRATION_POLICY["maximum_interior_captured_gap_ms"]:
        failed.append("Source interior captured gap exceeds 100ms")
    return {"target_mbps": target, "generated_payload_mbps": mean, "mean_error_percent": error * 100,
            "source_statistics": stats, "failed_criteria": failed, "evidence_issues": issues,
            "verdict": "INCONCLUSIVE" if issues else "FAIL" if failed else "PASS"}


def meter_counts(text):
    inputs = re.findall(r"\bpacket_in_count\s*[:=]\s*(\d+)", text)
    bands = re.findall(r"\bpacket_count\s*[:=]\s*(\d+)", text)
    if len(inputs) != 1 or len(bands) != 1:
        raise ValueError("Expected one video meter and one drop band in statistics")
    return {"input_packets": int(inputs[0]), "drop_packets": int(bands[0])}


def collect_source_load(applied, directory, duration, controller):
    """Collect one unchanged initial plan. No state publication or link action."""
    token = uuid.uuid4().hex[:12]
    jobs, observers, clients, servers = [], [], {}, {}
    monitor = pump = monitor_handle = None
    fq_attempted = False
    data = {"schema": 1, "protocol": "battery-source-calibration-v1", "status": "starting",
            "scenario": "A", "mode": "fixed", "duration_s": duration, "payload_bytes": 1200,
            "profiles": PROFILES, "policy": CALIBRATION_POLICY, "battery_event_enabled": False,
            "link_failure_enabled": False, "socket_pacing_cap_enabled": False,
            "source_fq_options": SOURCE_FQ_OPTIONS, "epoch": applied["epoch"],
            "cleanup_errors": [], "timing_marks": {"begin": clock_mark()},
            "scope": "One instrumented source calibration on protected queues; not QoS or energy proof"}

    def require_alive():
        if controller.poll() is not None:
            raise RuntimeError("Protected controller exited during calibration")

    def ofctl(operation, *args):
        return command(["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", operation, P.SWITCH_NAME] + list(args))

    error = None
    try:
        for executable in ("tcpdump", "nsenter", "timeout", "vmstat"):
            if not shutil.which(executable):
                raise RuntimeError("Required executable missing: " + executable)
        for node in ("u1", "gs"):
            prefix = ["sudo", "-n", "docker", "exec", "mn." + node, "iperf3"]
            version = command(prefix + ["--version"])
            help_text = command(prefix + ["--help"])
            if not version.startswith("iperf 3.9") or "--forceflush" not in help_text or "--fq-rate" not in help_text:
                raise RuntimeError("This calibration requires iperf3 3.9 with --forceflush/--fq-rate")
            data[node + "_iperf_version"] = version
        for profile in PROFILES:
            if listener(profile["port"]):
                raise RuntimeError("Existing listener on GS port " + str(profile["port"]) + "; left untouched")
        original = capture(directory, "source-qdisc-original.json",
                           source_tc("-j", "-s", "qdisc", "show", "dev", SOURCE_INTERFACE))
        if root_qdisc(original).get("kind") != "noqueue":
            raise RuntimeError("Source root must be noqueue before calibration; left untouched")
        fq_attempted = True
        command(source_tc("qdisc", "add", "dev", SOURCE_INTERFACE, "root", "handle", SOURCE_HANDLE,
                          "fq", *SOURCE_FQ_OPTIONS))
        source_before = source_snapshot(directory, "before")
        before = queue_snapshot(directory, "before")
        mid = applied["video_meter_id"]
        meter_before = ofctl("meter-stats", "meter=" + str(mid))
        (directory / "video-meter-before.txt").write_text(meter_before)
        source_ip = P.HOSTS["u1"][0].split("/")[0]
        destination = P.HOSTS["gs"][0].split("/")[0]
        data.update(source_ip=source_ip, destination_ip=destination)
        packet_filter = ("ip and host %s and host %s and (udp or tcp) and (port 5201 or port 5202)"
                         % (source_ip, destination))
        data["capture_settings"] = {"filter": packet_filter, "snaplen": 128,
            "post_jobs_observation_s": 8, "clock": "pcap wall clock; not controller monotonic timestamps"}
        for name in ("u1", "gs"):
            observer = Capture(directory, name, container_pid("mn." + name), name + "-eth0", packet_filter)
            observers.append(observer)
            observer.ready()
        print("Both captures ready; private UAV1=90%; NO battery event or link failure.", flush=True)
        bound = duration + 50
        for profile in PROFILES:
            job = Job(directory, token, "mn.gs", profile["name"].lower() + "-server",
                      ["iperf3", "-s", "-1", "-p", str(profile["port"]), "-i", "1", "--forceflush"], bound)
            jobs.append(job)
            servers[profile["name"]] = job
        deadline = time.monotonic() + 10
        while not all(listener(profile["port"]) for profile in PROFILES):
            require_alive()
            if any(job.process.poll() is not None for job in servers.values()) or time.monotonic() > deadline:
                raise RuntimeError("Both UDP servers did not become ready")
            time.sleep(.1)
        monitor_handle = (directory / "vmstat.log").open("w", encoding="utf-8")
        monitor = subprocess.Popen(["vmstat", "-t", "1"], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1,
            env=dict(os.environ, LC_ALL="C"))
        pump = OutputPump(monitor, monitor_handle, directory / "vmstat.timing.jsonl")
        data["timing_marks"]["client_launch_origin"] = clock_mark()
        print("Concurrent UDP: VOICE 1.2 Mbps, VIDEO 4.2 Mbps, 1200-byte payload; --fq-rate 0.", flush=True)
        for profile in PROFILES:
            job = Job(directory, token, "mn.u1", profile["name"].lower() + "-client",
                      ["iperf3", "-c", destination, "-p", str(profile["port"]), "-u",
                       "-b", "%gM" % profile["rate_mbps"], "--fq-rate", "0", "-l", "1200",
                       "-t", str(duration), "-i", "1", "-S", str(profile["tos"]), "--forceflush"], bound)
            jobs.append(job)
            clients[profile["name"]] = job
            data["timing_marks"][profile["name"].lower() + "_client_launch"] = job.launch_mark
        data["job_commands"] = {job.name: job.argv for job in jobs}
        write_json(directory / "source-calibration-data.json", data)
        deadline = time.monotonic() + 15
        while True:
            require_alive()
            if any(job.process.poll() is not None for job in jobs):
                raise RuntimeError("A traffic job exited before both receive streams were confirmed")
            if all(any(row["role"] == "interval" and row["total_packets"] > row["lost_packets"]
                       for row in udp_records(read_log(job.path))) for job in servers.values()):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Both UDP receive streams were not confirmed within 15s")
            time.sleep(.1)
        data["timing_marks"]["both_streams_observed"] = clock_mark()
        print("Both UDP streams observed; collecting one fixed baseline for %ds." % duration, flush=True)
        deadline = time.monotonic() + bound
        while any(job.process.poll() is None for job in clients.values()):
            require_alive()
            if monitor.poll() is not None or any(job.process.poll() not in (None, 0) for job in clients.values()):
                raise RuntimeError("A client or vmstat monitor failed during calibration")
            if time.monotonic() > deadline:
                raise RuntimeError("UDP clients exceeded the bounded run time")
            time.sleep(.1)
        for job in jobs:
            job.process.wait(timeout=10)
            job.pump.drain()
            job.handle.flush()
            if job.process.returncode != 0:
                raise RuntimeError("Traffic job failed: " + job.name)
        data["timing_marks"]["traffic_finished"] = clock_mark()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            require_alive()
            if any(observer.process.poll() is not None for observer in observers):
                raise RuntimeError("Capture exited before tail observation completed")
            time.sleep(.1)
        for observer in observers:
            observer.stop()
        source_after = source_snapshot(directory, "final")
        after = queue_snapshot(directory, "final")
        drops = {name: after[name] - count for name, count in before.items()}
        if any(count < 0 for count in drops.values()) or source_after["drops"] < source_before["drops"]:
            raise RuntimeError("Queue counters reset during calibration")
        data["queue_root_drop_deltas"] = drops
        data["source_pacing"] = {"dropped_packets_delta": source_after["drops"] - source_before["drops"],
            "final_queued_packets": source_after["qlen"], "final_backlog_bytes": source_after["backlog"]}
        meter_after = ofctl("meter-stats", "meter=" + str(mid))
        (directory / "video-meter-final.txt").write_text(meter_after)
        mb, ma = meter_counts(meter_before), meter_counts(meter_after)
        data["video_meter_deltas"] = {name: ma[name] - mb[name] for name in ma}
        if any(value < 0 for value in data["video_meter_deltas"].values()):
            raise RuntimeError("Video meter counters reset during calibration")
        data["udp"] = {}
        for profile in PROFILES:
            name = profile["name"]
            receiver = receiver_summary(read_log(servers[name].path))
            senders = [row for row in udp_records(read_log(clients[name].path)) if row["role"] == "sender"]
            if not senders or senders[-1]["end_s"] - senders[-1]["start_s"] < duration - 1:
                raise RuntimeError("No complete planned-duration sender summary for " + name)
            data["udp"][name] = {"receiver": receiver, "sender": senders[-1]}
            print("%s receiver: %.3f Mbps; missing %d/%d; displayed jitter %.3f ms" %
                  (name, receiver["bitrate_mbps"], receiver["lost_packets"], receiver["total_packets"],
                   receiver["jitter_ms"]), flush=True)
        data["status"] = "completed"
    except BaseException as caught:
        error = caught
        data["status"] = "failed"
        data["error"] = type(caught).__name__ + ": " + str(caught)
    finally:
        def cleanup(label, action):
            try:
                action()
            except Exception as caught:
                data["cleanup_errors"].append(label + ": " + str(caught))
        for observer in reversed(observers):
            cleanup("capture " + observer.name, observer.stop)
        for job in reversed(jobs):
            cleanup(job.name, job.stop)
        if monitor is not None:
            def stop_monitor():
                if monitor.poll() is None:
                    monitor.terminate()
                    try:
                        monitor.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        monitor.kill(); monitor.wait(timeout=3)
            cleanup("vmstat process", stop_monitor)
        if pump is not None:
            cleanup("vmstat observer", pump.drain)
        if monitor_handle is not None:
            cleanup("vmstat log", monitor_handle.close)
        if fq_attempted:
            before_cleanup = len(data["cleanup_errors"])
            cleanup("source fq", lambda: restore_source_qdisc(directory))
            data.setdefault("source_pacing", {})["noqueue_restored"] = len(data["cleanup_errors"]) == before_cleanup
        if data["cleanup_errors"]:
            data["status"] = "failed"
        data["timing_marks"]["end"] = clock_mark()
        write_json(directory / "source-calibration-data.json", data)
    if error is not None:
        raise error
    if data["status"] != "completed":
        raise RuntimeError("Traffic/capture/source cleanup failed; inspect source-calibration-data.json")
    return {"collection_status": "completed", "duration_s": duration,
            "battery_event_enabled": False, "link_failure_enabled": False,
            "data_file": "source-calibration-data.json"}


def report_source_calibration(directory):
    directory = Path(directory)
    outer = json.loads((directory / "manifest.json").read_text())
    data = json.loads((directory / "source-calibration-data.json").read_text())
    if (outer.get("status") != "completed" or outer.get("cleanup_errors")
            or data.get("status") != "completed" or data.get("cleanup_errors")):
        raise ValueError("Expected a completed collection and verified controller/queue/source cleanup")
    if (data.get("protocol") != "battery-source-calibration-v1" or data.get("policy") != CALIBRATION_POLICY
            or data.get("battery_event_enabled") is not False or data.get("link_failure_enabled") is not False):
        raise ValueError("Calibration protocol or predeclared acceptance settings differ")
    if (data.get("profiles") != list(PROFILES) or data.get("payload_bytes") != 1200
            or data.get("socket_pacing_cap_enabled") is not False
            or type(data.get("duration_s")) is not int or not 20 <= data["duration_s"] <= 60
            or data.get("mode") != "fixed" or data.get("scenario") != "A"):
        raise ValueError("Traffic profile, duration or fixed scenario differs")
    captures, quality, source_issues, receiver_issues = {}, {}, [], []
    for name in ("u1", "gs"):
        count, captures[name] = read_capture(directory / (name + ".pcap"), data["source_ip"], data["destination_ip"])
        quality[name] = tcpdump_stats((directory / (name + "-tcpdump.log")).read_text())
        issues = source_issues if name == "u1" else receiver_issues
        if count != quality[name]["captured"]:
            issues.append(name + ": pcap count differs from tcpdump record count")
        if quality[name]["kernel_dropped"]:
            issues.append(name + ": tcpdump reported capture drops")
    streams = {}
    for profile in PROFILES:
        name, port = profile["name"], profile["port"]
        row = assess_source(captures["u1"][port], data["udp"][name]["sender"], data["duration_s"], profile["rate_mbps"])
        row["gs_statistics"] = stream_statistics(captures["gs"][port], data["duration_s"])
        first, second = set(captures["u1"][port]["ids"]), set(captures["gs"][port]["ids"])
        row["source_ids_not_observed_at_gs"] = sorted(first - second)
        row["gs_ids_not_observed_at_source"] = sorted(second - first)
        streams[name] = row
    verdicts = [row["verdict"] for row in streams.values()]
    source_verdict = ("INCONCLUSIVE" if source_issues or "INCONCLUSIVE" in verdicts else
                      "FAIL" if "FAIL" in verdicts else "PASS")
    path_issues = list(receiver_issues)
    if any(data["queue_root_drop_deltas"].values()):
        path_issues.append("UAV queues recorded drops")
    if data["video_meter_deltas"]["drop_packets"]:
        path_issues.append("VIDEO ingress meter recorded policing drops")
    pacing = data["source_pacing"]
    if pacing.get("noqueue_restored") is not True:
        path_issues.append("Source noqueue restoration was not verified")
    if pacing["dropped_packets_delta"] or pacing["final_queued_packets"] or pacing["final_backlog_bytes"]:
        path_issues.append("Source fq had drops or final backlog")
    if any(row["source_ids_not_observed_at_gs"] or row["gs_ids_not_observed_at_source"] for row in streams.values()):
        path_issues.append("Source and GS captured sequence sets differ; losses are not individually localized")
    if any(row["gs_statistics"]["duplicate_observations"] for row in streams.values()):
        path_issues.append("Duplicate GS observations require review")
    baseline_clean = not (source_issues or path_issues)
    acceptance = "PASS" if source_verdict == "PASS" and baseline_clean else "FAIL" if source_verdict == "FAIL" else "INCONCLUSIVE"
    result = {"schema": 1, "source_verdict": source_verdict, "overall_acceptance": acceptance,
        "clean_path_baseline": baseline_clean, "policy": CALIBRATION_POLICY, "capture_quality": quality,
        "source_evidence_issues": source_issues, "path_evidence_issues": path_issues,
        "video_meter_deltas": data["video_meter_deltas"], "queue_root_drop_deltas": data["queue_root_drop_deltas"],
        "source_pacing": pacing, "streams": streams,
        "scope": "One instrumented calibration; not repeatability, QoS, continuity, codec adaptation or energy proof"}
    write_json(directory / "calibration-report.json", result)
    print("\nSOURCE CALIBRATION:", source_verdict, flush=True)
    print("Same criteria: mean +/-5%; every interior 1s bin +/-10%; interior gap <=100ms; trim 5s at each end.")
    for name, row in streams.items():
        print("%s: generated %.3f / target %.3f Mbps (%+.2f%%); gap %.3f ms; %s" %
              (name, row["generated_payload_mbps"], row["target_mbps"], row["mean_error_percent"],
               row["source_statistics"]["maximum_interior_captured_gap_ms"], row["verdict"]))
        for issue in row["failed_criteria"] + row["evidence_issues"]:
            print("  " + issue)
    print("VIDEO meter:", data["video_meter_deltas"])
    print("Clean path baseline:", baseline_clean)
    for issue in source_issues + path_issues:
        print("Evidence:", issue)
    print("OVERALL CALIBRATION ACCEPTANCE:", acceptance)
    print("Saved:", directory / "calibration-report.json")
    print("Retain this single run. Do not automatically repeat or start a comparison batch.")
    return result
