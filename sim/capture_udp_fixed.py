"""One FIXED paced diagnostic with passive captures at u1 and gs.

Run as normal user after sudo -v; keep the topology running separately.
Requires the existing run_udp_trial_paced.py and its timing helpers in sim/.
No trial/controller/topology source is modified. A new capture directory holds
128-byte packet snapshots, tcpdump logs, metadata, and a sequence audit.

Offline reanalysis: python3 capture_udp_fixed.py --analyze CAPTURE_DIRECTORY
Packet capture adds overhead. Counts describe these interface observations;
they are not packet delivery acknowledgements or one-way delay measurements.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError("Command failed: %s\n%s" % (" ".join(argv), result.stderr.strip()))
    return result.stdout


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


def analyze(directory):
    metadata = json.loads((directory / "capture-manifest.json").read_text())
    if metadata.get("status") != "captured":
        raise ValueError("Capture did not finish cleanly: " + str(metadata.get("status")))
    trial_path = Path(metadata["trial_directory"])
    manifest = json.loads((trial_path / "manifest.json").read_text())
    if manifest.get("status") != "completed" or manifest.get("trial_protocol") != "udp-v3-fq-paced-diagnostic":
        raise ValueError("Expected a completed paced trial")
    if not manifest.get("mn.u1_iperf_version", "").startswith("iperf 3.9"):
        raise ValueError("This decoder is validated for the current iperf3 3.9 protocol")
    if any("--udp-counters-64bit" in argv for argv in manifest["job_commands"].values()):
        raise ValueError("64-bit UDP sequence option is outside this decoder")
    captures, quality = {}, {}
    for name in ("u1", "gs"):
        count, captures[name] = read_capture(directory / (name + ".pcap"),
            metadata["source_ip"], metadata["destination_ip"])
        quality[name] = tcpdump_stats((directory / (name + "-tcpdump.log")).read_text())
        if count != quality[name]["captured"]:
            raise ValueError("pcap record count differs from tcpdump's captured count for " + name)
    good = all(row["kernel_dropped"] == 0 for row in quality.values())
    audit = {"schema": 1, "trial_directory": str(trial_path), "capture_quality": quality,
             "source_pacing": manifest["source_pacing"],
             "zero_reported_capture_drops": good, "streams": {}, "notes": [
        "Interface capture is not application delivery acknowledgement; missing captured IDs are not automatically declared network loss.",
        "The sender counter is not independent on-wire evidence. Compare sequence sets at the two capture points.",
        "Only exact single-byte TCP TEST_END messages are recognized. No TCP reassembly; an absent marker is unknown.",
        "Capture timestamps are packet-capture wall-clock timestamps, not runner/controller monotonic hook times.",
        "Capture adds overhead; this is a diagnostic protocol and is not pooled with uncaptured performance batches.",
        "Observation continues 8 seconds after the trial process exits; non-arrival is bounded by this observation window."]}
    for name, port in (("VOICE", 5201), ("VIDEO", 5202)):
        sent = captures["u1"][port]; received = captures["gs"][port]
        source_ids, gs_ids = set(sent["ids"]), set(received["ids"])
        if not source_ids or not gs_ids:
            raise ValueError("No captured data for " + name)
        server = manifest["udp"][name]
        sender_counter = server["sender"]["total_packets"]
        bad_ids = sorted((source_ids | gs_ids) - set(range(1, sender_counter + 1)))
        if bad_ids:
            raise ValueError("Captured sequences exceed the sender's reported counter")
        end = min(received["end_markers"], default=None)
        above = sorted(sequence for sequence in gs_ids if sequence > server["total_packets"])
        audit["streams"][name] = {
            "sender_reported_counter": sender_counter,
            "receiver_reported_sequence_count": server["total_packets"],
            "receiver_reported_missing": server["lost_packets"],
            "source_unique_ids": len(source_ids), "gs_unique_ids": len(gs_ids),
            "source_duplicate_observations": sent["datagrams"]-len(source_ids),
            "gs_duplicate_observations": received["datagrams"]-len(gs_ids),
            "source_ids_not_observed_at_gs": sorted(source_ids-gs_ids),
            "gs_ids_not_observed_at_source": sorted(gs_ids-source_ids),
            "gs_ids_above_receiver_reported_counter": above,
            "gs_single_byte_test_end_observed": end is not None,
            "gs_ids_captured_after_test_end_arrival": sorted(sequence for sequence, stamp in received["ids"].items()
                                                           if end is not None and stamp > end),
            "last_gs_data_minus_test_end_ms": (max(received["ids"].values())-end)/1e6 if end is not None else None}
    save_json(directory / "sequence-audit.json", audit)
    print("\nPACKET SEQUENCE AUDIT:", directory)
    print("Capture quality:", quality)
    print("Zero reported capture drops:", good)
    print("Source queue caveat:",manifest["source_pacing"].get("source_queue_caveat","unknown"))
    if not good:
        print("CAPTURE INCOMPLETE: do not interpret absent IDs as path loss.")
    for name, row in audit["streams"].items():
        print("\n" + name)
        for key in ("sender_reported_counter", "receiver_reported_sequence_count", "receiver_reported_missing",
                    "source_unique_ids", "gs_unique_ids", "source_duplicate_observations", "gs_duplicate_observations",
                    "gs_single_byte_test_end_observed", "last_gs_data_minus_test_end_ms"):
            print("  %s: %s" % (key, row[key]))
        for key in ("source_ids_not_observed_at_gs", "gs_ids_not_observed_at_source",
                    "gs_ids_above_receiver_reported_counter", "gs_ids_captured_after_test_end_arrival"):
            values = row[key]
            print("  %s: count=%d first=%s last=%s" % (key,len(values),values[:5],values[-5:]))
    print("\nFull ID lists saved in sequence-audit.json. Capture is not a QoS or energy-saving result.")
    return audit


def run_capture():
    if os.geteuid() == 0:
        raise ValueError("Run as normal user after sudo -v")
    project = Path(__file__).resolve().parent.parent
    trial_script = project / "sim/run_udp_trial_paced.py"
    if not trial_script.is_file():
        raise ValueError("Missing " + str(trial_script))
    for tool in ("tcpdump", "nsenter", "timeout"):
        if not shutil.which(tool):
            raise ValueError("Missing host tool: " + tool)
    # Load existing configuration, without starting a trial or editing files.
    import run_udp_trial_paced as trial_module
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((trial_module.P.CONTROLLER_IP, trial_module.P.CONTROLLER_PORT))
    pids = {name: container_pid("mn." + name) for name in ("u1", "gs")}
    for name, pid in pids.items():
        command(["sudo", "-n", "nsenter", "--target", str(pid), "--net",
                 "ip", "link", "show", "dev", name + "-eth0"])
    source_ip = trial_module.P.HOSTS["u1"][0].split("/")[0]
    destination_ip = trial_module.P.HOSTS["gs"][0].split("/")[0]
    # Only these test endpoints and ports; no unrelated interface traffic.
    packet_filter = ("ip and host %s and host %s and (udp or tcp) and (port 5201 or port 5202)" %
                     (source_ip, destination_ip))
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = project / "results/udp-captures" / (stamp + "-fixed-" + uuid.uuid4().hex[:12])
    directory.mkdir(parents=True, exist_ok=False)
    metadata = {"schema":1,"status":"starting","mode":"fixed","source_ip":source_ip,
        "destination_ip":destination_ip,"container_pids":pids,"filter":packet_filter,
        "snaplen":128,"post_trial_observation_s":8,"started_utc":stamp,
        "paced_runner_sha256":hashlib.sha256(trial_script.read_bytes()).hexdigest()}
    save_json(directory / "capture-manifest.json", metadata)
    trial_root = project / "results/udp-paced-trials"
    before = set(trial_root.glob("*/manifest.json"))
    captures=[]; child=None
    print("Capture directory:", directory, flush=True)
    try:
        for name in ("gs", "u1"):
            capture = Capture(directory,name,pids[name],name+"-eth0",packet_filter)
            captures.append(capture)
            capture.ready()
        metadata["capture_ready_monotonic_ns"]=time.monotonic_ns()
        save_json(directory / "capture-manifest.json",metadata)
        print("Both captures ready; starting one FIXED paced diagnostic.",flush=True)
        child=subprocess.Popen([sys.executable,str(trial_script),"--mode","fixed"],preexec_fn=os.setpgrp)
        deadline=time.monotonic()+300
        while child.poll() is None:
            if any(c.process.poll() is not None for c in captures):
                raise RuntimeError("A packet capture exited before the trial ended")
            if time.monotonic()>deadline:
                raise RuntimeError("Trial exceeded the capture wrapper's 300s limit")
            time.sleep(.1)
        metadata["trial_returncode"]=child.returncode
        metadata["trial_exit_monotonic_ns"]=time.monotonic_ns()
        added=sorted(set(trial_root.glob("*/manifest.json"))-before)
        if len(added)==1:
            metadata["trial_directory"]=str(added[0].parent)
        if child.returncode!=0:
            raise RuntimeError("Paced trial failed (exit %s); see its error above. Capture retained without delivery interpretation." % child.returncode)
        if len(added)!=1:
            raise ValueError("Cannot uniquely associate capture with one new paced trial")
        print("Trial finished; observing test traffic for 8 more seconds.",flush=True)
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            if any(c.process.poll() is not None for c in captures):
                raise RuntimeError("Capture ended during post-trial observation")
            time.sleep(.1)
        if any(container_pid("mn."+name)!=pid for name,pid in pids.items()):
            raise RuntimeError("A topology container restarted during capture")
        metadata["status"]="captured"
    except KeyboardInterrupt:
        metadata["status"]="interrupted"
        metadata["error"]="Interrupted by user"
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
        metadata["status"]="failed"; metadata["error"]=str(error)
    finally:
        if child is not None and child.poll() is None:
            try:
                child.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=60)
            except subprocess.TimeoutExpired:
                metadata.setdefault("cleanup_errors",[]).append("Trial did not finish cleanup; do not start another trial")
                metadata["status"]="failed"
        for capture in reversed(captures):
            try:
                capture.stop()
            except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
                metadata.setdefault("cleanup_errors",[]).append(capture.name+": "+str(error))
                metadata["status"]="failed"
        metadata["finished_utc"]=dt.datetime.now(dt.timezone.utc).isoformat()
        if "trial_directory" not in metadata:
            added=sorted(set(trial_root.glob("*/manifest.json"))-before)
            if len(added)==1:
                metadata["trial_directory"]=str(added[0].parent)
        save_json(directory/"capture-manifest.json",metadata)
    if metadata["status"]!="captured":
        print("Capture not usable:",json.dumps(metadata,indent=2),file=sys.stderr)
        return 1
    analyze(directory)
    return 0


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyze",type=Path,help="Reanalyze saved capture only; does not start traffic")
    args=parser.parse_args()
    try:
        if args.analyze:
            analyze(args.analyze.expanduser().resolve())
            return 0
        return run_capture()
    except (OSError,ValueError,RuntimeError,KeyError,TypeError,struct.error,subprocess.TimeoutExpired) as error:
        print("Capture diagnostic failed:",error,file=sys.stderr)
        return 1


if __name__=="__main__":
    sys.exit(main())
