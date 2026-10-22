"""FIXED source-load calibration on the existing multi-hop topology.

Run as normal user after sudo -v; leave Containernet running separately.
Uses the existing fq settings, application targets and socket caps unchanged.
Initializes synthetic state to UAV1=90%; publishes NO in-traffic battery event.
Starts its own Ryu, two iperf clients/servers, vmstat and passive captures.
Results: results/udp-source-calibration/<unique-id>. State is not restored.

This is a calibration of this capture-instrumented configuration, not proof
of QoS, energy savings, VM root cause, or uncaptured benchmark stability.
Offline report: python3 run_udp_calibration.py --analyze RESULT_DIRECTORY
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import subprocess
import sys
import time
import uuid

from run_live_trial import (
    PROJECT_ROOT, P, STATES, EXPERIMENT_FIXED_WEIGHTS, plan_forward,
    load_state, save_state, write_json, command, capture, read_log,
    ensure_state, wait_ready, wait_topology, stop_controller,
)

from udp_timing_support import OutputPump, clock_mark
from capture_udp_fixed import Capture, container_pid, read_capture, tcpdump_stats

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
        except Exception:
            self.handle.close()
            raise

    def stop(self):
        if self.process.poll() is None:
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
        self.pump.drain()
        self.handle.close()
        try:
            command(["sudo", "-n", "docker", "exec", self.container,
                     "rm", "-f", "--", self.pidfile], timeout=3)
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            pass


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



# This protocol adds a finite sender queue. It must be audited, not treated as
# a free improvement in QoS. Application reports are NOT on-wire pacing proof.
SOURCE_CONTAINER = "mn.u1"
SOURCE_INTERFACE = "u1-eth0"
SOURCE_HANDLE = "7f00:"
SOURCE_FQ_OPTIONS = ["limit", "1000", "flow_limit", "1000",
                     "quantum", "1514", "initial_quantum", "1514", "pacing"]
PACING_HEADROOM = 1.05


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


def assess_stream(source, receiver, sender, duration, target):
    source_stats = stream_statistics(source, duration)
    receiver_stats = stream_statistics(receiver, duration)
    reasons, invalid = [], []
    for label, stream in (("source", source), ("GS", receiver)):
        observed_order = list(stream["ids"].values())
        if any(b < a for a, b in zip(observed_order, observed_order[1:])):
            invalid.append(label + ": nonmonotonic capture timestamps; wall-clock continuity is uncertain")
    counter = sender["total_packets"]
    # Contiguous sequences and sender/capture agreement are evidence checks;
    # missing capture IDs are never silently relabeled as network loss.
    expected = set(range(1, counter+1))
    source_ids, receiver_ids = set(source["ids"]), set(receiver["ids"])
    if source_ids != expected:
        invalid.append("Source IDs do not match the sender's complete reported sequence range")
    if source_ids != receiver_ids:
        invalid.append("Source and GS captured sequence sets differ; loss is not localized")
    if source_stats["duplicate_observations"] or receiver_stats["duplicate_observations"]:
        invalid.append("Duplicate observations require a separate sequence review")
    reported_duration = sender["end_s"]-sender["start_s"]
    if abs(reported_duration-duration) > .1:
        invalid.append("Sender reported duration differs from the requested duration by over 0.1s")
    measured = counter*1200*8/duration/1e6
    error = measured/target-1
    if abs(error) > CALIBRATION_POLICY["mean_rate_tolerance_fraction"] + 1e-12:
        reasons.append("Sender payload count per requested duration is outside target +/-5%")
    lower, upper = source_stats["interior_bin_indices"]
    bad_bins = [i for i in range(lower, upper)
                if abs(source_stats["one_second_payload_mbps"][i]/target-1) >
                CALIBRATION_POLICY["interior_one_second_rate_tolerance_fraction"] + 1e-12]
    if bad_bins:
        reasons.append("Source interior 1s bins outside target +/-10%: " + str(bad_bins))
    if source_stats["maximum_interior_captured_gap_ms"] > CALIBRATION_POLICY["maximum_interior_captured_gap_ms"]:
        reasons.append("Source captured gap exceeds 100ms within the interior window")
    return {"target_mbps": target, "sender_payload_mbps_from_count": measured,
            "sender_rate_error_percent": 100*error, "failed_criteria": reasons,
            "evidence_issues": invalid, "source": source_stats, "gs": receiver_stats,
            "source_ids_not_observed_at_gs": sorted(source_ids-receiver_ids),
            "gs_ids_not_observed_at_source": sorted(receiver_ids-source_ids),
            "verdict": "INCONCLUSIVE" if invalid else "FAIL" if reasons else "PASS"}


def report_calibration(directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    if (manifest.get("trial_protocol") != "udp-v4-fixed-source-calibration"
            or manifest.get("status") != "completed"):
        raise ValueError("Expected a completed source calibration")
    if manifest.get("calibration_policy") != CALIBRATION_POLICY:
        raise ValueError("Recorded calibration policy differs from this analyzer")
    if manifest.get("battery_event_enabled") is not False or manifest.get("mode") != "fixed":
        raise ValueError("Expected FIXED without a battery event")
    settings = manifest["capture_settings"]
    captures, quality, evidence = {}, {}, []
    for name in ("u1", "gs"):
        count, captures[name] = read_capture(directory / (name + ".pcap"),
            settings["source_ip"], settings["destination_ip"])
        quality[name] = tcpdump_stats((directory / (name + "-tcpdump.log")).read_text())
        if count != quality[name]["captured"]:
            evidence.append(name + ": pcap record count differs from tcpdump statistics")
        if quality[name]["kernel_dropped"] != 0:
            evidence.append(name + ": capture reported dropped packets")
    if manifest["source_pacing"].get("source_queue_caveat") is not False:
        evidence.append("Source fq had drops or remaining backlog")
    if manifest["source_pacing"].get("noqueue_restored") is not True:
        evidence.append("Source noqueue restoration was not verified")
    if any(manifest["queue_root_drop_deltas"].values()):
        evidence.append("UAV queues reported drops; this run is not a clean end-to-end baseline")
    streams = {}
    for profile in manifest["profiles"]:
        name, port = profile["name"], profile["port"]
        streams[name] = assess_stream(captures["u1"][port], captures["gs"][port],
            manifest["udp"][name]["sender"], manifest["options"]["duration"], profile["rate_mbps"])
    verdicts = [row["verdict"] for row in streams.values()]
    verdict = ("INCONCLUSIVE" if evidence or "INCONCLUSIVE" in verdicts else
               "FAIL" if "FAIL" in verdicts else "PASS")
    result = {"schema": 1, "verdict": verdict, "policy": CALIBRATION_POLICY,
        "capture_quality": quality, "evidence_issues": evidence, "streams": streams,
        "notes": [
            "PASS applies only to this instrumented run; it does not establish repeatability or QoS/energy benefits.",
            "INCONCLUSIVE denotes incomplete/contaminated evidence, not confirmed path loss.",
            "Packet count divided by requested duration describes generated payload load, not interface throughput over its entire capture span.",
            "Gap and bin timestamps come from interface capture; each endpoint uses its own first-packet origin. They are not one-way delay.",
            "Captures observe interfaces, not application delivery acknowledgements.",
            "Source buffering is part of this protocol. TEST_END tail times are not network latency measurements.",
            "Do not pool this no-event calibration with timed/ paced event trials."]}
    write_json(directory / "calibration-report.json", result)
    print("\nSOURCE CALIBRATION:", verdict, flush=True)
    print("Policy: mean target +/-5%; every interior 1s source bin +/-10%; interior gap <=100ms.")
    print("Interior: first captured source data +5s through +(duration-5)s. Not a QoS threshold.")
    for name, row in streams.items():
        print("%s: target %.3f, generated %.3f Mbps (%+.2f%%); %s" %
              (name, row["target_mbps"], row["sender_payload_mbps_from_count"],
               row["sender_rate_error_percent"], row["verdict"]))
        print("  source maximum interior captured gap: %.3f ms" % row["source"]["maximum_interior_captured_gap_ms"])
        for reason in row["failed_criteria"] + row["evidence_issues"]:
            print("  " + reason)
    for reason in evidence:
        print("Evidence issue:", reason)
    print("Saved:", directory / "calibration-report.json")
    print("Completion and acceptance are separate. Retain this run; do not automatically repeat or start a comparison batch.")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=40,
                        help="Client seconds, 20 through 60; defaults to 40")
    parser.add_argument("--ready-timeout", type=float, default=120.0)
    parser.add_argument("--analyze", type=Path, metavar="DIRECTORY",
                        help="Read a completed calibration; no live jobs or sudo")
    args = parser.parse_args()
    if args.analyze:
        try:
            report_calibration(args.analyze.expanduser().resolve())
            return 0
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
            print("Calibration analysis failed: " + str(error), file=sys.stderr)
            return 1
    args.mode = "fixed"
    if (not 20 <= args.duration <= 60 or not math.isfinite(args.ready_timeout)
            or args.ready_timeout <= 0):
        parser.error("Use duration 20 through 60 and a positive ready timeout")
    if os.geteuid() == 0:
        parser.error("Run as your normal user. Use sudo -v first")
    if set(P.DRONES) != {"UAV1", "UAV2", "UAV3", "UAV4"}:
        parser.error("This scenario expects the current four UAVs")
    ryu = Path.home() / "ryuenv" / "bin" / "ryu-manager"
    controller_path = PROJECT_ROOT / "controller" / "live_paths_timed.py"
    state_path = PROJECT_ROOT / "config" / "runtime_state.json"
    try:
        if not ryu.is_file() or not controller_path.is_file():
            raise ValueError("Ryu executable or controller file is missing")
        for executable in ("tcpdump", "nsenter", "timeout", "vmstat"):
            if not shutil.which(executable):
                raise ValueError("Required program not found: " + executable)
        docker_version = command(["sudo", "-n", "docker", "info", "--format", "{{.ServerVersion}}"])
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((P.CONTROLLER_IP, P.CONTROLLER_PORT))
        original = load_state(state_path, P.DRONES)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(2, "Preflight failed: %s\nCheck sudo -v and port 6653.\n" % error)

    lock = open(state_path.with_suffix(".trial.lock"), "a", encoding="utf-8")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        parser.exit(2, "Another live trial is using this state file\n")
    token = uuid.uuid4().hex[:12]
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = PROJECT_ROOT / "results" / "udp-source-calibration" / (stamp + "-" + args.mode + "-" + token)
    directory.mkdir(parents=True, exist_ok=False)
    manifest = {"schema": 1, "trial_protocol": "udp-v4-fixed-source-calibration",
                "status": "starting", "mode": args.mode, "options": vars(args),
                "profiles": PROFILES, "started_utc": stamp, "docker_version": docker_version.strip(),
                "fixed_weights": EXPERIMENT_FIXED_WEIGHTS, "source_sha256": {},
                "clock_origin": "host observation that BOTH servers have reported a positive UDP interval",
                "scope": "Concurrent forward synthetic VOICE/VIDEO UDP; no measured one-way delay, no energy drain",
                "notes": ["Client launches are sequential; their observed offsets are recorded.",
                          "Receiver bitrate and jitter are iperf's displayed summary values; intervals are retained.",
                          "No queue/OVS diagnostic commands are run between stream confirmation and client completion.",
                          "A VLAN update protects path versions, not transient bandwidth reservations or cross-class atomicity.",
                          "Root HTB drop deltas are per interface; child netem counters are not added again."]}
    for relative in ("sim/run_udp_calibration.py", "sim/capture_udp_fixed.py", "sim/run_live_trial.py", "controller/live_paths_timed.py",
                    "sim/udp_timing_support.py",
                     "core/model.py", "core/lab_scenario.py", "core/state_store.py",
                     "config/params.py", "topology/fanet_topo.py"):
        path = PROJECT_ROOT / relative
        if path.is_file():
            manifest["source_sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest["source_pacing"] = {
        "method": "iperf3 SO_MAX_PACING_RATE plus sender sch_fq",
        "application_target_mbps": {p["name"]: p["rate_mbps"] for p in PROFILES},
        "socket_pacing_cap_mbps": {p["name"]: p["rate_mbps"] * PACING_HEADROOM for p in PROFILES},
        "headroom_factor": PACING_HEADROOM,
        "headroom_reason": "5% margin for packet/header accounting; target -b stays unchanged",
        "source_interface": SOURCE_INTERFACE,
        "fq_options": SOURCE_FQ_OPTIONS,
        "note": "A finite source queue adds delay and may drop packets. Its counters/backlog are retained. "
                "Neither application send reports nor fq counters provide packet-level delay or on-wire verification."
    }
    manifest["calibration_policy"] = CALIBRATION_POLICY
    manifest["battery_event_enabled"] = False
    manifest["capture_settings"] = {"snaplen": 128, "post_jobs_observation_s": 8,
        "clock": "pcap wall clock; never subtracted from controller monotonic hooks"}
    manifest["notes"].append("Captures add overhead. Do not pool with timed or paced trial batches.")
    manifest["timing_marks"] = {"trial_created": clock_mark()}
    manifest["timing_semantics"] = (
        "Host CLOCK_MONOTONIC nanoseconds in runner/controller/line observers. "
        "Log line observation time is NOT packet arrival or iperf measurement time. "
        "Flow-submitted marks are NOT dataplane application timestamps.")
    manifest["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    manifest["host_logical_cpus"] = os.cpu_count()
    manifest["runner_cpu_affinity"] = sorted(os.sched_getaffinity(0))
    write_json(directory / "state-before-trial.json", original)
    write_json(directory / "manifest.json", manifest)
    controller = monitor = monitor_pump = None
    controller_handle = monitor_handle = None
    jobs = []
    clients = {}
    servers = {}
    succeeded = False
    fq_attempted = False
    packet_captures = []
    try:
        ensure_state(original, state_path)
        initial = {"schema": 1, "revision": original["revision"] + 1,
                   "states": {name: dict(STATES[name]) for name in P.DRONES}}
        initial["states"]["UAV1"]["energy_fraction"] = 0.90
        current = save_state(state_path, initial, P.DRONES)
        write_json(directory / "state-initial.json", current)
        plan = plan_forward(P, states=current["states"], weight_mode=args.mode,
                            fixed_weights=EXPERIMENT_FIXED_WEIGHTS)
        if any(not record["admitted"] for record in plan["classes"]):
            raise ValueError("Both classes must be admitted before this load test")
        by_name = {record["name"]: record for record in plan["classes"]}
        for profile in PROFILES:
            record = by_name.get(profile["name"], {})
            if (record.get("dscp") != profile["tos"] // 4
                    or record.get("demand_mbps") != profile["rate_mbps"]):
                raise ValueError("UDP profile does not match the planner's class demand/DSCP")
        write_json(directory / "plan-initial.json", plan)
        controller_handle = (directory / "controller.log").open("w", encoding="utf-8")
        env = dict(os.environ, FANET_WEIGHT_MODE=args.mode, FANET_STATE_FILE=str(state_path),
                   PYTHONUNBUFFERED="1", LC_ALL="C")
        controller = subprocess.Popen([str(ryu), "--ofp-listen-host", P.CONTROLLER_IP,
                                       "--ofp-tcp-listen-port", str(P.CONTROLLER_PORT), str(controller_path)],
                                      cwd=str(PROJECT_ROOT), env=env,
                                      stdout=controller_handle, stderr=subprocess.STDOUT)
        print("Results:", directory, flush=True)
        print("Ryu started: %s. Keep/start the topology in the other terminal." % args.mode.upper(), flush=True)
        epoch_before = wait_ready(controller, directory / "controller.log", current,
                                 args.mode, plan, state_path, args.ready_timeout)
        wait_topology(controller, current, state_path, directory, 60)
        wait_ready(controller, directory / "controller.log", current, args.mode, plan, state_path, 5)
        for container in ("mn.u1", "mn.gs"):
            manifest[container + "_iperf_version"] = capture(directory, container + "-iperf-version.txt",
                ["sudo", "-n", "docker", "exec", container, "iperf3", "--version"])
            help_text = command(["sudo", "-n", "docker", "exec", container, "iperf3", "--help"])
            if "--forceflush" not in help_text:
                raise ValueError("iperf3 --forceflush is required for live receive confirmation")
            if not manifest[container + "_iperf_version"].startswith("iperf 3.9"):
                raise ValueError("The packet decoder requires the currently validated iperf3 3.9")
        sender_help = command(["sudo", "-n", "docker", "exec", SOURCE_CONTAINER, "iperf3", "--help"])
        if "--fq-rate" not in sender_help:
            raise ValueError("The sender's iperf3 does not expose --fq-rate")
        original_qdisc_text = capture(directory, "source-qdisc-original.json",
            source_tc("-j", "-s", "qdisc", "show", "dev", SOURCE_INTERFACE))
        if root_qdisc(original_qdisc_text).get("kind") != "noqueue":
            raise ValueError("This diagnostic expects the existing sender root to be noqueue; left unchanged")
        fq_attempted = True
        command(source_tc("qdisc", "add", "dev", SOURCE_INTERFACE, "root", "handle", SOURCE_HANDLE,
                          "fq", *SOURCE_FQ_OPTIONS))
        source_before = source_snapshot(directory, "before")
        print("Sender fq installed: application targets 1.2/4.2 Mbps; socket caps 1.26/4.41 Mbps.", flush=True)
        ovs = ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", P.SWITCH_NAME]
        capture(directory, "flows-before.txt", ovs)
        before = queue_snapshot(directory, "before")
        # Capture is installed before either UDP client is launched. Its
        # readiness handshake uses the same sudo session as this runner.
        source_ip = P.HOSTS["u1"][0].split("/")[0]
        destination_ip = P.HOSTS["gs"][0].split("/")[0]
        packet_filter = ("ip and host %s and host %s and (udp or tcp) "
                         "and (port 5201 or port 5202)" % (source_ip, destination_ip))
        manifest["capture_settings"].update(source_ip=source_ip, destination_ip=destination_ip,
                                              filter=packet_filter, container_pids={})
        for name in ("u1", "gs"):
            pid = container_pid("mn." + name)
            manifest["capture_settings"]["container_pids"][name] = pid
            observer = Capture(directory, name, pid, name + "-eth0", packet_filter)
            packet_captures.append(observer)
            observer.ready()
        manifest["timing_marks"]["captures_ready"] = clock_mark()
        write_json(directory / "manifest.json", manifest)
        print("Both captures ready. FIXED calibration; NO battery event will be published.", flush=True)
        bound = args.duration + 50
        for profile in PROFILES:
            if listener(profile["port"]):
                raise RuntimeError("GS port %s already has a listener; existing process was not killed" % profile["port"])
            job = Job(directory, token, "mn.gs", profile["name"].lower() + "-server",
                      ["iperf3", "-s", "-1", "-p", str(profile["port"]), "-i", "1", "--forceflush"], bound)
            jobs.append(job)
            servers[profile["name"]] = job
        deadline = time.monotonic() + 10
        while True:
            if any(job.process.poll() is not None for job in servers.values()):
                raise RuntimeError("A UDP server exited before its client; inspect server logs")
            if all(listener(profile["port"]) for profile in PROFILES):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("UDP servers did not begin listening")
            time.sleep(0.1)
        monitor_handle = (directory / "vmstat.log").open("w", encoding="utf-8")
        manifest["timing_marks"]["vmstat_launch"] = clock_mark()
        monitor = subprocess.Popen(["vmstat", "-t", "1"], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                   errors="replace", bufsize=1,
                                   env=dict(os.environ, LC_ALL="C"))
        monitor_pump = OutputPump(monitor, monitor_handle, directory / "vmstat.timing.jsonl")
        if monitor.poll() is not None:
            raise RuntimeError("vmstat monitor did not start")
        destination = P.HOSTS["gs"][0].split("/")[0]
        manifest["timing_marks"]["client_launch_origin"] = clock_mark()
        launch_start = manifest["timing_marks"]["client_launch_origin"]["monotonic_ns"] / 1e9
        for profile in PROFILES:
            job = Job(directory, token, "mn.u1", profile["name"].lower() + "-client",
                      ["iperf3", "-c", destination, "-p", str(profile["port"]), "-u",
                       "-b", "%gM" % profile["rate_mbps"],
                       "--fq-rate", "%gM" % (profile["rate_mbps"] * PACING_HEADROOM),
                       "-l", "1200", "-t", str(args.duration),
                       "-i", "1", "-S", str(profile["tos"]), "--forceflush"], bound)
            jobs.append(job)
            clients[profile["name"]] = job
            manifest["timing_marks"][profile["name"].lower() + "_client_launch"] = job.launch_mark
        manifest["job_commands"] = {job.name: job.argv for job in jobs}
        manifest["client_launch_offsets_s"] = {name: job.launched - launch_start for name, job in clients.items()}
        deadline = launch_start + 15
        while True:
            if controller.poll() is not None or any(j.process.poll() is not None for j in jobs):
                raise RuntimeError("A process exited before concurrent UDP delivery was confirmed")
            ensure_state(current, state_path)
            active = {name: any(row["role"] == "interval" and row["total_packets"] > row["lost_packets"]
                                for row in udp_records(read_log(job.path))) for name, job in servers.items()}
            if all(active.values()):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Both servers did not confirm positive UDP receive intervals within 15s")
            time.sleep(0.05)
        manifest["timing_marks"]["both_streams_observed"] = clock_mark()
        origin = manifest["timing_marks"]["both_streams_observed"]["monotonic_ns"] / 1e9
        manifest["both_streams_confirmed_after_first_client_launch_s"] = origin - launch_start
        print("Both streams observed; collecting the unchanged FIXED baseline.", flush=True)
        manifest["epochs"] = {"before": epoch_before, "after": epoch_before}
        epoch_after = epoch_before
        deadline = launch_start + bound + 5
        while any(job.process.poll() is None for job in clients.values()):
            if controller.poll() is not None:
                raise RuntimeError("Controller exited during UDP measurement")
            if any(job.process.poll() not in (None, 0) for job in clients.values()):
                raise RuntimeError("iperf client failed; inspect saved logs")
            if time.monotonic() > deadline:
                raise RuntimeError("UDP clients exceeded the time limit")
            ensure_state(current, state_path)
            time.sleep(0.1)
        for job in jobs:
            job.process.wait(timeout=10)
            job.pump.drain()
            job.handle.flush()
            if job.process.returncode != 0:
                raise RuntimeError("%s failed (exit %s); inspect its log" % (job.name, job.process.returncode))
        if monitor.poll() is not None:
            raise RuntimeError("vmstat exited during measurement; monitoring evidence incomplete")
        manifest["timing_marks"]["traffic_jobs_finished"] = clock_mark()
        # A bounded observation window retains UDP tails after iperf exits.
        # Poll ownership/liveness and state; never discard queued source data
        # as a means of making this diagnostic appear to pass.
        drain_deadline = time.monotonic() + 8
        while time.monotonic() < drain_deadline:
            ensure_state(current, state_path)
            if controller.poll() is not None:
                raise RuntimeError("Controller exited during tail observation")
            if any(observer.process.poll() is not None for observer in packet_captures):
                raise RuntimeError("A packet capture exited before its observation window ended")
            time.sleep(0.1)
        for observer in packet_captures:
            observer.stop()
        manifest["timing_marks"]["captures_stopped"] = clock_mark()
        source_after = source_snapshot(directory, "final")
        source_drops = source_after["drops"] - source_before["drops"]
        if source_drops < 0:
            raise RuntimeError("Sender fq counters reset during this trial")
        manifest["source_pacing"].update(
            dropped_packets_delta=source_drops,
            final_queued_packets=source_after["qlen"],
            final_backlog_bytes=source_after["backlog"],
            initial_stats=source_before, final_stats=source_after,
            source_queue_caveat=bool(source_drops or source_after["qlen"] or source_after["backlog"]))
        after = queue_snapshot(directory, "final")
        capture(directory, "flows-final.txt", ovs)
        manifest["queue_root_drop_deltas"] = {name: after[name] - value for name, value in before.items()}
        if any(value < 0 for value in manifest["queue_root_drop_deltas"].values()):
            raise RuntimeError("A queue counter reset during the trial")
        manifest["udp"] = {}
        for profile in PROFILES:
            summary = receiver_summary(read_log(servers[profile["name"]].path))
            sender = [row for row in udp_records(read_log(clients[profile["name"]].path)) if row["role"] == "sender"]
            if not sender or sender[-1]["end_s"] - sender[-1]["start_s"] < args.duration - 1:
                raise RuntimeError("%s client did not finish the planned duration" % profile["name"])
            summary["sender"] = sender[-1]
            manifest["udp"][profile["name"]] = summary
        ensure_state(current, state_path)
        epoch_after = wait_ready(controller, directory / "controller.log", current,
                                 args.mode, plan, state_path, 5)
        if epoch_after != epoch_before:
            raise RuntimeError("Controller epoch changed in a no-event calibration")
        manifest["epochs"]["after"] = epoch_after
        manifest["status"] = "completed"
        succeeded = True
        for name, summary in manifest["udp"].items():
            print("%s receiver: %.3f Mbps | lost %s/%s (%.3f%%) | jitter %.3f ms" %
                  (name, summary["bitrate_mbps"], summary["lost_packets"], summary["total_packets"],
                   summary["loss_percent"], summary["jitter_ms"]), flush=True)
        print("Epoch %s -> %s. Root queue drop deltas: %s" %
              (epoch_before, epoch_after, manifest["queue_root_drop_deltas"]), flush=True)
        print("Source fq: dropped %d packets; final queue %d packets / %d bytes." % (
            source_drops, source_after["qlen"], source_after["backlog"]), flush=True)
        if manifest["source_pacing"]["source_queue_caveat"]:
            print("SOURCE QUEUE CAVEAT: source drops/backlog exist; retained for diagnosis, not a clean delivery result.", flush=True)
        print("Calibration traffic completed. Acceptance is evaluated after cleanup; this is not a QoS result.", flush=True)
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
        manifest["error"] = "Interrupted by user"
        print("Interrupted; partial evidence retained.", file=sys.stderr)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        print("UDP trial failed: %s\nEvidence retained: %s" % (error, directory), file=sys.stderr)
    finally:
        for observer in reversed(packet_captures):
            try:
                observer.stop()
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                manifest.setdefault("cleanup_errors", []).append("Capture cleanup: " + str(error))
                manifest["status"] = "failed"
                succeeded = False
        # Stop container jobs we created; never pkill unrelated iperf processes.
        for job in reversed(jobs):
            try:
                job.stop()
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                manifest.setdefault("cleanup_errors", []).append("%s: %s" % (job.name, error))
                manifest["status"] = "failed"
                succeeded = False
        if monitor is not None and monitor.poll() is None:
            monitor.terminate()
            try:
                monitor.wait(timeout=3)
            except subprocess.TimeoutExpired:
                monitor.kill()
                monitor.wait(timeout=3)
        stop_controller(controller)
        if controller_handle is not None:
            controller_handle.close()
        if monitor_pump is not None:
            try:
                monitor_pump.drain()
            except RuntimeError as error:
                manifest["monitor_observer_error"] = str(error)
                manifest["status"] = "failed"
                succeeded = False
        if monitor_handle is not None:
            monitor_handle.close()
        if fq_attempted:
            try:
                restore_source_qdisc(directory)
                manifest["source_pacing"]["noqueue_restored"] = True
                print("Sender noqueue restored.", flush=True)
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                manifest["source_pacing"]["noqueue_restored"] = False
                manifest.setdefault("cleanup_errors", []).append("Source fq cleanup: " + str(error))
                manifest["status"] = "failed"
                succeeded = False
                print("Source qdisc restoration failed: " + str(error), file=sys.stderr)
        manifest["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        write_json(directory / "manifest.json", manifest)
        lock.close()
        print("Ryu and owned traffic jobs stopped. Topology remains running; state is not restored.", flush=True)
    if succeeded:
        try:
            result = report_calibration(directory)
            manifest["calibration_verdict"] = result["verdict"]
            write_json(directory / "manifest.json", manifest)
        except (ImportError, OSError, ValueError, KeyError, TypeError) as error:
            print("Calibration report failed; raw data retained: " + str(error), file=sys.stderr)
            return 1
    return 0 if succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
