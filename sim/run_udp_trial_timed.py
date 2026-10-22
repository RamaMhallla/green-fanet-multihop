"""Concurrent synthetic VOICE/VIDEO UDP trial with a live battery event.

Run normally, after sudo -v; topology runs in another terminal. Reuses the
verified helpers in sim/run_live_trial.py. Does not modify that script, model,
controller, or topology. Results are separate: results/udp-trials/<unique-id>.
No ICMP probe is generated; rates, loss and jitter come from the UDP receiver.
"""

import argparse
import datetime as dt
import fcntl
import hashlib
import math
import os
from pathlib import Path
import re
import signal
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("fixed", "adaptive"))
    parser.add_argument("--duration", type=int, default=40, help="Seconds per UDP client")
    parser.add_argument("--change-after", type=float, default=15.0,
                        help="Seconds after both first UDP receive intervals are observed")
    parser.add_argument("--ready-timeout", type=float, default=120.0)
    args = parser.parse_args()
    if (args.duration < 20 or not math.isfinite(args.change_after)
            or not 0 < args.change_after < args.duration - 10
            or not math.isfinite(args.ready_timeout) or args.ready_timeout <= 0):
        parser.error("Use duration >=20s; leave >10s after the event")
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
    directory = PROJECT_ROOT / "results" / "udp-timed-trials" / (stamp + "-" + args.mode + "-" + token)
    directory.mkdir(parents=True, exist_ok=False)
    manifest = {"schema": 1, "trial_protocol": "udp-v2-host-observed-timing",
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
    for relative in ("sim/run_udp_trial_timed.py", "sim/run_live_trial.py", "controller/live_paths_timed.py",
                    "sim/udp_timing_support.py",
                     "core/model.py", "core/lab_scenario.py", "core/state_store.py",
                     "config/params.py", "topology/fanet_topo.py"):
        path = PROJECT_ROOT / relative
        if path.is_file():
            manifest["source_sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
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
        ovs = ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", P.SWITCH_NAME]
        capture(directory, "flows-before.txt", ovs)
        before = queue_snapshot(directory, "before")
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
                       "-b", "%gM" % profile["rate_mbps"], "-l", "1200", "-t", str(args.duration),
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
        if origin - launch_start + args.change_after >= args.duration - 5:
            raise RuntimeError("Startup too slow to leave at least 5s of loaded traffic after event")
        print("Both UDP streams delivering data: VOICE 1.2 Mbps, VIDEO 4.2 Mbps.", flush=True)
        print("Battery event in %.1fs; receiver intervals are being saved." % args.change_after, flush=True)
        while time.monotonic() - origin < args.change_after:
            if controller.poll() is not None or any(j.process.poll() is not None for j in jobs):
                raise RuntimeError("A process exited before the battery event")
            ensure_state(current, state_path)
            time.sleep(0.05)
        event = {"schema": 1, "revision": current["revision"] + 1,
                 "states": {name: dict(value) for name, value in current["states"].items()}}
        event["states"]["UAV1"]["energy_fraction"] = 0.10
        ensure_state(current, state_path)
        manifest["timing_marks"]["event_publish_start"] = clock_mark()
        manifest["event_publish_start_offset_s"] = (
            manifest["timing_marks"]["event_publish_start"]["monotonic_ns"] / 1e9 - origin)
        current = save_state(state_path, event, P.DRONES)
        manifest["timing_marks"]["event_publish_end"] = clock_mark()
        manifest["event_publish_end_offset_s"] = (
            manifest["timing_marks"]["event_publish_end"]["monotonic_ns"] / 1e9 - origin)
        write_json(directory / "state-event.json", current)
        event_plan = plan_forward(P, states=current["states"], weight_mode=args.mode,
                                  fixed_weights=EXPERIMENT_FIXED_WEIGHTS)
        write_json(directory / "plan-event.json", event_plan)
        print("UAV1 set to 10%%, revision %s. Waiting for controller..." % current["revision"], flush=True)
        epoch_after = wait_ready(controller, directory / "controller.log", current,
                                args.mode, event_plan, state_path, 15)
        manifest["timing_marks"]["controller_confirmation_observed"] = clock_mark()
        manifest["confirmation_observed_offset_s"] = (
            manifest["timing_marks"]["controller_confirmation_observed"]["monotonic_ns"] / 1e9 - origin)
        manifest["epochs"] = {"before": epoch_before, "after": epoch_after}
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
        manifest["status"] = "completed"
        succeeded = True
        for name, summary in manifest["udp"].items():
            print("%s receiver: %.3f Mbps | lost %s/%s (%.3f%%) | jitter %.3f ms" %
                  (name, summary["bitrate_mbps"], summary["lost_packets"], summary["total_packets"],
                   summary["loss_percent"], summary["jitter_ms"]), flush=True)
        print("Epoch %s -> %s. Root queue drop deltas: %s" %
              (epoch_before, epoch_after, manifest["queue_root_drop_deltas"]), flush=True)
        print("Completed. These are UDP performance measurements, not an energy-saving result.", flush=True)
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
        manifest["error"] = "Interrupted by user"
        print("Interrupted; partial evidence retained.", file=sys.stderr)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        print("UDP trial failed: %s\nEvidence retained: %s" % (error, directory), file=sys.stderr)
    finally:
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
        manifest["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        write_json(directory / "manifest.json", manifest)
        lock.close()
        print("Ryu and owned traffic jobs stopped. Topology remains running; state is not restored.", flush=True)
    return 0 if succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
