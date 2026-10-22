"""One separate no-event FIXED/A VOICE-buffer diagnostic.
Changes only VOICE netem limit 100 to 128; retains old source acceptance criteria.
No weak battery, no link failure, no automatic retries. Restores owned settings.
"""
import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import uuid

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "sim"))
from config import params as P
from core.lab_scenario import STATES
from core.state_store import save_state
from core.battery_policy import plan_protected, plan_signature
from core.battery_enforcement import (
    COOKIE, COOKIE_MASK, GUARD_PRIORITY, METER_BASE, MAX_EPOCH, CLASS_MINOR,
    ROOT_HANDLE, restore_commands, class_packets, meter_id, vlan_id,
)
from core.battery_live_support import command, topology_snapshot, quantity, stop_controller
from run_battery_source_calibration import (require, write_json, docker, ofctl, interfaces,
    strict_baseline, flow_configuration, meter_ids, meter_configuration, check_idle_flows,
    verify_owned_queues, wait_applied, verify_flow_profile, packet_snapshot, verify_transition)
from voice_buffer_support import (BUFFER_PROFILE, queue_commands, verify_buffer_queues,
    collect_voice_buffer, report_voice_buffer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=40)
    parser.add_argument("--analyze", type=Path)
    args = parser.parse_args()
    if args.analyze is not None:
        try:
            report_voice_buffer(args.analyze.expanduser().resolve())
            return 0
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
            print("Calibration analysis failed: " + str(error), file=sys.stderr)
            return 1
    if args.duration != 40:
        parser.error("This diagnostic requires exactly 40 seconds")
    args.mode, args.scenario = "fixed", "A"
    if os.geteuid() == 0:
        parser.error("Run as your normal user after sudo -v")
    controller = None
    handle = None
    lock = None
    owned_interfaces = []
    overlay_started = False
    directory = None
    report = {"schema": 1, "status": "starting", "mode": args.mode, "scenario": args.scenario,
              "scope": "One no-event VOICE buffer diagnostic; conditional captured delivery and capture-time separation, not calibrated QoS",
              "voice_buffer_profile": BUFFER_PROFILE,
              "protocol": "battery-voice-buffer-diagnostic-v1", "battery_event_enabled": False,
              "link_failure_enabled": False, "duration_s": args.duration,
              "cleanup_errors": [], "private_state": True}
    try:
        command(["sudo", "-n", "docker", "info", "--format", "{{.ServerVersion}}"])
        lock = (PROJECT_ROOT / "config/runtime_state.trial.lock").open("a")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((P.CONTROLLER_IP, P.CONTROLLER_PORT))
        ryu = Path.home() / "ryuenv/bin/ryu-manager"
        require(ryu.is_file(), "Missing ~/ryuenv/bin/ryu-manager")
        require(P.UAV_BW_MBPS == 5, "This queue profile is specific to 5 Mbps UAVs")
        for node in ("u1", "gs"):
            processes = command(["sudo", "-n", "docker", "top", "mn." + node, "-eo", "pid,args"])
            require(not re.search(r"\b(?:iperf3|tcpdump|ping)\b", processes),
                    "Existing traffic/capture in mn." + node + "; stop its owning trial first")
        baseline = topology_snapshot()
        strict_baseline(baseline)
        flows_before = ofctl("dump-flows")
        check_idle_flows(flows_before)
        meters_before = ofctl("dump-meters")
        require(not (meter_ids(meters_before) & set(range(METER_BASE, METER_BASE + MAX_EPOCH + 1))),
                "Protected meter range is already in use")
        features = ofctl("meter-features")
        require("drop" in features and "kbps" in features and "stats" in features,
                "Switch lacks the required drop/kbps/stats meter capability")
        states = copy.deepcopy(STATES)
        states["UAV1"]["energy_fraction"] = .90
        initial = plan_protected(P, states, args.scenario)
        require(all(row["admitted"] for row in initial["classes"]), "Initial classes are not both admitted")
        require(any("UAV1" in row["path"] for row in initial["classes"]),
                "Initial plan differs from the verified scenario A configuration")
        require(initial["config"] == {
            "weak_battery_threshold": .20, "relay_headroom_mbps": .10,
            "voice_payload_mbps": 1.2, "voice_scheduler_budget_mbps": 1.3,
            "video_payload_mbps": 4.2, "video_full_scheduler_budget_mbps": 4.4,
            "video_degraded_cap_mbps": 3.6, "voice_delay_budget_ms": 100.0,
            "video_delay_budget_ms": 150.0}, "Planner settings differ from the fixed queue profile")
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        directory = PROJECT_ROOT / "results/battery-voice-buffer-diagnostics" / (stamp + "-" + args.scenario + "-" + args.mode + "-" + uuid.uuid4().hex[:12])
        directory.mkdir(parents=True)
        print("Results:", directory, flush=True)
        write_json(directory / "topology-before.json", baseline)
        for label, text in (("flows-before.txt", flows_before), ("meters-before.txt", meters_before), ("meter-features.txt", features)):
            (directory / label).write_text(text)
        report["source_sha256"] = {name: hashlib.sha256((PROJECT_ROOT / name).read_bytes()).hexdigest()
            for name in ("core/battery_policy.py", "core/battery_enforcement.py", "controller/battery_paths.py",
                         "sim/run_battery_source_calibration.py", "sim/battery_calibration_support.py", "config/params.py",
                         "sim/run_voice_buffer_diagnostic.py", "sim/voice_buffer_support.py")}
        report["started_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        write_json(directory / "manifest.json", report)
        for drone, interface in interfaces():
            owned_interfaces.append((drone, interface))
            for arguments in queue_commands(interface, P.UAV_DELAY_MS):
                docker(drone, arguments)
        write_json(directory / "queues-installed.json", verify_buffer_queues())
        print("Only queue-setting change: VOICE netem limit 100 -> 128 on all eight UAV egress interfaces; VIDEO/CONTROL stay 100.", flush=True)
        state_file = directory / "private-state.json"
        document = save_state(state_file, {"schema": 1, "revision": 0, "states": states}, P.DRONES)
        handle = (directory / "controller.log").open("w")
        env = dict(os.environ, FANET_WEIGHT_MODE=args.mode, FANET_SCENARIO=args.scenario,
                   FANET_STATE_FILE=str(state_file), FANET_APPLIED_FILE=str(directory / "applied.json"),
                   FANET_SMOKE_TOKEN=uuid.uuid4().hex, PYTHONUNBUFFERED="1", LC_ALL="C")
        overlay_started = True
        controller = subprocess.Popen([str(ryu), "--ofp-listen-host", P.CONTROLLER_IP,
            "--ofp-tcp-listen-port", str(P.CONTROLLER_PORT), str(PROJECT_ROOT / "controller/battery_paths.py")],
            cwd=PROJECT_ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT)
        report["stages"] = {}
        applied = wait_applied(controller, directory, document, initial, args.mode, args.scenario)
        print("Protected FIXED plan confirmed: UAV1=90%%, epoch=%d; full VIDEO meter 4.4 Mbps." % applied["epoch"], flush=True)
        profile = verify_flow_profile(applied, directory, "initial")
        packet_before = packet_snapshot()
        collection = collect_voice_buffer(applied, directory, args.duration, controller)
        packet_after = packet_snapshot()
        deltas = {drone: {name: packet_after[drone][name] - packet_before[drone][name]
                          for name in CLASS_MINOR} for drone in P.DRONES}
        for row in initial["classes"]:
            for drone in P.DRONES:
                count = deltas[drone][row["name"]]
                require(count > 0 if drone in row["path"] else count == 0,
                        "UDP packets did not use the planned " + row["name"] + " queue/path at " + drone)
        confirmed = wait_applied(controller, directory, document, initial, args.mode, args.scenario)
        require(confirmed["epoch"] == applied["epoch"], "Epoch changed in a no-event calibration")
        write_json(directory / "queues-after-traffic.json", verify_buffer_queues())
        report["stages"]["initial"] = {"applied": applied, "profile_check": profile,
            "collection": collection, "forward_class_packet_deltas": deltas}
        log = (directory / "controller.log").read_text()
        epochs = {row["applied"]["epoch"] for row in report["stages"].values()}
        report["transition_events"] = {str(epoch): verify_transition(log, epoch) for epoch in epochs}
        report["status"] = "completed"
    except (Exception, KeyboardInterrupt) as error:
        report["status"] = "failed"
        report["error"] = type(error).__name__ + ": " + str(error)
        print("Calibration collection stopped:", report["error"], flush=True)
    finally:
        def clean(label, action):
            try:
                action()
            except Exception as error:
                report["cleanup_errors"].append(label + ": " + str(error))
        clean("stop owned Ryu", lambda: stop_controller(controller))
        if handle:
            handle.close()
        # Remove our guard/classifiers before restoring old network settings.
        if overlay_started:
            clean("delete owned flows", lambda: ofctl("del-flows", "cookie=0x%x/0x%x" % (COOKIE, COOKIE_MASK)))
            def remove_meters():
                present = meter_ids(ofctl("dump-meters"))
                for mid in sorted(present & set(range(METER_BASE, METER_BASE + MAX_EPOCH + 1))):
                    ofctl("del-meters", "meter=" + str(mid))
            clean("delete owned meters", remove_meters)
        for drone, interface in reversed(owned_interfaces):
            def restore(drone=drone, interface=interface):
                text = docker(drone, ["tc", "qdisc", "show", "dev", interface])
                if re.search(r"^qdisc htb 1: root\b", text, re.M):
                    return  # First replace failed before making a change.
                require(re.search(r"^qdisc htb 7e00: root\b", text, re.M),
                        "Owned root changed externally; refusing to overwrite it")
                for arguments in restore_commands(interface, P.UAV_DELAY_MS):
                    docker(drone, arguments)
            clean("restore queue " + interface, restore)
        if directory is not None:
            def verify_restore():
                write_json(directory / "topology-restored.json", topology_snapshot())
                after = ofctl("dump-flows")
                (directory / "flows-restored.txt").write_text(after)
                require(flow_configuration(after) == flow_configuration(flows_before), "Previous flow configuration differs after cleanup")
                require(meter_configuration(ofctl("dump-meters")) == meter_configuration(meters_before),
                        "Previous meter configuration differs after cleanup")
            clean("verify restoration", verify_restore)
            if report["cleanup_errors"]:
                report["collection_status_before_cleanup"] = report["status"]
                report["status"] = "cleanup_failed"
            report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
            write_json(directory / "manifest.json", report)
            print("VOICE BUFFER COLLECTION:", report["status"].upper(), flush=True)
            print("Private state retained as evidence; config/runtime_state.json was not edited.", flush=True)
            if not report["cleanup_errors"]:
                print("Owned Ryu/flows/meters removed; accepted relay queue configuration restored.", flush=True)
            else:
                print("Cleanup requires attention:", report["cleanup_errors"], flush=True)
            print("Collection completion is separate from source acceptance, measured QoS and energy savings.", flush=True)
        if lock:
            lock.close()
    if report["status"] == "completed":
        try:
            result = report_voice_buffer(directory)
            report["source_verdict"] = result["source_verdict"]
            report["voice_delivery_screen"] = result["voice_delivery_screen"]
            report["voice_capture_time_screen"] = result["voice_capture_time_screen"]
            write_json(directory / "manifest.json", report)
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
            print("Calibration report failed; evidence retained: " + str(error), file=sys.stderr)
            return 1
    return 0 if report["status"] == "completed" else 1

if __name__ == "__main__":
    sys.exit(main())
