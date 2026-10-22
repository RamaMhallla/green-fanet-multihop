"""One source-conditioned packet-delivery pilot, scenario A only.
Normal user after sudo -v, existing topology running. No comparison batch.
Both arms share the exact common initial plan and traffic settings.
--mode fixed freezes it; --mode adaptive uses the separate joint controller.
Private battery 90 -> 10 -> 0%; actual UAV1 link failure after +20s ready.
Source criteria remain unchanged and separate from the conditional endpoint.
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
    ROOT_HANDLE, queue_commands, restore_commands, class_packets, meter_id, vlan_id,
)
from core.battery_live_support import command, topology_snapshot, quantity, stop_controller
from core.joint_battery_policy import plan_joint_protected
from battery_resilience_support import collect_event_load, report_resilience, clock_mark, PRIMARY_ENDPOINT


from run_battery_udp_diagnostic import (
    require, write_json, docker, ofctl, interfaces, flow_configuration, meter_ids, meter_configuration, meter_input, check_idle_flows, strict_baseline, verify_owned_queues, wait_applied, verify_flow_profile, packet_snapshot, verify_transition,
)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fixed", "adaptive"), default="fixed")
    parser.add_argument("--duration", type=int, default=40)
    parser.add_argument("--analyze", type=Path)
    args = parser.parse_args()
    if args.analyze is not None:
        try:
            report_resilience(args.analyze.expanduser().resolve())
            return 0
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
            print("Calibration analysis failed: " + str(error), file=sys.stderr)
            return 1
    if args.duration != 40:
        parser.error("This diagnostic has a predeclared duration of 40 seconds")
    args.scenario = "A"
    if os.geteuid() == 0:
        parser.error("Run as your normal user after sudo -v")
    controller = None
    handle = None
    lock = None
    owned_interfaces = []
    down_interfaces = []
    overlay_started = False
    directory = None
    report = {"schema": 1, "status": "starting", "mode": args.mode, "scenario": args.scenario,
              "scope": "One A failure-delivery pilot, conditioned on captured source packets; not calibrated QoS or energy proof",
              "protocol": "battery-resilience-pilot-v1", "battery_event_enabled": True,
              "link_failure_enabled": True, "duration_s": args.duration,
              "cleanup_errors": [], "private_state": True, "primary_endpoint": PRIMARY_ENDPOINT}
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
        directory = PROJECT_ROOT / "results/battery-resilience-pilots" / (stamp + "-" + args.scenario + "-" + args.mode + "-" + uuid.uuid4().hex[:12])
        directory.mkdir(parents=True)
        print("Results:", directory, flush=True)
        write_json(directory / "topology-before.json", baseline)
        for label, text in (("flows-before.txt", flows_before), ("meters-before.txt", meters_before), ("meter-features.txt", features)):
            (directory / label).write_text(text)
        report["source_sha256"] = {name: hashlib.sha256((PROJECT_ROOT / name).read_bytes()).hexdigest()
            for name in ("core/battery_policy.py", "core/battery_enforcement.py", "controller/battery_paths.py",
                         "sim/run_battery_resilience_pilot.py", "sim/battery_resilience_support.py", "sim/run_battery_udp_diagnostic.py", "sim/battery_diagnostic_support.py", "core/joint_battery_policy.py", "controller/joint_battery_paths.py", "sim/battery_calibration_support.py", "config/params.py")}
        report["started_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        write_json(directory / "manifest.json", report)
        for drone, interface in interfaces():
            owned_interfaces.append((drone, interface))
            for arguments in queue_commands(interface, P.UAV_DELAY_MS):
                docker(drone, arguments)
        write_json(directory / "queues-installed.json", verify_owned_queues())
        print("Voice/video queues installed on all eight UAV egress interfaces.", flush=True)
        state_file = directory / "private-state.json"
        document = save_state(state_file, {"schema": 1, "revision": 0, "states": states}, P.DRONES)
        handle = (directory / "controller.log").open("w")
        env = dict(os.environ, FANET_WEIGHT_MODE=args.mode, FANET_SCENARIO=args.scenario,
                   FANET_STATE_FILE=str(state_file), FANET_APPLIED_FILE=str(directory / "applied.json"),
                   FANET_SMOKE_TOKEN=uuid.uuid4().hex, PYTHONUNBUFFERED="1", LC_ALL="C")
        overlay_started = True
        controller = subprocess.Popen([str(ryu), "--ofp-listen-host", P.CONTROLLER_IP,
            "--ofp-tcp-listen-port", str(P.CONTROLLER_PORT), str(PROJECT_ROOT / "controller/joint_battery_paths.py")],
            cwd=PROJECT_ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT)
        report["stages"] = {}
        applied = wait_applied(controller, directory, document, initial, args.mode, args.scenario)
        print("Protected %s initial plan confirmed: UAV1=90%%, epoch=%d; full VIDEO meter 4.4 Mbps." % (args.mode.upper(), applied["epoch"]), flush=True)
        profile = verify_flow_profile(applied, directory, "initial")
        report["stages"]["initial"] = {"applied": applied, "profile_check": profile}
        latest_expected = initial

        def event_tick(data, finished):
            nonlocal document, latest_expected
            origin = data["timing_marks"]["both_streams_observed"]["monotonic_ns"]
            elapsed = (time.monotonic_ns() - origin) / 1e9
            for label, offset, energy in (("weak", 8.0, .10), ("failed", 20.0, .0)):
                if label in report["stages"] or elapsed < offset:
                    continue
                require(not finished, "Clients finished before all planned battery events; diagnostic incomplete")
                mark = clock_mark()
                stage = {"scheduled_after_ready_s": offset, "publish_start": mark,
                         "observed_publish_lateness_s": elapsed - offset}
                document = copy.deepcopy(document)
                document["revision"] += 1
                document["states"]["UAV1"]["energy_fraction"] = energy
                save_state(state_file, document, P.DRONES)
                stage["publish_end"] = clock_mark()
                expected = (initial if args.mode == "fixed" else
                            plan_joint_protected(P, document["states"], "A", latest_expected))
                current = wait_applied(controller, directory, document, expected, args.mode, args.scenario, timeout=8)
                require(current["plan"]["states"] == expected["states"], "Controller state history differs")
                require(current["plan"].get("discharge_caps_mbps") == expected.get("discharge_caps_mbps"),
                        "Controller guard history differs")
                latest_expected = expected
                stage["confirmation_observed"] = clock_mark()
                stage["applied"] = current
                stage["profile_check"] = verify_flow_profile(current, directory, label)
                if label == "failed":
                    stage["link_down_begin"] = clock_mark()
                    for interface in ("uav1-eth0", "uav1-eth1"):
                        down_interfaces.append(interface)
                        docker("UAV1", ["ip", "link", "set", "dev", interface, "down"])
                    links = json.loads(docker("UAV1", ["ip", "-j", "link", "show"]))
                    require(all("UP" not in next(row for row in links if row["ifname"] == interface)["flags"]
                                for interface in down_interfaces), "UAV1 physical failure was not confirmed")
                    stage["link_down_confirmed"] = clock_mark()
                report["stages"][label] = stage
                data["event_stages"] = report["stages"]
                write_json(directory / "manifest.json", report)
                write_json(directory / "resilience-data.json", data)
                print("UAV1=%d%%; epoch=%d; VIDEO=%s%s" %
                      (energy * 100, current["epoch"], expected["classes"][1]["decision"],
                       "; both UAV1 links DOWN" if label == "failed" else ""), flush=True)
                elapsed = (time.monotonic_ns() - origin) / 1e9
            if finished:
                require(set(report["stages"]) == {"initial", "weak", "failed"},
                        "Not all event stages occurred before clients finished")

        collection = collect_event_load(applied, directory, args.duration, controller, event_tick, args.mode)
        current = wait_applied(controller, directory, document, latest_expected, args.mode, args.scenario, timeout=8)
        require(current["epoch"] == report["stages"]["weak"]["applied"]["epoch"],
                "Unexpected epoch changed between weak and failed plans")
        write_json(directory / "queues-after-traffic.json", verify_owned_queues())
        report["collection"] = collection
        report["video_meter_totals"] = {}
        for epoch in sorted({row["applied"]["epoch"] for row in report["stages"].values()}):
            text = ofctl("meter-stats", "meter=" + str(meter_id(epoch)))
            (directory / ("video-meter-epoch-%d-final.txt" % epoch)).write_text(text)
            from battery_calibration_support import meter_counts
            report["video_meter_totals"][str(epoch)] = meter_counts(text)
        log = (directory / "controller.log").read_text()
        epochs = {row["applied"]["epoch"] for row in report["stages"].values()}
        report["transition_events"] = {str(epoch): verify_transition(log, epoch) for epoch in epochs}
        report["status"] = "completed"
    except (Exception, KeyboardInterrupt) as error:
        report["status"] = "failed"
        report["error"] = type(error).__name__ + ": " + str(error)
        print("Diagnostic collection stopped:", report["error"], flush=True)
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
        for interface in reversed(down_interfaces):
            clean("restore " + interface, lambda name=interface:
                  docker("UAV1", ["ip", "link", "set", "dev", name, "up"]))
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
            print("DIAGNOSTIC COLLECTION:", report["status"].upper(), flush=True)
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
            result = report_resilience(directory)
            report["source_verdict"] = result["source_verdict"]
            report["performance_comparison_supported"] = False
            write_json(directory / "manifest.json", report)
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
            print("Calibration report failed; evidence retained: " + str(error), file=sys.stderr)
            return 1
    return 0 if report["status"] == "completed" else 1

if __name__ == "__main__":
    sys.exit(main())
