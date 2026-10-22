"""Separate LIVE joint-candidate functional check, not a UDP comparison.
Run normally after sudo -v with the existing topology running. Private battery
sequence 90 -> 30 -> 25 -> 25 -> 19 -> 0%; downs both UAV1 links at zero.
Verifies applied guard history, epochs, profiles and small DSCP-marked ICMP
probes. Restores owned settings. The original controller remains unchanged.
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
from core.joint_battery_policy import plan_joint_protected
from core.battery_enforcement import (
    COOKIE, COOKIE_MASK, GUARD_PRIORITY, METER_BASE, MAX_EPOCH, CLASS_MINOR,
    ROOT_HANDLE, queue_commands, restore_commands, class_packets, meter_id, vlan_id,
)
from core.battery_live_support import command, topology_snapshot, quantity, stop_controller


from check_battery_enforcement import (
    require, write_json, docker, ofctl, interfaces, flow_configuration,
    meter_ids, meter_configuration, check_idle_flows, strict_baseline, verify_owned_queues,
    verify_flow_profile, probe, verify_transition,
)
import check_battery_enforcement as legacy


def wait_applied(process, directory, document, expected, mode, scenario, timeout=30):
    applied = legacy.wait_applied(process, directory, document, expected, mode, scenario, timeout)
    require(applied["plan"]["states"] == expected["states"], "Applied candidate state history differs")
    for field in ("discharge_caps_mbps", "guarded_relays", "guard_blocks_feasible_voice"):
        require(applied["plan"].get(field) == expected.get(field),
                "Applied candidate guard history differs: " + field)
    return applied

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("A", "B"), default="A")
    args = parser.parse_args()
    args.mode = "adaptive"
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
              "scope": "Separate joint-candidate functional check; no UDP/QoS or energy result",
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
                "The common initial plan does not use UAV1; this failure check would have no affected flow")
        require(initial["config"] == {
            "weak_battery_threshold": .20, "relay_headroom_mbps": .10,
            "voice_payload_mbps": 1.2, "voice_scheduler_budget_mbps": 1.3,
            "video_payload_mbps": 4.2, "video_full_scheduler_budget_mbps": 4.4,
            "video_degraded_cap_mbps": 3.6, "voice_delay_budget_ms": 100.0,
            "video_delay_budget_ms": 150.0}, "Planner settings differ from the fixed queue profile")
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        directory = PROJECT_ROOT / "results/joint-battery-functional-checks" / (stamp + "-" + args.scenario + "-" + args.mode + "-" + uuid.uuid4().hex[:12])
        directory.mkdir(parents=True)
        print("Results:", directory, flush=True)
        write_json(directory / "topology-before.json", baseline)
        for label, text in (("flows-before.txt", flows_before), ("meters-before.txt", meters_before), ("meter-features.txt", features)):
            (directory / label).write_text(text)
        report["source_sha256"] = {name: hashlib.sha256((PROJECT_ROOT / name).read_bytes()).hexdigest()
            for name in ("core/battery_policy.py", "core/battery_enforcement.py", "controller/battery_paths.py",
                         "sim/check_joint_battery_enforcement.py", "sim/check_battery_enforcement.py", "core/joint_battery_policy.py", "controller/joint_battery_paths.py", "config/params.py")}
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
        previous_expected = initial
        expected_epochs = ({"initial": 0, "declining": 0, "intermediate": 0, "plateau": 0, "weak": 1, "failed": 1}
                           if args.scenario == "A" else
                           {"initial": 0, "declining": 0, "intermediate": 1, "plateau": 1, "weak": 1, "failed": 1})
        for label, energy in (("initial", .90), ("declining", .30), ("intermediate", .25),
                              ("plateau", .25), ("weak", .19), ("failed", .0)):
            expected = initial if label == "initial" else plan_joint_protected(
                P, {**states, "UAV1": {**states["UAV1"], "energy_fraction": energy}}, args.scenario, previous_expected)
            require(all(row["admitted"] for row in expected["classes"]),
                    "Candidate rejected a class in this declared functional scenario")
            decision = "VIDEO_DOWNGRADED" if args.scenario == "A" and energy < .20 else "VIDEO_ADMITTED_FULL"
            require(expected["classes"][1]["decision"] == decision, "Candidate VIDEO profile differs from declared scenario")
            if label in ("intermediate", "plateau"):
                require(abs(expected["forward_scheduler_allocations_mbps"]["UAV1"] -
                            (1.3 if args.scenario == "A" else 0)) < 1e-9,
                        "Candidate does not retain the declared 25% allocation")
            if label != "initial":
                document = copy.deepcopy(document)
                document["revision"] += 1
                document["states"]["UAV1"]["energy_fraction"] = energy
                save_state(state_file, document, P.DRONES)
            applied = wait_applied(controller, directory, document, expected, args.mode, args.scenario)
            require(applied["epoch"] == expected_epochs[label], "Unexpected candidate epoch for " + label)
            previous_expected = expected
            if label == "failed":
                report["link_failure_begin_monotonic_ns"] = time.monotonic_ns()
                for interface in ("uav1-eth0", "uav1-eth1"):
                    down_interfaces.append(interface)
                    docker("UAV1", ["ip", "link", "set", "dev", interface, "down"])
                links = json.loads(docker("UAV1", ["ip", "-j", "link", "show"]))
                require(all("UP" not in next(row for row in links if row["ifname"] == name)["flags"]
                            for name in down_interfaces), "UAV1 link failure was not applied")
                report["link_failure_confirmed_monotonic_ns"] = time.monotonic_ns()
            print("UAV1=%d%%; stage=%s; epoch=%d; UAV1 budget=%.2f Mbps; VIDEO=%s" %
                  (energy * 100, label, applied["epoch"],
                   expected["forward_scheduler_allocations_mbps"]["UAV1"],
                   expected["classes"][1]["decision"]), flush=True)
            profile = verify_flow_profile(applied, directory, label)
            probes = probe(applied, directory, label, physically_failed=(label == "failed"))
            report["stages"][label] = {"applied": applied, "profile_check": profile, "probes": probes}
            write_json(directory / "manifest.json", report)
        log = (directory / "controller.log").read_text()
        epochs = {row["applied"]["epoch"] for row in report["stages"].values()}
        report["transition_events"] = {str(epoch): verify_transition(log, epoch) for epoch in epochs}
        report["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        report["status"] = "failed"
        report["error"] = type(error).__name__ + ": " + str(error)
        print("Joint candidate check stopped:", report["error"], flush=True)
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
            clean("restore " + interface, lambda name=interface: docker("UAV1", ["ip", "link", "set", "dev", name, "up"]))
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
                report["functional_status_before_cleanup"] = report["status"]
                report["status"] = "cleanup_failed"
            report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
            write_json(directory / "manifest.json", report)
            print("JOINT CANDIDATE FUNCTIONAL CHECK:", report["status"].upper(), flush=True)
            print("Private state retained as evidence; config/runtime_state.json was not edited.", flush=True)
            if not report["cleanup_errors"]:
                print("Owned Ryu/flows/meters removed; accepted queue configuration and links restored.", flush=True)
            else:
                print("Cleanup requires attention:", report["cleanup_errors"], flush=True)
            print("This is not a UDP performance, source-calibration or energy-saving result.", flush=True)
        if lock:
            lock.close()
    return 0 if report["status"] == "passed" else 1

if __name__ == "__main__":
    sys.exit(main())
