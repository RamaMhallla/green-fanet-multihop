"""Bounded LIVE battery-policy functional check; run normally after sudo -v.

Owns a temporary flow overlay, video meters, relay egress queues and one Ryu
process. Uses a PRIVATE synthetic state file, not config/runtime_state.json.
Tests small DSCP-marked ICMP probes, then physically downs both UAV1 links.
Restores the accepted topology queue configuration and links on normal error
or exit. Queue counters/history cannot be restored. No UDP load batch, source
calibration, measured QoS guarantee, codec adaptation or real energy result.
Do not run any other controller, traffic generator or topology edit alongside.
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


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def docker(node, arguments):
    return command(["sudo", "-n", "docker", "exec", "mn." + node.lower()] + arguments)


def ofctl(operation, *arguments):
    return command(["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", operation,
                    P.SWITCH_NAME] + list(arguments))


def interfaces():
    return [(drone, drone.lower() + "-eth" + str(index))
            for drone in P.DRONES for index in (0, 1)]


def flow_configuration(text):
    rows = []
    for line in text.splitlines():
        if "actions=" not in line:
            continue
        line = re.sub(r"\b(?:duration|n_packets|n_bytes|idle_age|hard_age)=[^, ]+,?\s*", "", line)
        rows.append(" ".join(line.split()))
    return sorted(rows)


def meter_ids(text):
    return set(map(int, re.findall(r"\bmeter(?:_id)?\s*[:=]\s*(\d+)", text)))


def meter_configuration(text):
    # OVS 2.17 prints bands on continuation lines. Ignore the reply xid.
    blocks = re.findall(r"^\s*meter(?:_id)?\s*[:=]\s*\d+\b.*?(?=^\s*meter(?:_id)?\s*[:=]|\Z)", text, re.M | re.S)
    return {next(iter(meter_ids(block))): " ".join(block.split()) for block in blocks}


def meter_input(text):
    match = re.search(r"\bpacket_in_count\s*[:=]\s*(\d+)", text)
    require(match is not None, "Missing meter packet_in_count in meter statistics")
    return int(match[1])


def check_idle_flows(text):
    for line in text.splitlines():
        if "actions=" not in line:
            continue
        priority = re.search(r"\bpriority=(\d+)", line)
        require(priority is not None and int(priority[1]) < GUARD_PRIORITY,
                "Existing flow uses a reserved priority >=190; no network change made")
        require(not re.search(r"\b(?:idle_timeout|hard_timeout)=", line),
                "Existing expiring flows cannot be faithfully retained")
        tag = re.search(r"\bdl_vlan=(\d+)", line)
        require(tag is None or not 3000 <= int(tag[1]) <= 3962,
                "Existing flow uses the reserved protected VLAN range")


def strict_baseline(snapshot):
    for drone, entries in snapshot["uavs"].items():
        for interface, row in entries.items():
            kinds = re.findall(r"^qdisc (\S+) (\S+)", row["qdiscs"], re.M)
            require(sorted(kinds) == sorted([("htb", "1:"), ("netem", "10:"), ("clsact", "ffff:")]),
                    interface + ": unexpected qdisc; leave it untouched")
            require(len(re.findall(r"^class ", row["classes"], re.M)) == 1,
                    interface + ": extra classes would not be restored")
            line = next(line for line in row["qdiscs"].splitlines() if line.startswith("qdisc netem "))
            require(re.fullmatch(r"qdisc netem 10: parent 1:10 limit 100(?: delay [\d.]+(?:ns|us|ms|s))?\s*", line),
                    interface + ": unexpected netem options would not be restored")
            root_filters = docker(drone, ["tc", "filter", "show", "dev", interface, "parent", "1:"])
            require(not root_filters.strip(), interface + ": extra root filters would not be restored")


def verify_owned_queues():
    result = {}
    for drone, interface in interfaces():
        qdiscs = docker(drone, ["tc", "-s", "qdisc", "show", "dev", interface])
        classes = docker(drone, ["tc", "-s", "class", "show", "dev", interface])
        filters = docker(drone, ["tc", "filter", "show", "dev", interface, "parent", ROOT_HANDLE])
        require(re.search(r"^qdisc htb 7e00: root\b", qdiscs, re.M), interface + ": owned root missing")
        for minor, rate, ceil, priority in (("10", 1.3, 1.3, 0), ("20", 3.6, 4.4, 1), ("30", .1, .1, 2)):
            match = re.search(r"^class htb 7e00:" + minor + r"\b([^\n]*)", classes, re.M)
            require(match is not None, interface + ": missing class " + minor)
            for key, expected in (("rate", rate), ("ceil", ceil)):
                value = re.search(r"\b" + key + r" (\S+)", match[1])
                require(value is not None and abs(quantity(value[1], "rate") - expected) < 1e-5,
                        interface + ": wrong " + key + " on " + minor)
            require(re.search(r"\bprio " + str(priority) + r"\b", match[1]), interface + ": wrong priority")
            class_packets(classes, minor)
        require(filters.count("flower") >= 4 and "7e00:10" in filters and "7e00:20" in filters,
                interface + ": classification filters missing")
        result[interface] = {"qdiscs": qdiscs, "classes": classes, "filters": filters}
    return result


def wait_applied(process, directory, document, expected, mode, scenario, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        require(process.poll() is None, "Ryu exited; inspect controller.log")
        log = (directory / "controller.log").read_text(errors="replace")
        require(not any(word in log for word in ("ENFORCEMENT FAILED", "OpenFlow error", "Traceback")),
                "Controller reported an error; inspect controller.log")
        path = directory / "applied.json"
        if path.exists():
            row = json.loads(path.read_text())
            if row["revision"] == document["revision"]:
                require(row["mode"] == mode and row["scenario"] == scenario,
                        "Controller mode/scenario acknowledgement mismatch")
                require(plan_signature(row["plan"]) == plan_signature(expected),
                        "Applied plan/profile differs from the expected plan")
                return row
        time.sleep(.1)
    raise RuntimeError("No confirmed protected plan within %.0fs; inspect controller.log" % timeout)


def verify_flow_profile(applied, directory, label):
    epoch = applied["epoch"]
    flows = ofctl("dump-flows")
    meters = ofctl("dump-meters")
    (directory / (label + "-flows.txt")).write_text(flows)
    (directory / (label + "-meters.txt")).write_text(meters)
    video = next(row for row in applied["plan"]["classes"] if row["name"] == "VIDEO")
    mid = meter_id(epoch)
    block = meter_configuration(meters).get(mid, "")
    require("kbps" in block and "stats" in block and block.count("type=") == 1
            and "type=drop" in block and re.search(r"\brate=" + str(round(video["meter_cap_mbps"] * 1000)) + r"\b", block),
            "Expected video kbps/drop meter configuration missing")
    ports = P.port_map()
    for row in applied["plan"]["classes"]:
        selected = [line for line in flows.splitlines()
                    if re.search(r"\bpriority=200\b", line)
                    and re.search(r"\bin_port=" + str(ports["u1"]) + r"(?:,| )", line)
                    and re.search(r"\bnw_tos=" + str(row["dscp"] * 4) + r"(?:,| )", line)]
        require(len(selected) == 1, "Missing unique forward ingress classifier for " + row["name"])
        line = selected[0]
        assigned = re.findall(r"set_field:(0x[0-9a-fA-F]+|\d+)->vlan_vid|mod_vlan_vid:(0x[0-9a-fA-F]+|\d+)", line)
        require(any(int(first or second, 0) & 0xfff == vlan_id(row["dscp"], epoch)
                    for first, second in assigned),
                "Ingress classifier does not select the expected VLAN version")
        if row["name"] == "VIDEO":
            require("meter:" + str(mid) in line, "VIDEO ingress does not reference its owned meter")
        else:
            require("meter:" not in line, "VOICE unexpectedly has a drop meter")
    return {"epoch": epoch, "video_meter_id": mid, "video_cap_mbps": video["meter_cap_mbps"]}


def packet_snapshot():
    result = {}
    for drone in P.DRONES:
        interface = drone.lower() + "-eth1"
        text = docker(drone, ["tc", "-s", "class", "show", "dev", interface])
        result[drone] = {name: class_packets(text, minor) for name, minor in CLASS_MINOR.items()}
    return result


def probe(applied, directory, label, physically_failed=False):
    before = packet_snapshot()
    mid = applied["video_meter_id"]
    meter_before = ofctl("meter-stats", "meter=" + str(mid))
    observations = []
    for row in applied["plan"]["classes"]:
        expected_delivery = not (physically_failed and "UAV1" in row["path"])
        args = ["sudo", "-n", "docker", "exec", "mn.u1", "ping", "-n", "-c", "3",
                "-i", "0.2", "-W", "1", "-Q", str(row["dscp"] * 4),
                P.HOSTS["gs"][0].split("/")[0]]
        completed = subprocess.run(args, capture_output=True, text=True, timeout=8)
        text = completed.stdout + completed.stderr
        (directory / (label + "-" + row["name"].lower() + "-ping.txt")).write_text(text)
        counts = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", text)
        require(counts is not None and int(counts[1]) == 3, "Unusable probe result for " + row["name"])
        received = int(counts[2])
        require((received > 0) == expected_delivery,
                label + ": unexpected connectivity for " + row["name"] + "; inspect probe log")
        observations.append({"name": row["name"], "transmitted": 3, "received": received,
                             "expected_delivery": expected_delivery, "returncode": completed.returncode})
    time.sleep(.2)
    after = packet_snapshot()
    deltas = {drone: {name: after[drone][name] - before[drone][name] for name in CLASS_MINOR}
              for drone in P.DRONES}
    for row, observation in zip(applied["plan"]["classes"], observations):
        if not observation["expected_delivery"]:
            continue
        for drone in P.DRONES:
            if drone in row["path"]:
                require(deltas[drone][row["name"]] > 0,
                        label + ": packets did not enter the intended " + row["name"] + " queue at " + drone)
            else:
                require(deltas[drone][row["name"]] == 0,
                        label + ": protected traffic appeared on an unintended relay: " + drone)
    meter_after = ofctl("meter-stats", "meter=" + str(mid))
    require(meter_input(meter_after) > meter_input(meter_before), "Video probes did not hit the active meter")
    result = {"probes": observations, "forward_class_packet_deltas": deltas,
              "meter_before": meter_before, "meter_after": meter_after,
              "scope": "Small ICMP connectivity/classification probes; not UDP performance or overload protection"}
    write_json(directory / (label + "-probes.json"), result)
    for row in observations:
        print("  %s: %d/3 replies; expected %s" %
              (row["name"], row["received"], "connected" if row["expected_delivery"] else "outage"), flush=True)
    return result


def verify_transition(log, epoch):
    events = []
    for line in log.splitlines():
        if "TIMING " in line:
            row = json.loads(line.split("TIMING ", 1)[1])
            if row.get("epoch") == epoch:
                events.append(row)
    sequence = [row["event"] for row in events]
    for event in ("INTERNAL_BARRIER_REPLY", "VIDEO_BARRIER_REPLY", "VOICE_UPDATE_BEGIN", "INGRESS_BARRIER_REPLY"):
        require(sequence.count(event) == 1, "Missing unique transition mark " + event)
    require(sequence.index("INTERNAL_BARRIER_REPLY") < sequence.index("VIDEO_BARRIER_REPLY")
            < sequence.index("VOICE_UPDATE_BEGIN") < sequence.index("INGRESS_BARRIER_REPLY"),
            "Voice update preceded confirmed video update")
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fixed", "adaptive"), default="adaptive")
    parser.add_argument("--scenario", choices=("A", "B"), default="A")
    args = parser.parse_args()
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
              "scope": "Functional installation/connectivity check only; no performance or energy result",
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
        low_states = copy.deepcopy(states)
        low_states["UAV1"]["energy_fraction"] = .10
        low = plan_protected(P, low_states, args.scenario) if args.mode == "adaptive" else initial
        require(all(row["admitted"] for row in low["classes"]), "Smoke check requires both protected classes admitted")
        if args.mode == "adaptive":
            require(not any("UAV1" in row["path"] for row in low["classes"]), "Weak UAV1 was not excluded")
            require(low["classes"][1]["decision"] == ("VIDEO_DOWNGRADED" if args.scenario == "A" else "VIDEO_ADMITTED_FULL"),
                    "Current scenario does not have the expected video profile")
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        directory = PROJECT_ROOT / "results/battery-enforcement-checks" / (stamp + "-" + args.scenario + "-" + args.mode + "-" + uuid.uuid4().hex[:12])
        directory.mkdir(parents=True)
        print("Results:", directory, flush=True)
        write_json(directory / "topology-before.json", baseline)
        for label, text in (("flows-before.txt", flows_before), ("meters-before.txt", meters_before), ("meter-features.txt", features)):
            (directory / label).write_text(text)
        report["source_sha256"] = {name: hashlib.sha256((PROJECT_ROOT / name).read_bytes()).hexdigest()
            for name in ("core/battery_policy.py", "core/battery_enforcement.py", "controller/battery_paths.py",
                         "sim/check_battery_enforcement.py", "config/params.py")}
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
            "--ofp-tcp-listen-port", str(P.CONTROLLER_PORT), str(PROJECT_ROOT / "controller/battery_paths.py")],
            cwd=PROJECT_ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT)
        report["stages"] = {}
        for label, energy, expected in (("initial", .90, initial), ("weak", .10, low), ("failed", .0, low)):
            if label != "initial":
                document = copy.deepcopy(document)
                document["revision"] += 1
                document["states"]["UAV1"]["energy_fraction"] = energy
                save_state(state_file, document, P.DRONES)
            applied = wait_applied(controller, directory, document, expected, args.mode, args.scenario)
            if label == "failed":
                report["link_failure_begin_monotonic_ns"] = time.monotonic_ns()
                for interface in ("uav1-eth0", "uav1-eth1"):
                    down_interfaces.append(interface)
                    docker("UAV1", ["ip", "link", "set", "dev", interface, "down"])
                links = json.loads(docker("UAV1", ["ip", "-j", "link", "show"]))
                require(all("UP" not in next(row for row in links if row["ifname"] == name)["flags"]
                            for name in down_interfaces), "UAV1 link failure was not applied")
                report["link_failure_confirmed_monotonic_ns"] = time.monotonic_ns()
            print("UAV1=%d%%; epoch=%d; VIDEO=%s" %
                  (energy * 100, applied["epoch"], expected["classes"][1]["decision"]), flush=True)
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
        print("Functional check stopped:", report["error"], flush=True)
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
            print("FUNCTIONAL ENFORCEMENT:", report["status"].upper(), flush=True)
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
