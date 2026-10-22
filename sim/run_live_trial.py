"""Repeatable live ping trial; run as your normal Ubuntu user, not with sudo.

Owns one Ryu process; the topology runs separately in another terminal.
Manual two-point synthetic battery experiment, not an energy-drain model.
Only DSCP-46 ICMP is generated. VOICE/VIDEO admission still plans both classes.
Run fixed and adaptive separately with the same options and topology.
Measurement waits for both the OpenFlow acknowledgement and the container
data plane: tc shaping/wires on BOTH interfaces, plus endpoint IP/static ARP.
"""

import argparse
import datetime as dt
import hashlib
import json
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import params as P
from core.lab_scenario import EXPERIMENT_FIXED_WEIGHTS, STATES, plan_forward
from core.state_store import load_state, save_state


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def command(arguments, timeout=10):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Command failed: %s\n%s" %
                           (" ".join(arguments), result.stderr.strip()))
    return result.stdout


def capture(directory, name, arguments):
    output = command(arguments)
    (directory / name).write_text(output, encoding="utf-8")
    return output


def read_log(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def acknowledged(log, document, mode, plan):
    """Require this revision's state line AND its subsequent route records.

    A 'PREPARE' or 'FLIP' line alone does not confirm switch completion.
    LivePaths emits STATE after the ingress barrier, or after an unchanged plan.
    """
    pattern = r"^STATE revision=%d UAV1=[^\n]* mode=%s epoch=(\d+)\s*$" % (
        document["revision"], mode.upper())
    matches = list(re.finditer(pattern, log, flags=re.MULTILINE))
    if not matches:
        return None
    match = matches[-1]
    tail = log[match.end():]
    next_state = re.search(r"^STATE revision=", tail, flags=re.MULTILINE)
    if next_state:
        tail = tail[:next_state.start()]
    for record in plan["classes"]:
        if not record["admitted"]:
            expected = r"^%s REJECTED:" % re.escape(record["name"])
        else:
            expected = (r"^%s DSCP=%d VLAN=\d+ cost=[^\n]+ path=%s\s*$" %
                        (re.escape(record["name"]), record["dscp"],
                         re.escape(" -> ".join(record["path"]))))
        if not re.search(expected, tail, flags=re.MULTILINE):
            return None
    return int(match.group(1))


def ping_summary(text):
    counts = re.search(r"(\d+) packets transmitted,\s*(\d+) received,.*?"
                       r"([\d.]+)% packet loss", text)
    if not counts:
        raise RuntimeError("Ping did not produce a complete summary; inspect ping.log")
    value = {"transmitted": int(counts[1]), "received": int(counts[2]),
             "loss_percent": float(counts[3])}
    rtt = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", text)
    if rtt:
        value["rtt_ms"] = dict(zip(("min", "mean", "max", "mdev"),
                                    map(float, rtt.groups())))
    return value


def ensure_state(expected, state_path):
    if load_state(state_path, P.DRONES) != expected:
        raise RuntimeError("State changed outside this trial; do not run set_energy.py concurrently")


def wait_ready(process, log_path, document, mode, plan, state_path, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Ryu exited; inspect controller.log")
        ensure_state(document, state_path)
        log = read_log(log_path)
        if "automatic updates halted" in log or "VLAN labels exhausted" in log:
            raise RuntimeError("Controller halted; inspect controller.log")
        epoch = acknowledged(log, document, mode, plan)
        if epoch is not None:
            return epoch
        time.sleep(0.1)
    raise RuntimeError("Controller did not confirm revision %s within %.0fs; inspect controller.log" %
                       (document["revision"], timeout))


def stop_controller(process):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def quantity(token, kind):
    """Decode iproute2's displayed time/rate, e.g. 10000us or 5Mbit."""
    if kind == "delay":
        match = re.fullmatch(r"([0-9.]+)(ns|us|ms|s)", token)
        factors = {"ns": 1e-6, "us": 1e-3, "ms": 1, "s": 1000}
    else:
        match = re.fullmatch(r"([0-9.]+)(bit|Kbit|Mbit|Gbit)", token)
        factors = {"bit": 1e-6, "Kbit": 1e-3, "Mbit": 1, "Gbit": 1000}
    if match is None:
        raise ValueError("Unrecognized tc %s value: %r" % (kind, token))
    return float(match[1]) * factors[match[2]]


def validate_tc(interface, destination, qdiscs, classes, filters):
    """Require our topology's installed queues and tc-wire action, read-only."""
    if not re.search(r"^qdisc htb 1: root\b[^\n]*\bdefault (?:0x)?10\b", qdiscs, re.M):
        raise ValueError("%s: HTB root/default class is not ready" % interface)
    netem = re.search(r"^qdisc netem 10: parent 1:10\b([^\n]*)", qdiscs, re.M)
    if netem is None:
        raise ValueError("%s: netem is not ready" % interface)
    delay = re.search(r"\bdelay (\S+)", netem[1])
    # tc omits the delay field for a configured zero delay.
    measured = quantity(delay[1], "delay") if delay else 0.0
    if not math.isclose(measured, float(P.UAV_DELAY_MS), rel_tol=1e-5, abs_tol=1e-5):
        raise ValueError("%s: netem delay does not match config" % interface)
    limit = re.search(r"\blimit (\d+)\b", netem[1])
    if limit is None or int(limit[1]) != 100:
        raise ValueError("%s: expected netem limit 100" % interface)
    selected = re.search(r"^class htb 1:10\b([^\n]*)", classes, re.M)
    if selected is None:
        raise ValueError("%s: HTB class is not ready" % interface)
    for name in ("rate", "ceil"):
        value = re.search(r"\b%s (\S+)" % name, selected[1])
        if value is None or not math.isclose(quantity(value[1], "rate"),
                                            float(P.UAV_BW_MBPS), rel_tol=1e-5):
            raise ValueError("%s: HTB %s does not match config" % (interface, name))
    if ("matchall" not in filters
            or not re.search(r"mirred \(Egress Redirect to device %s\)" %
                             re.escape(destination), filters)):
        raise ValueError("%s: ingress tc wire to %s is not ready" %
                         (interface, destination))


def topology_snapshot():
    """Read actual container settings, independently of Ryu's barrier."""
    evidence = {"uavs": {}, "endpoints": {}}
    for drone in P.DRONES:
        container = "mn." + drone.lower()
        prefix = ["sudo", "-n", "docker", "exec", container]
        addresses = json.loads(command(prefix + ["ip", "-j", "address", "show"], timeout=5))
        by_name = {entry["ifname"]: entry for entry in addresses}
        interfaces = {}
        for index in (0, 1):
            interface = drone.lower() + "-eth" + str(index)
            other = drone.lower() + "-eth" + str(1 - index)
            link = by_name.get(interface, {})
            if "UP" not in link.get("flags", []):
                raise ValueError("%s is not up" % interface)
            if any(addr.get("family") == "inet" for addr in link.get("addr_info", [])):
                raise ValueError("%s still has an IPv4 address" % interface)
            qdiscs = command(prefix + ["tc", "-s", "qdisc", "show", "dev", interface], timeout=5)
            classes = command(prefix + ["tc", "-s", "class", "show", "dev", interface], timeout=5)
            filters = command(prefix + ["tc", "-s", "filter", "show", "dev", interface, "ingress"], timeout=5)
            validate_tc(interface, other, qdiscs, classes, filters)
            interfaces[interface] = {"address": link, "qdiscs": qdiscs,
                                     "classes": classes, "ingress_filters": filters}
        evidence["uavs"][drone] = interfaces
    for host, peer in (("u1", "gs"), ("gs", "u1")):
        prefix = ["sudo", "-n", "docker", "exec", "mn." + host]
        addresses = json.loads(command(prefix + ["ip", "-j", "address", "show"], timeout=5))
        ip, mac = P.HOSTS[host]
        local_ip, prefix_length = ip.split("/")
        link = next((entry for entry in addresses if any(
            addr.get("family") == "inet" and addr.get("local") == local_ip
            and addr.get("prefixlen") == int(prefix_length)
            for addr in entry.get("addr_info", []))), None)
        if (link is None or "UP" not in link.get("flags", [])
                or link.get("address", "").lower() != mac.lower()):
            raise ValueError("%s: endpoint address/link is not ready" % host)
        neighbours = json.loads(command(prefix + ["ip", "-j", "neigh", "show"], timeout=5))
        peer_ip, peer_mac = P.HOSTS[peer]
        if not any(entry.get("dst") == peer_ip.split("/")[0]
                   and entry.get("lladdr", "").lower() == peer_mac.lower()
                   and entry.get("dev") == link["ifname"]
                   and "PERMANENT" in entry.get("state", []) for entry in neighbours):
            raise ValueError("%s: permanent neighbour for %s is not ready" % (host, peer))
        evidence["endpoints"][host] = {"address": link, "neighbours": neighbours}
    return evidence


def wait_topology(process, document, state_path, directory, timeout):
    deadline = time.monotonic() + timeout
    reason = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Ryu exited while waiting for topology configuration")
        ensure_state(document, state_path)
        try:
            evidence = topology_snapshot()
        except (ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            current_reason = str(error)
            if current_reason != reason:
                print("Topology not ready yet: " + current_reason.splitlines()[0], flush=True)
                reason = current_reason
            write_json(directory / "readiness-pending.json", {"last_reason": current_reason})
            time.sleep(0.5)
            continue
        ensure_state(document, state_path)
        write_json(directory / "topology-ready.json", evidence)
        print("Topology ready: both UAV interfaces shaped/wired; endpoint IP/static ARP verified.", flush=True)
        return
    raise RuntimeError("Topology configuration was not ready within %.0fs: %s" % (timeout, reason))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fixed", "adaptive"), required=True)
    parser.add_argument("--count", type=int, default=200, help="Ping requests (default 200)")
    parser.add_argument("--interval", type=float, default=0.2, help="Seconds between pings")
    parser.add_argument("--change-after", type=float, default=15.0,
                        help="Seconds after local Docker-exec launch (default 15)")
    parser.add_argument("--ready-timeout", type=float, default=120.0,
                        help="Seconds allowed to start the separate topology")
    parser.add_argument("--topology-timeout", type=float, default=60.0,
                        help="Seconds allowed for tc wires/queues and endpoint setup")
    args = parser.parse_args()
    if (args.count < 2 or not all(math.isfinite(x) and x > 0 for x in
                                (args.interval, args.change_after, args.ready_timeout,
                                 args.topology_timeout))
            or args.interval < 0.2
            or args.change_after >= (args.count - 1) * args.interval - 5):
        parser.error("Use interval >= 0.2s and leave at least 5s of pings after the event")
    if os.geteuid() == 0:
        parser.error("Run python3 normally. Use sudo -v first, not sudo python3")

    ryu = Path.home() / "ryuenv" / "bin" / "ryu-manager"
    state_path = PROJECT_ROOT / "config" / "runtime_state.json"
    controller_path = PROJECT_ROOT / "controller" / "live_paths.py"
    for required in (ryu, controller_path, state_path):
        if not required.is_file():
            parser.error("Missing file: %s" % required)
    if set(P.DRONES) != {"UAV1", "UAV2", "UAV3", "UAV4"}:
        parser.error("This first experiment expects the current four-UAV topology")
    if set(STATES) != set(P.DRONES):
        parser.error("Scenario does not match configured UAVs")

    # Stop before state changes if sudo credentials, Docker or the port fail.
    try:
        docker_version = command(["sudo", "-n", "docker", "info", "--format", "{{.ServerVersion}}"])
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((P.CONTROLLER_IP, P.CONTROLLER_PORT))
        original = load_state(state_path, P.DRONES)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(2, "Preflight failed: %s\nUse sudo -v first; stop any controller on port 6653.\n" % error)

    # Unique directory: no earlier trial is overwritten, including failed runs.
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = PROJECT_ROOT / "results" / "trials" / (stamp + "-" + args.mode + "-" + uuid.uuid4().hex[:8])
    directory.mkdir(parents=True, exist_ok=False)
    state_lock = open(state_path.with_suffix(".trial.lock"), "a", encoding="utf-8")
    import fcntl
    try:
        fcntl.flock(state_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        state_lock.close()
        parser.exit(2, "Another automated trial is already using the state file\n")

    manifest = {"schema": 1, "status": "starting", "mode": args.mode,
                "trial_protocol": "v2-container-readiness-gate",
                "started_utc": stamp, "options": vars(args),
                "docker_version": docker_version.strip(), "python": sys.version,
                "scope": "DSCP-46 ping only; synthetic two-point state; no real battery drain",
                "clock_origin": "local Docker-exec launch; actual event offset recorded",
                "fixed_weights": EXPERIMENT_FIXED_WEIGHTS, "source_sha256": {}}
    for relative in ("controller/live_paths.py", "core/model.py", "core/lab_scenario.py",
                     "core/state_store.py", "config/params.py", "topology/fanet_topo.py",
                     "sim/run_live_trial.py"):
        source = PROJECT_ROOT / relative
        if source.exists():
            manifest["source_sha256"][relative] = hashlib.sha256(source.read_bytes()).hexdigest()
    write_json(directory / "state-before-trial.json", original)
    write_json(directory / "manifest.json", manifest)
    controller = ping = None
    controller_handle = ping_handle = None
    current = None
    succeeded = False
    try:
        ensure_state(original, state_path)
        initial = {"schema": 1, "revision": original["revision"] + 1,
                   "states": {name: dict(STATES[name]) for name in P.DRONES}}
        initial["states"]["UAV1"]["energy_fraction"] = 0.90
        current = save_state(state_path, initial, P.DRONES)
        write_json(directory / "state-initial.json", current)
        initial_plan = plan_forward(P, states=current["states"], weight_mode=args.mode,
                                    fixed_weights=EXPERIMENT_FIXED_WEIGHTS)
        write_json(directory / "plan-initial.json", initial_plan)

        env = dict(os.environ, FANET_WEIGHT_MODE=args.mode, FANET_STATE_FILE=str(state_path),
                   PYTHONUNBUFFERED="1", LC_ALL="C")
        controller_handle = (directory / "controller.log").open("w", encoding="utf-8")
        controller = subprocess.Popen(
            [str(ryu), "--ofp-listen-host", P.CONTROLLER_IP,
             "--ofp-tcp-listen-port", str(P.CONTROLLER_PORT), str(controller_path)],
            cwd=str(PROJECT_ROOT), env=env, stdout=controller_handle, stderr=subprocess.STDOUT)
        print("Results:", directory, flush=True)
        print("Ryu started in %s mode. Start the topology in the OTHER terminal now." %
              args.mode.upper(), flush=True)
        print("Waiting for switch and confirmed initial paths (up to %.0fs)..." %
              args.ready_timeout, flush=True)
        epoch_before = wait_ready(controller, directory / "controller.log", current,
                                 args.mode, initial_plan, state_path, args.ready_timeout)
        containers = ["mn.u1", "mn.gs"] + ["mn." + d.lower() for d in P.DRONES]
        running = command(["sudo", "-n", "docker", "inspect", "--format", "{{.State.Running}}"] + containers)
        if running.split() != ["true"] * len(containers):
            raise RuntimeError("Expected topology containers are not all running")
        print("Ryu rules confirmed. Verifying actual container data-plane setup...", flush=True)
        wait_topology(controller, current, state_path, directory, args.topology_timeout)
        # Recheck controller health/ack after waiting for container configuration.
        wait_ready(controller, directory / "controller.log", current,
                   args.mode, initial_plan, state_path, 5)
        manifest["topology_ready_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        destination = P.HOSTS["gs"][0].split("/")[0]
        ovs = ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", P.SWITCH_NAME]
        capture(directory, "flows-before.txt", ovs)
        capture(directory, "ports.txt", ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "show", P.SWITCH_NAME])
        for drone in P.DRONES:
            capture(directory, "queue-before-%s.txt" % drone,
                    ["sudo", "-n", "docker", "exec", "mn." + drone.lower(),
                     "tc", "-s", "qdisc", "show", "dev", drone.lower() + "-eth1"])

        total_bound = math.ceil(args.count * args.interval + 15)
        # timeout bounds the container process even if this Python process dies.
        # Print the timeout PID before exec so Ctrl+C cleanup can target OUR job.
        ping_args = ["sudo", "-n", "docker", "exec", "-e", "LC_ALL=C", "mn.u1",
                     "sh", "-c", 'echo FANET_JOB_PID=$$; exec "$@"', "fanet-trial",
                     "timeout", "-s", "INT", "-k", "3", str(total_bound),
                     "ping", "-n", "-D", "-i", str(args.interval), "-c", str(args.count),
                     "-W", "2", "-Q", "184", destination]
        manifest["ping_command"] = ping_args
        ping_handle = (directory / "ping.log").open("w", encoding="utf-8")
        start = time.monotonic()
        ping = subprocess.Popen(ping_args, stdout=ping_handle, stderr=subprocess.STDOUT)
        print("Ping running. Battery event scheduled at +%.1fs." % args.change_after, flush=True)
        while time.monotonic() - start < args.change_after:
            if controller.poll() is not None or ping.poll() is not None:
                raise RuntimeError("Controller or ping stopped before the battery event")
            ensure_state(current, state_path)
            time.sleep(0.05)
        if not re.search(r"\bicmp_seq=\d+\b", read_log(directory / "ping.log")):
            raise RuntimeError("No successful ping before event; check connectivity")
        event = {"schema": 1, "revision": current["revision"] + 1,
                 "states": {name: dict(value) for name, value in current["states"].items()}}
        event["states"]["UAV1"]["energy_fraction"] = 0.10
        ensure_state(current, state_path)
        publish_start = time.monotonic()
        current = save_state(state_path, event, P.DRONES)
        manifest["event_publish_start_offset_s"] = publish_start - start
        manifest["event_publish_end_offset_s"] = time.monotonic() - start
        write_json(directory / "state-event.json", current)
        event_plan = plan_forward(P, states=current["states"], weight_mode=args.mode,
                                  fixed_weights=EXPERIMENT_FIXED_WEIGHTS)
        write_json(directory / "plan-event.json", event_plan)
        print("UAV1 set to 10%%, revision %s. Waiting for controller confirmation..." %
              current["revision"], flush=True)
        epoch_after = wait_ready(controller, directory / "controller.log", current,
                                args.mode, event_plan, state_path, 15)
        manifest["confirmation_observed_offset_s"] = time.monotonic() - start
        manifest["epochs"] = {"before": epoch_before, "after": epoch_after}
        capture(directory, "flows-after-event.txt", ovs)
        while ping.poll() is None:
            if time.monotonic() - start > total_bound + 10:
                raise RuntimeError("Ping did not finish within its time limit")
            if controller.poll() is not None:
                raise RuntimeError("Controller exited during the experiment")
            ensure_state(current, state_path)
            time.sleep(0.1)
        ping_handle.flush()
        manifest["ping_returncode"] = ping.returncode
        summary = ping_summary(read_log(directory / "ping.log"))
        if ping.returncode not in (0, 1) or summary["transmitted"] != args.count:
            raise RuntimeError("Incomplete ping run; retained as failed, not discarded")
        manifest["ping"] = summary
        capture(directory, "flows-final.txt", ovs)
        for drone in P.DRONES:
            capture(directory, "queue-final-%s.txt" % drone,
                    ["sudo", "-n", "docker", "exec", "mn." + drone.lower(),
                     "tc", "-s", "qdisc", "show", "dev", drone.lower() + "-eth1"])
        ensure_state(current, state_path)
        succeeded = True
        manifest["status"] = "completed"
        print("Completed: %s/%s replies, loss %.2f%%." %
              (summary["received"], summary["transmitted"], summary["loss_percent"]), flush=True)
        print("Epoch %s -> %s. This tests route response, not energy savings." %
              (epoch_before, epoch_after), flush=True)
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
        manifest["error"] = "Interrupted by user"
        print("Interrupted; partial evidence retained.", file=sys.stderr)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        print("Trial failed: %s\nEvidence retained in %s" % (error, directory), file=sys.stderr)
    finally:
        if ping is not None and ping.poll() is None:
            job = re.search(r"^FANET_JOB_PID=(\d+)$", read_log(directory / "ping.log"), re.MULTILINE)
            if job:
                try:
                    command(["sudo", "-n", "docker", "exec", "mn.u1", "sh", "-c",
                             'kill -INT "$1"', "fanet-cleanup", job[1]], timeout=5)
                    ping.wait(timeout=5)
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    pass  # Remote timeout remains the final bound.
            if ping.poll() is None:
                ping.terminate()
                try:
                    ping.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    ping.kill()
                    ping.wait(timeout=3)
        stop_controller(controller)
        if ping_handle is not None:
            ping_handle.close()
        if controller_handle is not None:
            controller_handle.close()
        manifest["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        write_json(directory / "manifest.json", manifest)
        state_lock.close()
        print("Ryu stopped. Topology remains running; state is not restored.", flush=True)
    return 0 if succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
