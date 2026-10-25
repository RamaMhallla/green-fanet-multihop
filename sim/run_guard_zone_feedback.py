"""One real-time 28% start / 30% guard trial, with private estimated battery state.

Both weight arms replan. Same energy parameters, joint search, admission and
barrier engine. No battery schedule, acceleration, link failure or auto-retry.
"""
import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT/"sim")]
import run_weight_comparison as R
import run_energy_feedback_trial as F
from core.energy_feedback import (BatteryLedger, MODEL, UPDATE_INTERVAL_S,
    PROTOCOL as COLLECTOR_PROTOCOL, digest, load_profile, require)
from core.guard_zone_protocol import (PROTOCOL, DEFINITION, DURATION_S,
    initial_states, initial_zone_plan, next_zone_plan)
from core.state_store import save_state
from energy_counter_support import read_snapshot

NEW_SOURCES = ("core/feedback_guard_policy.py", "core/guard_zone_protocol.py",
    "controller/guard_zone_paths.py", "sim/run_guard_zone_feedback.py", "sim/guard_zone_report.py")
SOURCES = tuple(dict.fromkeys(R.SOURCES + F.ADDED_SOURCES + NEW_SOURCES))


class GuardZoneTrial(F.FeedbackTrial):
    def __init__(self, args, profile, sha):
        super().__init__(args, profile, sha)
        self.report.update(protocol=PROTOCOL,
            scope="28% start / 30% allocation-guard energy feedback demonstration; source/QoS/energy claims separate")
        self.feedback.update(protocol=PROTOCOL, guard_definition=copy.deepcopy(DEFINITION))

    def start(self):
        # This protocol needs a different initial state and controller. Reuse
        # the original cleanup/helpers, but do not start the 90% controller and
        # relabel it or modify module globals to inject a different planner.
        require(os.geteuid() != 0, "Run normally after sudo -v, not sudo python3")
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.directory = ROOT/"results/guard-zone-feedback-trials"/(
            stamp+"-"+self.args.scenario+"-"+self.args.weights+"-"+uuid.uuid4().hex[:12])
        self.directory.mkdir(parents=True)
        print("Results:", self.directory, flush=True)
        self.report["started_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self.write()
        R.command(["sudo", "-n", "docker", "info", "--format", "{{.ServerVersion}}"])
        self.lock = (ROOT/"config/runtime_state.trial.lock").open("a")
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((R.P.CONTROLLER_IP, R.P.CONTROLLER_PORT))
        self.ryu = Path.home()/"ryuenv/bin/ryu-manager"
        require(self.ryu.is_file(), "Missing ~/ryuenv/bin/ryu-manager")
        require(R.P.UAV_BW_MBPS == 5 and R.P.UAV_DELAY_MS == 10, "Requires 5 Mbps / 10 ms UAVs")
        for name in ("u1", "gs"):
            processes = R.command(["sudo", "-n", "docker", "top", "mn."+name, "-eo", "pid,args"])
            require(not re.search(r"\b(?:iperf3|tcpdump|ping)\b", processes), "Existing endpoint traffic; stop its owning trial first")
        baseline = R.topology_snapshot()
        R.D.strict_baseline(baseline)
        self.flows = R.D.ofctl("dump-flows")
        R.D.check_idle_flows(self.flows)
        for cookie in re.findall(r"\bcookie=(0x[0-9a-fA-F]+)", self.flows):
            require(int(cookie, 16)&R.D.COOKIE_MASK != R.D.COOKIE&R.D.COOKIE_MASK,
                    "Owned cookie prefix already in use")
        self.meters = R.D.ofctl("dump-meters")
        owned_meters = set(range(R.D.METER_BASE, R.D.METER_BASE+R.D.MAX_EPOCH+1))
        require(not R.D.meter_ids(self.meters)&owned_meters, "Owned meter range already in use")
        features = R.D.ofctl("meter-features")
        require(all(x in features for x in ("drop", "kbps", "stats")), "Required meter features missing")
        R.C.write_json(self.directory/"topology-before.json", baseline)
        (self.directory/"flows-before.txt").write_text(self.flows)
        (self.directory/"meters-before.txt").write_text(self.meters)
        self.states = initial_states(R.P)
        self.previous = initial_zone_plan(R.P, self.states, self.args.scenario, self.args.weights)
        hashes = {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES}
        resources = {}
        for name in ("u1", "gs")+tuple(n.lower() for n in R.P.DRONES):
            resources[name] = R.command(["sudo", "-n", "docker", "inspect", "--format",
                "{{.Image}} cpu_quota={{.HostConfig.CpuQuota}} cpu_period={{.HostConfig.CpuPeriod}} "
                "nano_cpus={{.HostConfig.NanoCpus}} cpuset={{.HostConfig.CpusetCpus}} memory={{.HostConfig.Memory}}",
                "mn."+name]).strip()
        contract = {"protocol": PROTOCOL, "scenario": self.args.scenario, "kind": self.args.kind,
            "routing_mode": "replan", "planner": "joint", "guard_definition": copy.deepcopy(DEFINITION),
            "fixed_weights": [.56, .20, .24], "initial_states": self.states,
            "initial_assignment": [{k: row.get(k) for k in ("name", "path", "scheduler_budget_mbps", "meter_cap_mbps")}
                                   for row in self.previous["classes"]],
            "initial_assignment_rule": "Same supplied full paths/profiles; only their evaluated costs/weight tuples differ",
            "policy_config": self.previous["config"], "logical_links": self.previous["logical_links"],
            "duration_s": DURATION_S, "model": MODEL, "parameter_sha256": self.profile_sha,
            "parameter_canonical_sha256": digest(self.profile), "time_acceleration": 1.0,
            "battery_update_interval_target_s": UPDATE_INTERVAL_S, "scheduled_battery_events": False,
            "link_failure_enabled": False, "source_policy": R.C.CALIBRATION_POLICY,
            "traffic_profiles": R.C.PROFILES, "payload_bytes": 1200,
            "source_fq_options": R.C.SOURCE_FQ_OPTIONS, "socket_pacing_cap_enabled": False,
            "buffer_packet_limits": R.BUFFER_LIMITS, "exclude_source_pause_windows": False,
            "collector_protocol": COLLECTOR_PROTOCOL, "source_sha256": hashes,
            "host_logical_cpus": os.cpu_count(), "kernel_release": os.uname().release,
            "container_resource_settings": resources,
            "observation_scope": "Each UAV has its own bracketed counter interval, including preparation and tail",
            "stop_rule": "Abort on depletion or any service rejection; no silent relaxation or forced route change",
            "comparison_claim": "Single pair demonstrates estimated feedback and observed route decisions, not statistical energy/lifetime/QoS gains"}
        self.report.update(contract=contract, contract_sha256=digest(contract), source_sha256=hashes)
        self.feedback.update(comparison_contract_sha256=self.report["contract_sha256"],
                             initial_states=copy.deepcopy(self.states))
        self.write()
        self.write_feedback()
        for drone, interface in R.D.interfaces():
            self.owned.append((drone, interface))
            for argv in R.queue_commands(interface, R.P.UAV_DELAY_MS):
                R.D.docker(drone, argv)
        installed = R.D.verify_owned_queues()
        for interface, row in installed.items():
            for handle, limit in (("7e10:", 128), ("7e20:", 100), ("7e30:", 100)):
                match = re.search(r"^qdisc netem "+re.escape(handle)+r" [^\n]*\blimit (\d+)\b", row["qdiscs"], re.M)
                require(match is not None and int(match[1]) == limit, "Wrong queue limit at "+interface)
        R.C.write_json(self.directory/"queues-installed.json", installed)
        self.state_file = self.directory/"private-state.json"
        self.document = save_state(self.state_file, {"schema": 1, "revision": 0, "states": self.states}, R.P.DRONES)
        env = dict(os.environ, FANET_WEIGHT_MODE="adaptive", FANET_COST_WEIGHTS=self.args.weights,
            FANET_GUARD_ZONE_PROTOCOL=PROTOCOL, FANET_SCENARIO=self.args.scenario,
            FANET_STATE_FILE=str(self.state_file), FANET_APPLIED_FILE=str(self.directory/"applied.json"),
            FANET_SMOKE_TOKEN=uuid.uuid4().hex, PYTHONUNBUFFERED="1", LC_ALL="C")
        self.log = (self.directory/"controller.log").open("w")
        self.overlay = True
        self.controller = subprocess.Popen([str(self.ryu), "--ofp-listen-host", R.P.CONTROLLER_IP,
            "--ofp-tcp-listen-port", str(R.P.CONTROLLER_PORT), str(ROOT/"controller/guard_zone_paths.py")],
            cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        applied = self.wait(self.previous)
        self.report["stages"]["initial"] = {"confirmation_observed": R.C.clock_mark(), "applied": applied,
            "profile_check": R.D.verify_flow_profile(applied, self.directory, "initial")}
        self.write()
        print(f"GUARD ZONE: UAV1 starts at 28%; activation <=30%; weights={self.args.weights}; BOTH arms REPLAN.", flush=True)
        print("All batteries follow the unchanged reference-derived model; no scheduled jumps or accelerated clock.", flush=True)
        return applied

    def wait(self, expected):
        row = R.Trial.wait(self, expected)
        require(row["plan"].get("policy") == PROTOCOL
                and row["plan"].get("guard_definition") == DEFINITION,
                "Controller acknowledged the wrong guard protocol")
        require(digest(row["plan"]) == digest(expected), "Acknowledged complete plan differs")
        return row

    def begin_feedback(self):
        require(self.ledger is None, "Feedback already started")
        before = R.C.clock_mark()
        origin = read_snapshot(R.P.DRONES)
        self.ledger = BatteryLedger(self.document, origin, self.profile)
        self.feedback.update(status="observing", origin_read_begin=before,
                             origin_read_end=R.C.clock_mark(), origin=origin)
        self.next_read_ns = time.monotonic_ns()+int(UPDATE_INTERVAL_S*1e9)
        self.write_feedback()

    def tick(self, data=None, finished=False):
        require(self.ledger is not None, "Feedback origin missing")
        if not finished and time.monotonic_ns() < self.next_read_ns:
            return
        begin = R.C.clock_mark()
        snapshot = read_snapshot(R.P.DRONES)
        row = {"read_begin": begin, "read_end": R.C.clock_mark(), "snapshot": snapshot, "status": "estimated"}
        energy = self.ledger.advance(snapshot)
        row["energy"] = energy
        self.feedback["updates"].append(row)
        self.write_feedback()
        require(not any(p["depleted"] for p in energy["per_uav"].values()), "Estimated depletion; no unpowered-hover model")
        document = {"schema": 1, "revision": self.document["revision"]+1, "states": energy["states"]}
        expected = next_zone_plan(R.P, document["states"], self.args.scenario, self.previous, self.args.weights)
        row["expected_plan"] = expected
        if not all(c["admitted"] for c in expected["classes"]):
            row.update(status="model_stop", reason="Service rejection under declared zone guard")
            self.write_feedback()
            raise RuntimeError(row["reason"]+"; no new state published; evidence retained")
        previous_epoch = max(s["applied"]["epoch"] for s in self.report["stages"].values())
        row["publish_start"] = R.C.clock_mark()
        self.document = save_state(self.state_file, document, R.P.DRONES)
        row["publish_end"] = R.C.clock_mark()
        self.write_feedback()
        applied = self.wait(expected)
        label = "energy%03d" % self.document["revision"]
        row.update(status="acknowledged", confirmation_observed=R.C.clock_mark(),
                   revision=self.document["revision"], epoch=applied["epoch"])
        row["profile_check"] = R.D.verify_flow_profile(applied, self.directory, label)
        stage = {"publish_start": row["publish_start"], "confirmation_observed": row["confirmation_observed"],
                 "applied": applied, "profile_check": row["profile_check"]}
        self.report["stages"][label] = stage
        self.previous = expected
        if self.args.kind == "functional" and applied["epoch"] != previous_epoch:
            stage["probes_after_change"] = R.probe(applied, self.directory, label)
            require(all(p["received"] == 3 for p in stage["probes_after_change"]["probes"]), "Post-change functional probes failed")
        row["status"] = "applied"
        row["update_finished"] = R.C.clock_mark()
        self.next_read_ns = time.monotonic_ns()+int(UPDATE_INTERVAL_S*1e9)
        self.write_feedback()
        self.write()
        video = expected["classes"][1]
        print("ZONE revision=%d epoch=%d | UAV1=%.3f%% | UAV1 planned=%.2f Mbps | VIDEO %s | %s" %
              (self.document["revision"], applied["epoch"], 100*energy["states"]["UAV1"]["energy_fraction"],
               expected["forward_scheduler_allocations_mbps"]["UAV1"], video["decision"], " -> ".join(video["path"])), flush=True)


def functional(session, initial):
    session.report["functional_initial_probes"] = R.probe(initial, session.directory, "zone-initial")
    require(all(p["received"] == 3 for p in session.report["functional_initial_probes"]["probes"]), "Initial probes failed")
    session.begin_feedback()
    deadline = time.monotonic()+DURATION_S
    while time.monotonic() < deadline:
        session.alive()
        session.tick()
        time.sleep(.1)
    session.tick(finished=True)
    latest = max(session.report["stages"].values(), key=lambda s: s["applied"]["revision"])
    session.report["functional_probes"] = R.probe(latest["applied"], session.directory, "zone-final")
    require(all(p["received"] == 3 for p in session.report["functional_probes"]["probes"]), "Final probes failed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("A", "B"), required=True)
    parser.add_argument("--weights", choices=("fixed", "adaptive"), required=True)
    parser.add_argument("--kind", choices=("functional", "udp"), required=True)
    parser.add_argument("--pair", required=True)
    parser.add_argument("--parameters", type=Path, default=ROOT/"config/energy_feedback.reference.json")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", args.pair):
        parser.error("Pair label requires 1-40 letters/digits/underscores/hyphens")
    try:
        profile, sha = load_profile(args.parameters)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Zone trial stopped before network setup:", error)
        return 1
    session = GuardZoneTrial(args, profile, sha)
    try:
        applied = session.start()
        if args.kind == "functional":
            functional(session, applied)
        else:
            # Composition: same capture/source protocol, new policy protocol.
            # The raw traffic file keeps its original collector protocol ID.
            from energy_feedback_capture import collect
            collect(session)
        require(session.ledger is not None and session.ledger.updates > 0, "No feedback updates")
        session.finish_measurements()
        session.feedback["status"] = "collected"
    except (Exception, KeyboardInterrupt) as error:
        message = type(error).__name__+": "+str(error)
        session.report.update(status="failed", error=message)
        session.feedback.update(status="failed", error=message)
        print("Zone trial stopped:", message, flush=True)
    finally:
        session.close()
        session.feedback["status"] = "completed" if session.report["status"] == "completed" else "failed"
        session.write_feedback()
    if session.report["status"] != "completed":
        print("Evidence retained; cleanup:", session.report["cleanup_errors"])
        return 1
    try:
        from guard_zone_report import analyze, print_report
        report = analyze(session.directory)
        print_report(report)
        print("Saved:", session.directory/"guard-zone-report.json")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        session.report["zone_analysis_error"] = str(error)
        session.write()
        print("Zone analysis requires review:", error)
        return 1
    return 0


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Termination requested")
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
