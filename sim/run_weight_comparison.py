"""One weights-only run. --weights fixed replans; it never freezes routes.

Install once, run offline check, then functional checks before a UDP pilot.
No link failure, Windows change, automatic retry or comparison batch.
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
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT/"sim")]
from config import params as P
from core.lab_scenario import STATES
from core.state_store import save_state
from core.battery_live_support import command, topology_snapshot, stop_controller
from core.weight_comparison_policy import common_initial, plan_weight_comparison, weights_for
import run_battery_udp_diagnostic as D
from check_battery_enforcement import probe
import battery_calibration_support as C
from weight_comparison_analysis import PROTOCOL, DURATION, SCHEDULE, WINDOW, BUFFER_LIMITS, fingerprint, analyze

SOURCES = ("core/model.py", "core/lab_scenario.py", "core/state_store.py", "core/battery_policy.py",
    "core/joint_battery_policy.py", "core/weight_comparison_policy.py", "core/battery_enforcement.py",
    "core/battery_live_support.py", "controller/battery_paths.py", "controller/weight_comparison_paths.py",
    "sim/run_battery_udp_diagnostic.py", "sim/check_battery_enforcement.py", "sim/battery_diagnostic_support.py",
    "sim/battery_calibration_support.py", "sim/run_weight_comparison.py", "sim/weight_comparison_analysis.py",
    "sim/weight_comparison_capture.py", "config/params.py")


def queue_commands(interface, delay):
    rows = copy.deepcopy(D.queue_commands(interface, delay))
    changed = 0
    for row in rows:
        if "netem" in row and "7e10:" in row:
            i = row.index("limit")+1
            D.require(row[i] == "100", "Unexpected base voice leaf limit")
            row[i] = "128"
            changed += 1
    D.require(changed == 1, "Exactly one voice leaf must be configured")
    return rows


class Trial:
    def __init__(self, args):
        self.args, self.directory = args, None
        self.controller = self.log = self.lock = None
        self.owned = []
        self.overlay = False
        self.report = {"schema": 1, "protocol": PROTOCOL, "status": "starting", "kind": args.kind,
            "weights": args.weights, "routing_mode": "replan", "pair": args.pair, "scenario": args.scenario,
            "stages": {}, "cleanup_errors": [], "link_failure_enabled": False,
            "scope": "Weights-only joint+guard experiment; source acceptance separate; no QoS/energy claim"}

    def write(self):
        if self.directory is not None:
            C.write_json(self.directory/"manifest.json", self.report)

    def start(self):
        D.require(os.geteuid() != 0, "Run normally after sudo -v, not using sudo python3")
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.directory = ROOT/"results/weight-comparison-trials"/(
            stamp+"-"+self.args.scenario+"-"+self.args.weights+"-"+uuid.uuid4().hex[:12])
        self.directory.mkdir(parents=True)
        print("Results:", self.directory, flush=True)
        self.report["started_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self.write()
        command(["sudo", "-n", "docker", "info", "--format", "{{.ServerVersion}}"])
        self.lock = (ROOT/"config/runtime_state.trial.lock").open("a")
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((P.CONTROLLER_IP, P.CONTROLLER_PORT))
        self.ryu = Path.home()/"ryuenv/bin/ryu-manager"
        D.require(self.ryu.is_file(), "Missing ~/ryuenv/bin/ryu-manager")
        D.require(P.UAV_BW_MBPS == 5 and P.UAV_DELAY_MS == 10, "Protocol requires 5 Mbps / 10 ms UAVs")
        for name in ("u1", "gs"):
            ps = command(["sudo", "-n", "docker", "top", "mn."+name, "-eo", "pid,args"])
            D.require(not re.search(r"\b(?:iperf3|tcpdump|ping)\b", ps), "Existing endpoint traffic; stop its owning trial first")
        baseline = topology_snapshot()
        D.strict_baseline(baseline)
        self.flows = D.ofctl("dump-flows")
        D.check_idle_flows(self.flows)
        for cookie in re.findall(r"\bcookie=(0x[0-9a-fA-F]+)", self.flows):
            D.require(int(cookie, 16)&D.COOKIE_MASK != D.COOKIE&D.COOKIE_MASK, "Owned cookie prefix already in use")
        self.meters = D.ofctl("dump-meters")
        D.require(not D.meter_ids(self.meters)&set(range(D.METER_BASE, D.METER_BASE+D.MAX_EPOCH+1)), "Owned meter range already in use")
        features = D.ofctl("meter-features")
        D.require(all(s in features for s in ("drop", "kbps", "stats")), "Meter features unavailable")
        C.write_json(self.directory/"topology-before.json", baseline)
        (self.directory/"flows-before.txt").write_text(self.flows)
        (self.directory/"meters-before.txt").write_text(self.meters)
        self.states = copy.deepcopy(STATES)
        self.states["UAV1"]["energy_fraction"] = .90
        self.previous = common_initial(P, self.states, self.args.scenario)
        D.require(all(r["decision"] in ("VOICE_ADMITTED", "VIDEO_ADMITTED_FULL") for r in self.previous["classes"]), "Initial profiles differ")
        source_hashes = {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES}
        resource_settings = {}
        for name in ("u1", "gs")+tuple(n.lower() for n in P.DRONES):
            resource_settings[name] = command(["sudo", "-n", "docker", "inspect", "--format",
                "{{.Image}} cpu_quota={{.HostConfig.CpuQuota}} cpu_period={{.HostConfig.CpuPeriod}} "
                "nano_cpus={{.HostConfig.NanoCpus}} cpuset={{.HostConfig.CpusetCpus}} memory={{.HostConfig.Memory}}",
                "mn."+name]).strip()
        contract = {"protocol": PROTOCOL, "scenario": self.args.scenario, "kind": self.args.kind,
            "planner": "joint", "guard_enabled": True, "fixed_weights": [.56,.20,.24],
            "initial_states": self.states, "initial_assignment": [{k: r.get(k) for k in
                ("name", "path", "scheduler_budget_mbps", "meter_cap_mbps")} for r in self.previous["classes"]],
            "policy_config": self.previous["config"], "logical_links": self.previous["logical_links"],
            "duration_s": DURATION, "schedule_after_both_ready": SCHEDULE, "analysis_window_s": WINDOW,
            "primary_analysis_phase": "battery25", "exclude_source_pause_windows": False,
            "source_policy": C.CALIBRATION_POLICY, "traffic_profiles": C.PROFILES, "payload_bytes": 1200,
            "source_fq_options": C.SOURCE_FQ_OPTIONS, "socket_pacing_cap_enabled": False,
            "buffer_packet_limits": BUFFER_LIMITS, "source_sha256": source_hashes,
            "host_logical_cpus": os.cpu_count(), "kernel_release": os.uname().release,
            "container_resource_settings": resource_settings,
            "comparison_claim": "Shared initial assignment; total subsequent effect of weight choice with the SAME guard rule"}
        self.report.update(contract=contract, contract_sha256=fingerprint(contract), source_sha256=source_hashes)
        self.write()
        for drone, interface in D.interfaces():
            self.owned.append((drone, interface))
            for command_row in queue_commands(interface, P.UAV_DELAY_MS):
                D.docker(drone, command_row)
        verified = D.verify_owned_queues()
        for interface, row in verified.items():
            for handle, limit in (("7e10:",128),("7e20:",100),("7e30:",100)):
                match = re.search(r"^qdisc netem "+re.escape(handle)+r" [^\n]*\blimit (\d+)\b", row["qdiscs"], re.M)
                D.require(match is not None and int(match[1]) == limit, "Unexpected leaf limit at "+interface)
        C.write_json(self.directory/"queues-installed.json", verified)
        self.state_file = self.directory/"private-state.json"
        self.document = save_state(self.state_file, {"schema": 1,"revision":0,"states":self.states}, P.DRONES)
        env = dict(os.environ, FANET_WEIGHT_MODE="adaptive", FANET_COST_WEIGHTS=self.args.weights,
            FANET_SCENARIO=self.args.scenario, FANET_STATE_FILE=str(self.state_file),
            FANET_APPLIED_FILE=str(self.directory/"applied.json"), FANET_SMOKE_TOKEN=uuid.uuid4().hex,
            PYTHONUNBUFFERED="1", LC_ALL="C")
        self.log = (self.directory/"controller.log").open("w")
        self.overlay = True
        self.controller = subprocess.Popen([str(self.ryu), "--ofp-listen-host", P.CONTROLLER_IP,
            "--ofp-tcp-listen-port", str(P.CONTROLLER_PORT), str(ROOT/"controller/weight_comparison_paths.py")],
            cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        applied = self.wait(self.previous)
        self.report["stages"]["initial"] = {"confirmation_observed": C.clock_mark(), "applied": applied,
            "profile_check": D.verify_flow_profile(applied, self.directory, "initial"),
            "uav1_counters": self.uav1_counters()}
        self.write()
        print("REPLANNING with %s weights, scenario %s. Same joint+guard and VOICE buffer 128." %
              (self.args.weights.upper(), self.args.scenario), flush=True)
        return applied

    def alive(self):
        D.require(self.controller is not None and self.controller.poll() is None, "Controller exited; inspect controller.log")

    def wait(self, expected):
        row = D.wait_applied(self.controller, self.directory, self.document, expected, "adaptive", self.args.scenario)
        D.require(row["plan"].get("weight_mode") == self.args.weights, "Wrong acknowledged weight arm")
        D.require(row["plan"]["states"] == expected["states"], "Acknowledged states differ")
        D.require(row["plan"].get("discharge_caps_mbps") == expected.get("discharge_caps_mbps"), "Guard history differs")
        if self.document["revision"]:
            expected_weights = weights_for(expected["states"], self.args.weights)
            D.require(all(tuple(row["plan"]["relay_weights"][n]) == tuple(w) for n,w in expected_weights.items()),
                      "Acknowledged numerical weights differ")
        return row

    def uav1_counters(self):
        before = C.clock_mark()
        text = D.docker("UAV1", ["tc","-s","class","show","dev","uav1-eth1"])
        counters = {minor: {"bytes": int(b), "packets": int(p)} for minor,b,p in
            re.findall(r"^class htb 7e00:(\w+)[^\n]*\n\s*Sent (\d+) bytes (\d+) pkt", text, re.M)}
        D.require(all(n in counters for n in ("10","20","30")), "Missing UAV1 class counters")
        return {"begin": before, "end": C.clock_mark(), "interface":"uav1-eth1", "classes":counters,
            "scope":"tc class bytes, not payload bytes or energy; sequential observed snapshot"}

    def publish(self, label, energy, scheduled=None, elapsed=None):
        stage = {"publish_start": C.clock_mark(), "scheduled_after_ready_s": scheduled,
                 "observed_publish_lateness_s": None if scheduled is None else elapsed-scheduled}
        self.document = copy.deepcopy(self.document)
        self.document["revision"] += 1
        self.document["states"]["UAV1"]["energy_fraction"] = energy
        save_state(self.state_file, self.document, P.DRONES)
        stage["publish_end"] = C.clock_mark()
        expected = plan_weight_comparison(P, self.document["states"], self.args.scenario, self.previous, self.args.weights)
        D.require(not expected["blocked_relays"], "Weights-only live schedule unexpectedly triggers exclusion")
        applied = self.wait(expected)
        stage.update(confirmation_observed=C.clock_mark(), applied=applied,
            profile_check=D.verify_flow_profile(applied, self.directory, label), uav1_counters=self.uav1_counters())
        self.previous = expected
        self.report["stages"][label] = stage
        self.write()
        print("UAV1=%g%%; weights=%s; epoch=%d; UAV1 planned=%.2f Mbps; VIDEO=%s" %
            (100*energy, self.args.weights, applied["epoch"], expected["forward_scheduler_allocations_mbps"]["UAV1"],
             expected["classes"][1]["decision"]), flush=True)
        return applied

    def tick(self, data, finished):
        now = C.clock_mark()
        elapsed = (now["monotonic_ns"]-data["timing_marks"]["both_streams_observed"]["monotonic_ns"])/1e9
        for label, offset, energy in SCHEDULE:
            if label not in self.report["stages"] and elapsed>=offset:
                D.require(not finished, "Clients ended before the full schedule; keep failed evidence")
                self.publish(label, energy, offset, elapsed)
                elapsed = (C.clock_mark()["monotonic_ns"]-data["timing_marks"]["both_streams_observed"]["monotonic_ns"])/1e9
        if finished:
            D.require(all(label in self.report["stages"] for label,_,_ in SCHEDULE), "Incomplete schedule")

    def finish_measurements(self):
        self.report["final_uav1_counters"] = self.uav1_counters()
        self.report["video_meter_totals"] = {}
        for epoch in sorted({s["applied"]["epoch"] for s in self.report["stages"].values()}):
            text = D.ofctl("meter-stats", "meter="+str(D.meter_id(epoch)))
            (self.directory/("video-meter-epoch-%d-final.txt" % epoch)).write_text(text)
            self.report["video_meter_totals"][str(epoch)] = C.meter_counts(text)
        log = (self.directory/"controller.log").read_text()
        self.report["transition_events"] = {str(epoch): D.verify_transition(log,epoch)
            for epoch in sorted({s["applied"]["epoch"] for s in self.report["stages"].values()})}
        self.report["status"] = "completed"

    def close(self):
        def clean(label, action):
            try:
                action()
            except Exception as error:
                self.report["cleanup_errors"].append(label+": "+str(error))
        clean("owned Ryu", lambda: stop_controller(self.controller))
        if self.log is not None:
            self.log.close()
        if self.overlay:
            clean("owned flows", lambda: D.ofctl("del-flows", "cookie=0x%x/0x%x" % (D.COOKIE,D.COOKIE_MASK)))
            def remove_meters():
                for mid in sorted(D.meter_ids(D.ofctl("dump-meters"))&set(range(D.METER_BASE,D.METER_BASE+D.MAX_EPOCH+1))):
                    D.ofctl("del-meters", "meter="+str(mid))
            clean("owned meters", remove_meters)
        for drone, interface in reversed(self.owned):
            def restore(drone=drone, interface=interface):
                text = D.docker(drone,["tc","qdisc","show","dev",interface])
                if re.search(r"^qdisc htb 1: root\b",text,re.M):
                    return
                D.require(re.search(r"^qdisc htb 7e00: root\b",text,re.M), "Owned queue changed externally; refusing overwrite")
                for command_row in D.restore_commands(interface,P.UAV_DELAY_MS):
                    D.docker(drone,command_row)
            clean("queue "+interface,restore)
        if self.owned or self.overlay:
            def verify():
                C.write_json(self.directory/"topology-restored.json",topology_snapshot())
                D.require(D.flow_configuration(D.ofctl("dump-flows")) == D.flow_configuration(self.flows), "Flow configuration not restored")
                D.require(D.meter_configuration(D.ofctl("dump-meters")) == D.meter_configuration(self.meters), "Meter configuration not restored")
            clean("verify restoration",verify)
        if self.lock is not None:
            self.lock.close()
        if self.report["cleanup_errors"]:
            self.report["status"] = "cleanup_failed"
        self.report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self.write()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("A","B"), required=True)
    parser.add_argument("--weights", choices=("fixed","adaptive"), required=True)
    parser.add_argument("--kind", choices=("functional","udp"), required=True)
    parser.add_argument("--pair", required=True, help="Same label for the two matched arms, e.g. pilot01")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}",args.pair):
        parser.error("Pair label must contain 1-40 letters, digits, underscores or hyphens")
    session = Trial(args)
    try:
        initial = session.start()
        if args.kind == "functional":
            for label,energy in [("initial",.90)]+[(a,c) for a,_,c in SCHEDULE]:
                applied = initial if label == "initial" else session.publish(label,energy)
                observation = probe(applied,session.directory,label)
                D.require(all(p["received"] == 3 for p in observation["probes"]), "Functional check requires 3/3 for both classes")
        else:
            from weight_comparison_capture import collect
            collect(session)
        session.finish_measurements()
    except (Exception,KeyboardInterrupt) as error:
        session.report.update(status="failed",error=type(error).__name__+": "+str(error))
        print("Comparison stopped:",session.report["error"],flush=True)
    finally:
        session.close()
    if session.report["status"] != "completed":
        print("Evidence retained; status:",session.report["status"],"cleanup:",session.report["cleanup_errors"])
        return 1
    if args.kind == "udp":
        try:
            result = analyze(session.directory)
            session.report["source_verdict"] = result["source_verdict"]
            session.write()
        except (OSError,ValueError,RuntimeError,KeyError,TypeError) as error:
            session.report["analysis_error"] = str(error)
            session.write()
            print("Analysis requires review:",error)
            return 1
    print("COMPLETED:",args.kind,"| REPLAN +",args.weights,"weights | original runtime state untouched")
    print("Collection/functional success is separate from QoS, source acceptance and energy.")
    return 0


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Termination requested")
    signal.signal(signal.SIGTERM,interrupted)
    sys.exit(main())
