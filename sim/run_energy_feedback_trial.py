"""One bounded, real-time feedback trial; both weight modes REPLAN.

Uses the existing owned Ryu/queue lifecycle. No scheduled battery jumps, link
failure, time acceleration, retry batch, external state writer or auto-landing.
The first integration protocol starts at the existing common 90% assignment.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import signal
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "sim")]
from core.energy_feedback import (PROTOCOL, MODEL, UPDATE_INTERVAL_S, DURATION_S,
                                 BatteryLedger, digest, load_profile, require)
from core.state_store import save_state
from core.weight_comparison_policy import plan_weight_comparison
import run_weight_comparison as R
from energy_counter_support import read_snapshot

ADDED_SOURCES = ("core/energy_feedback.py", "core/uav_energy_model.py",
    "sim/energy_counter_support.py", "sim/run_energy_feedback_trial.py",
    "sim/energy_feedback_capture.py", "sim/energy_feedback_report.py")


class FeedbackTrial(R.Trial):
    def __init__(self, args, profile, profile_sha):
        super().__init__(args)
        self.profile, self.profile_sha = profile, profile_sha
        self.ledger = None
        self.next_read_ns = None
        self.feedback = {"schema": 1, "protocol": PROTOCOL, "status": "starting",
            "parameter_sha256": profile_sha, "parameters": copy.deepcopy(profile),
            "update_interval_target_s": UPDATE_INTERVAL_S, "updates": [],
            "time_acceleration": 1.0, "scheduled_battery_events": False,
            "scope": "Estimated battery feedback from virtual-interface workload. No physical energy, lifetime or QoS guarantee."}
        self.report.update(protocol=PROTOCOL, scope=self.feedback["scope"])

    def write_feedback(self):
        if self.directory is not None:
            R.C.write_json(self.directory / "energy-feedback-data.json", self.feedback)

    def start(self):
        # The parent provides strict preflight, common initial assignment,
        # private state, both replanning weight arms, owned Ryu and cleanup.
        # Its scheduled tick/publish/analysis are NEVER called by this module.
        applied = super().start()
        hashes = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in ADDED_SOURCES}
        contract = self.report["contract"]
        for key in ("schedule_after_both_ready", "analysis_window_s", "primary_analysis_phase"):
            contract.pop(key, None)
        contract.update(protocol=PROTOCOL, scheduled_battery_events=False,
            duration_s=DURATION_S, battery_update_interval_target_s=UPDATE_INTERVAL_S,
            model=MODEL, parameter_sha256=self.profile_sha,
            counter_instrumentation="Sequential bracketed RX/TX reads every >=5 real seconds; no catch-up update burst",
            time_acceleration=1.0, initial_assignment_rule="Existing common 90% UAV1 assignment in BOTH arms",
            guard_rule="Unchanged strict discharge/plateau guard on ALL UAVs, including idle hovering UAVs",
            stop_rule="Abort this bounded integration check on depletion or any service rejection; retain evidence",
            comparison_claim="One feedback demonstration per arm, not a source-calibrated causal energy comparison")
        contract["source_sha256"].update(hashes)
        self.report.update(protocol=PROTOCOL, source_sha256=dict(contract["source_sha256"]),
                           contract_sha256=digest(contract))
        self.feedback.update(comparison_contract_sha256=self.report["contract_sha256"],
                             initial_states=copy.deepcopy(self.document["states"]))
        self.write()
        self.write_feedback()
        print("ENERGY FEEDBACK: real time, ALL UAV batteries estimated from counters; no manual battery events.", flush=True)
        print("Reference-derived composite parameters; strict joint+guard unchanged; short run need not change routes.", flush=True)
        return applied

    def begin_feedback(self):
        require(self.ledger is None, "Feedback already started")
        before = R.C.clock_mark()
        origin = read_snapshot(R.P.DRONES)
        self.ledger = BatteryLedger(self.document, origin, self.profile)
        self.feedback.update(status="observing", origin_read_begin=before,
                             origin_read_end=R.C.clock_mark(), origin=origin)
        self.next_read_ns = self.feedback["origin_read_end"]["monotonic_ns"] + int(UPDATE_INTERVAL_S * 1e9)
        self.write_feedback()

    def tick(self, data=None, finished=False):
        require(self.ledger is not None, "Feedback origin not recorded")
        if not finished and time.monotonic_ns() < self.next_read_ns:
            return
        started = R.C.clock_mark()
        snapshot = read_snapshot(R.P.DRONES)
        read_end = R.C.clock_mark()
        energy = self.ledger.advance(snapshot)
        row = {"read_begin": started, "read_end": read_end, "snapshot": snapshot,
               "energy": energy, "status": "estimated"}
        self.feedback["updates"].append(row)
        self.write_feedback()
        if any(p["depleted"] for p in energy["per_uav"].values()):
            raise RuntimeError("Estimated battery depleted; v1 does not model continued unpowered hovering")
        document = copy.deepcopy(self.document)
        document["revision"] += 1
        document["states"] = energy["states"]
        expected = plan_weight_comparison(R.P, document["states"], self.args.scenario,
                                          self.previous, self.args.weights)
        row["expected_plan"] = expected
        # In particular, never silently disable the strict guard to force a
        # route change when all hovering batteries discharge together.
        if not all(c["admitted"] for c in expected["classes"]):
            row.update(status="model_stop", reason="Service rejection under unchanged joint+guard")
            self.write_feedback()
            raise RuntimeError(row["reason"] + "; no new state was published; inspect energy-feedback-data.json")
        row["publish_start"] = R.C.clock_mark()
        self.document = save_state(self.state_file, document, R.P.DRONES)
        row["publish_end"] = R.C.clock_mark()
        self.write_feedback()
        applied = self.wait(expected)
        row.update(status="acknowledged", confirmation_observed=R.C.clock_mark(),
                   revision=self.document["revision"], epoch=applied["epoch"])
        label = "energy%03d" % self.document["revision"]
        # Same profile verification as the original accepted full/degraded
        # services. A barrier acknowledgement alone is never packet delivery.
        profile_check = R.D.verify_flow_profile(applied, self.directory, label)
        row["profile_check"] = profile_check
        row["status"] = "applied"
        self.report["stages"][label] = {"publish_start": row["publish_start"],
            "confirmation_observed": row["confirmation_observed"], "applied": applied,
            "profile_check": profile_check}
        self.previous = expected
        # Sampling is serial: no next publication until this one is confirmed.
        self.next_read_ns = time.monotonic_ns() + int(UPDATE_INTERVAL_S * 1e9)
        row["update_finished"] = R.C.clock_mark()
        self.write_feedback()
        self.write()
        fractions = " ".join("%s=%.3f%%" % (n, 100*s["energy_fraction"])
                             for n, s in self.document["states"].items())
        print("FEEDBACK revision=%d epoch=%d | %s | UAV1 planned=%.2f Mbps" %
              (self.document["revision"], applied["epoch"], fractions,
               expected["forward_scheduler_allocations_mbps"]["UAV1"]), flush=True)


def functional(session, initial):
    from check_battery_enforcement import probe
    result = probe(initial, session.directory, "feedback-initial")
    require(all(p["received"] == 3 for p in result["probes"]), "Initial functional probes failed")
    session.begin_feedback()
    deadline = time.monotonic() + DURATION_S
    while time.monotonic() < deadline:
        session.alive()
        session.tick()
        time.sleep(.1)
    session.tick(finished=True)
    latest = max(session.report["stages"].values(), key=lambda s: s["applied"]["revision"])
    result = probe(latest["applied"], session.directory, "feedback-final")
    require(all(p["received"] == 3 for p in result["probes"]), "Final functional probes failed")
    session.report["functional_probes"] = result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("A", "B"), required=True)
    parser.add_argument("--weights", choices=("fixed", "adaptive"), required=True)
    parser.add_argument("--kind", choices=("functional", "udp"), required=True)
    parser.add_argument("--pair", required=True)
    parser.add_argument("--parameters", type=Path, default=ROOT / "config/energy_feedback.reference.json")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", args.pair):
        parser.error("Pair label must contain 1-40 letters, digits, underscores or hyphens")
    try:
        profile, sha = load_profile(args.parameters)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Feedback stopped before network setup:", error)
        return 1
    session = FeedbackTrial(args, profile, sha)
    try:
        initial = session.start()
        if args.kind == "functional":
            functional(session, initial)
        else:
            from energy_feedback_capture import collect
            collect(session)
        require(session.ledger is not None and session.ledger.updates >= 1, "No feedback updates")
        session.finish_measurements()
        session.feedback["status"] = "collected"
    except (Exception, KeyboardInterrupt) as error:
        message = type(error).__name__ + ": " + str(error)
        session.report.update(status="failed", error=message)
        session.feedback.update(status="failed", error=message)
        print("Feedback trial stopped:", message, flush=True)
    finally:
        session.close()
        session.feedback["status"] = "completed" if session.report["status"] == "completed" else "failed"
        session.write_feedback()
    if session.report["status"] != "completed":
        print("Evidence retained; cleanup:", session.report["cleanup_errors"])
        return 1
    try:
        from energy_feedback_report import analyze
        report = analyze(session.directory)
        print("FEEDBACK INTEGRATION:", report["integration_verdict"])
        if args.kind == "udp":
            print("SOURCE CRITERIA:", report["source_verdict"], "(unchanged thresholds)")
        print("Saved:", session.directory / "energy-feedback-report.json")
        print("No physical energy, longer-lifetime or QoS PASS is issued.")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        session.report["feedback_analysis_error"] = str(error)
        session.write()
        print("Feedback analysis requires review:", error)
        return 1
    return 0


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Termination requested")
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
