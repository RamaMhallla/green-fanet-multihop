"""Audit the NEW zone-guard protocol; reuse unchanged source/capture analysis."""
import argparse
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT/"sim")]
from config import params as P
from core.energy_feedback import BatteryLedger, digest, require, PROTOCOL as COLLECTOR_PROTOCOL
from core.guard_zone_protocol import (PROTOCOL, DEFINITION, DURATION_S, initial_zone_plan, next_zone_plan)
from core.battery_policy import plan_signature
from energy_feedback_report import traffic_report
import battery_calibration_support as C


def load(folder, name):
    return json.loads((Path(folder)/name).read_text())


def audit_updates(manifest, feedback, params=P):
    require(manifest.get("protocol") == feedback.get("protocol") == PROTOCOL,
            "Wrong protocol: old 90%/strict-guard trials cannot be relabelled as zone trials")
    require(manifest.get("status") == feedback.get("status") == "completed"
            and not manifest.get("cleanup_errors"), "Completed trial and verified cleanup required")
    contract = manifest["contract"]
    require(digest(contract) == manifest["contract_sha256"] == feedback["comparison_contract_sha256"], "Contract mismatch")
    require(contract.get("guard_definition") == feedback.get("guard_definition") == DEFINITION,
            "Guard definition differs")
    require(contract["parameter_sha256"] == feedback["parameter_sha256"]
            and contract["parameter_canonical_sha256"] == digest(feedback["parameters"]), "Energy parameter identity differs")
    require(contract.get("collector_protocol") == COLLECTOR_PROTOCOL
            and contract.get("scheduled_battery_events") is False
            and feedback.get("scheduled_battery_events") is False
            and contract.get("time_acceleration") == feedback.get("time_acceleration") == 1.0,
            "Collector, battery schedule or real-time contract differs")
    stages = manifest["stages"]
    previous = initial_zone_plan(params, feedback["initial_states"], manifest["scenario"], manifest["weights"])
    first_ack = stages["initial"]["applied"]
    require(first_ack["revision"] == 0 and first_ack["mode"] == "adaptive"
            and first_ack["scenario"] == manifest["scenario"]
            and digest(first_ack["plan"]) == digest(previous), "Initial controller plan differs")
    require(contract["initial_states"] == feedback["initial_states"], "Initial state differs")
    ledger = BatteryLedger({"schema": 1, "revision": 0, "states": feedback["initial_states"]},
                           feedback["origin"], feedback["parameters"])
    require(bool(feedback["updates"]), "No feedback updates")
    last_revision, last_epoch = 0, first_ack["epoch"]
    changes, offload = [], None
    initial_video_uses_uav1 = "UAV1" in previous["classes"][1]["path"]
    for row in feedback["updates"]:
        energy = ledger.advance(row["snapshot"])
        require(energy == row["energy"], "Energy/battery counter replay differs")
        require(row["status"] == "applied" and row["revision"] == last_revision+1, "Unapplied/skipped revision")
        expected = next_zone_plan(params, energy["states"], manifest["scenario"], previous, manifest["weights"])
        require(digest(expected) == digest(row["expected_plan"]), "Planner replay differs")
        stage = stages["energy%03d" % row["revision"]]
        ack = stage["applied"]
        require(ack["revision"] == row["revision"] and ack["epoch"] == row["epoch"]
                and ack["mode"] == "adaptive" and ack["scenario"] == manifest["scenario"]
                and digest(ack["plan"]) == digest(expected), "Acknowledged complete plan differs")
        changed = plan_signature(previous) != plan_signature(expected)
        require(ack["epoch"] == last_epoch + (1 if changed else 0), "Epoch change does not match route/profile change")
        require(ack["observed_monotonic_ns"] >= row["publish_start"]["monotonic_ns"], "Stale acknowledgement timestamp")
        require(all(energy["states"][n]["energy_fraction"] <= previous["states"][n]["energy_fraction"]
                    for n in energy["states"]), "Unexpected battery increase")
        event = {"revision": row["revision"], "epoch": ack["epoch"],
            "uav1_fraction": energy["states"]["UAV1"]["energy_fraction"],
            "confirmation_observed": row["confirmation_observed"],
            "classes": [{k: c.get(k) for k in ("name", "path", "decision", "scheduler_budget_mbps")} for c in expected["classes"]]}
        if changed:
            changes.append(event)
            if manifest["kind"] == "functional":
                probes = stage.get("probes_after_change", {}).get("probes", [])
                require(len(probes) == 2 and all(p["received"] == 3 for p in probes), "Missing successful post-change probes")
        video = expected["classes"][1]
        if initial_video_uses_uav1 and offload is None and video["admitted"] and "UAV1" not in video["path"]:
            offload = copy.deepcopy(event)
        previous, last_revision, last_epoch = expected, row["revision"], ack["epoch"]
    require(set(stages) == {"initial", *("energy%03d" % r["revision"] for r in feedback["updates"])}, "Unexpected manual stage")
    if manifest["kind"] == "functional":
        for key in ("functional_initial_probes", "functional_probes"):
            probes = manifest.get(key, {}).get("probes", [])
            require(len(probes) == 2 and all(p["received"] == 3 for p in probes), "Functional start/end probes missing")
    return {"integration_verdict": "PASS", "confirmed_feedback_updates": last_revision,
        "route_or_profile_changes": changes, "video_offload_from_uav1": offload,
        "video_offload_status": "OBSERVED_CONFIGURATION" if offload else "NOT_OBSERVED",
        "initial_states": feedback["initial_states"], "final_states": ledger.last["states"],
        "per_uav": ledger.last["per_uav"],
        "sum_per_node_interval_energy_j": ledger.last["sum_per_node_interval_energy_j"]}


def analyze(folder):
    folder = Path(folder)
    manifest, feedback = load(folder, "manifest.json"), load(folder, "energy-feedback-data.json")
    for relative, expected in manifest["source_sha256"].items():
        path = ROOT/relative
        require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                "Current source differs from recorded run; use matching source version: "+relative)
    report = {"schema": 1, "protocol": PROTOCOL, "scenario": manifest["scenario"],
        "weights": manifest["weights"], "pair": manifest["pair"], "kind": manifest["kind"],
        "contract_sha256": manifest["contract_sha256"], "parameter_sha256": feedback["parameter_sha256"],
        "guard_definition": copy.deepcopy(DEFINITION), "parameter_status": feedback["parameters"]["status"],
        **audit_updates(manifest, feedback), "qos_accepted": False,
        "energy_saving_established": False, "lifetime_gain_established": False,
        "scope": "Integration and observed configuration only; per-UAV observation intervals include setup/tail. Not equal-40s physical energy or statistically established benefit."}
    if manifest["kind"] == "udp":
        # This analyser checks the original collector protocol and all its
        # original criteria. New experiment identity remains in this manifest.
        data = load(folder, "energy-feedback-traffic.json")
        require(data.get("weights") == manifest["weights"] and data.get("scenario") == manifest["scenario"]
                and data.get("duration_s") == DURATION_S, "Traffic file belongs to another arm/scenario/duration")
        report.update(traffic_report(folder, manifest))
    C.write_json(folder/"guard-zone-report.json", report)
    return report


def print_report(report):
    print("GUARD ZONE INTEGRATION:", report["integration_verdict"], "|", report["scenario"], report["weights"])
    print("Confirmed updates:", report["confirmed_feedback_updates"], "route/profile changes:", len(report["route_or_profile_changes"]))
    offload = report["video_offload_from_uav1"]
    print("VIDEO off UAV1:", report["video_offload_status"],
          ("at sampled %.3f%%, epoch %d" % (100*offload["uav1_fraction"], offload["epoch"])) if offload else "")
    if "source_verdict" in report:
        print("SOURCE CRITERIA:", report["source_verdict"], "(unchanged)")
        for name, row in report["streams"].items():
            print("%s: source/GS %d/%d; absent %d; delivery %s; source %s" %
                  (name, row["source_unique_packets"], row["gs_unique_packets"],
                   len(row["source_ids_not_observed_at_gs"]), row["delivery_status"], row["verdict"]))
    for name, r in report["per_uav"].items():
        print("%s: %.3f%% -> %.3f%%; %.3fs; %.3f estimated J; %.6f average W" %
              (name, 100*r["initial_fraction"], 100*r["estimated_fraction"], r["duration_s"],
               r["estimated_total_j"], r["estimated_average_w"]))
    print("No physical energy, lifetime or QoS PASS is issued.")


def compare(reports, folders):
    require(len(reports) == 2 and len({str(p.resolve()) for p in folders}) == 2, "Two distinct trials required")
    require({r["weights"] for r in reports} == {"fixed", "adaptive"}, "One run per arm required")
    for key in ("protocol", "scenario", "pair", "kind", "contract_sha256", "parameter_sha256", "guard_definition"):
        require(reports[0][key] == reports[1][key], "Pair mismatch: "+key)
    fixed = next(r for r in reports if r["weights"] == "fixed")
    adaptive = next(r for r in reports if r["weights"] == "adaptive")
    return {"schema": 1, "protocol": PROTOCOL, "status": "PAIRED_ZONE_DEMONSTRATION",
        "scenario": fixed["scenario"], "pair": fixed["pair"], "kind": fixed["kind"],
        "guard_definition": fixed["guard_definition"], "contract_sha256": fixed["contract_sha256"],
        "trials": {r["weights"]: str(p.resolve()) for r, p in zip(reports, folders)},
        "source_verdicts": {r["weights"]: r.get("source_verdict", "NOT_A_UDP_TEST") for r in reports},
        "service_delivery": {r["weights"]: {name: {
            "source_packets": s["source_unique_packets"], "gs_packets": s["gs_unique_packets"],
            "not_observed_by_capture_end": len(s["source_ids_not_observed_at_gs"]),
            "delivery_status": s["delivery_status"], "source_verdict": s["verdict"]}
            for name, s in r.get("streams", {}).items()} for r in reports},
        "offload_status": {r["weights"]: r["video_offload_status"] for r in reports},
        "per_uav": {n: {"fixed_duration_s": a["duration_s"], "adaptive_duration_s": adaptive["per_uav"][n]["duration_s"],
            "fixed_average_w": a["estimated_average_w"], "adaptive_average_w": adaptive["per_uav"][n]["estimated_average_w"],
            "adaptive_minus_fixed_average_w": adaptive["per_uav"][n]["estimated_average_w"]-a["estimated_average_w"]}
            for n, a in fixed["per_uav"].items()},
        "qos_accepted": False, "energy_saving_established": False, "lifetime_gain_established": False,
        "scope": "One pair of independently timed feedback observations; whole per-UAV intervals include setup/tail. No fixed-duration mission, statistical or measured energy claim."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directories", type=Path, nargs="+")
    args = parser.parse_args()
    if len(args.directories) not in (1, 2):
        parser.error("Supply one trial or one matching fixed/adaptive pair")
    reports = [analyze(p) for p in args.directories]
    for r in reports:
        print_report(r)
    if len(reports) == 2:
        pair = compare(reports, args.directories)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:12]
        folder = ROOT/"results/guard-zone-feedback-summaries"/stamp
        folder.mkdir(parents=True)
        C.write_json(folder/"pair-report.json", pair)
        print("PAIR", pair["scenario"], pair["pair"], pair["status"])
        print("Offload:", pair["offload_status"], "Source:", pair["source_verdicts"])
        for name, r in pair["per_uav"].items():
            print("%s: fixed %.6f W; adaptive %.6f W; difference %+.6f W (own observation intervals)" %
                  (name, r["fixed_average_w"], r["adaptive_average_w"], r["adaptive_minus_fixed_average_w"]))
        print("Saved:", folder/"pair-report.json")


if __name__ == "__main__":
    main()
