"""Recompute feedback arithmetic and plans; retain the existing source criteria."""
import argparse
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "sim")]
from config import params as P
from core.energy_feedback import PROTOCOL, BatteryLedger, digest, require
from core.battery_policy import plan_signature
from core.weight_comparison_policy import plan_weight_comparison
from weight_comparison_analysis import cohort_metrics
import battery_calibration_support as C


def load(folder, name):
    return json.loads((Path(folder) / name).read_text())


def audit_updates(manifest, feedback, params=P):
    require(manifest.get("protocol") == feedback.get("protocol") == PROTOCOL,
            "Not an energy-feedback trial; do not mix with scheduled-battery results")
    require(manifest.get("status") == feedback.get("status") == "completed"
            and not manifest.get("cleanup_errors"), "Completed collection with verified cleanup required")
    require(manifest["contract_sha256"] == digest(manifest["contract"]), "Contract hash differs")
    require(feedback["comparison_contract_sha256"] == manifest["contract_sha256"]
            and feedback["parameter_sha256"] == manifest["contract"]["parameter_sha256"], "Parameter/contract identity differs")
    require(feedback.get("scheduled_battery_events") is False
            and feedback.get("time_acceleration") == 1.0, "Manual events or time acceleration are outside v1")
    stages = manifest["stages"]
    initial = copy.deepcopy(stages["initial"]["applied"]["plan"])
    require(initial["states"] == feedback["initial_states"], "Initial battery states differ")
    ledger = BatteryLedger({"schema": 1, "revision": 0, "states": feedback["initial_states"]},
                           feedback["origin"], feedback["parameters"])
    require(bool(feedback["updates"]), "No feedback updates")
    previous, last_revision = initial, 0
    epochs = [stages["initial"]["applied"]["epoch"]]
    changed = False
    for row in feedback["updates"]:
        energy = ledger.advance(row["snapshot"])
        require(energy == row["energy"], "Recorded energy/battery differs from counter replay")
        require(row["status"] == "applied" and row["revision"] == last_revision + 1,
                "Unapplied/skipped feedback revision")
        expected = plan_weight_comparison(params, energy["states"], manifest["scenario"], previous, manifest["weights"])
        require(digest(expected) == digest(row["expected_plan"]), "Recorded planner output differs from replay")
        stage = stages["energy%03d" % row["revision"]]
        ack = stage["applied"]
        require(ack["revision"] == row["revision"] and ack["epoch"] == row["epoch"]
                and ack["mode"] == "adaptive" and ack["scenario"] == manifest["scenario"], "Controller acknowledgement differs")
        plan = ack["plan"]
        require(plan_signature(plan) == plan_signature(expected)
                and plan["states"] == energy["states"]
                and plan["weight_mode"] == manifest["weights"]
                and plan["relay_weights"] == json.loads(json.dumps(expected["relay_weights"]))
                and plan.get("discharge_caps_mbps") == expected.get("discharge_caps_mbps"),
                "Applied routes/states/weights/guard differ")
        require(all(energy["states"][n]["energy_fraction"] <= previous["states"][n]["energy_fraction"]
                    for n in energy["states"]), "A battery increased without charging")
        changed |= any(energy["states"][n]["energy_fraction"] < initial["states"][n]["energy_fraction"]
                       for n in energy["states"])
        previous, last_revision = expected, row["revision"]
        epochs.append(row["epoch"])
    require(changed, "No estimated battery drain reached the controller")
    require(set(stages) == {"initial", *("energy%03d" % r["revision"] for r in feedback["updates"])},
            "Unexpected/manual stage present")
    return {"integration_verdict": "PASS", "confirmed_feedback_updates": last_revision,
        "route_or_profile_changes": sum(a != b for a, b in zip(epochs, epochs[1:])),
        "initial_states": feedback["initial_states"], "final_states": ledger.last["states"],
        "per_uav": ledger.last["per_uav"],
        "sum_per_node_interval_energy_j": ledger.last["sum_per_node_interval_energy_j"]}


def traffic_report(folder, manifest):
    data = load(folder, "energy-feedback-traffic.json")
    require(data.get("protocol") == PROTOCOL and data.get("status") == "completed"
            and not data.get("cleanup_errors"), "Completed feedback traffic evidence required")
    require(data.get("policy") == C.CALIBRATION_POLICY and data.get("profiles") == list(C.PROFILES),
            "Source acceptance or traffic settings differ")
    captures, quality, issues = {}, {}, []
    for name in ("u1", "gs"):
        count, captures[name] = C.read_capture(Path(folder) / (name + ".pcap"), data["source_ip"], data["destination_ip"])
        quality[name] = C.tcpdump_stats((Path(folder) / (name + "-tcpdump.log")).read_text())
        if quality[name]["kernel_dropped"] or count != quality[name]["captured"]:
            issues.append(name + ": capture drops/count mismatch")
    pacing = data["source_pacing"]
    if (pacing.get("dropped_packets_delta") != 0 or pacing.get("final_queued_packets") != 0
            or pacing.get("final_backlog_bytes") != 0 or pacing.get("noqueue_restored") is not True):
        issues.append("Source pacing drops/backlog/restoration requires review")
    marks = list(data["timing_marks"].values())
    offsets = [m["wall_ns"] - m["monotonic_ns"] for m in marks]
    spread = (max(offsets) - min(offsets)) / 1e6
    streams = {}
    for p in C.PROFILES:
        src, dst = captures["u1"][p["port"]], captures["gs"][p["port"]]
        source, destination = set(src["ids"]), set(dst["ids"])
        row = C.assess_source(src, data["udp"][p["name"]]["sender"], data["duration_s"], p["rate_mbps"])
        extra = sorted(destination - source)
        ambiguous = bool(issues or row["evidence_issues"] or extra
                         or dst["datagrams"] != len(destination))
        require(bool(source), "No source packets")
        metrics = cohort_metrics(src["ids"], dst["ids"], min(src["ids"].values()), max(src["ids"].values()) + 1)
        negative = metrics["capture_time_ms"] and metrics["capture_time_ms"]["minimum"] < 0
        row.update(source_unique_packets=len(source), gs_unique_packets=len(destination),
            source_ids_not_observed_at_gs=sorted(source-destination), gs_ids_not_observed_at_source=extra,
            packet_set_audit="INCONCLUSIVE" if ambiguous else "COMPLETE_CAPTURE_AUDIT",
            observed_delivery_percent=100*len(source & destination)/len(source),
            delivery_status="INCONCLUSIVE" if ambiguous else "OBSERVABLE",
            capture_time_status="INCONCLUSIVE" if ambiguous or spread > 5 or negative else "DESCRIPTIVE",
            paired_capture_time_ms=metrics["capture_time_ms"],
            absolute_capture_ipdv_ms=metrics["absolute_capture_ipdv_ms"],
            receiver_summary=data["udp"][p["name"]]["receiver"])
        streams[p["name"]] = row
    verdicts = [r["verdict"] for r in streams.values()]
    verdict = ("INCONCLUSIVE" if "INCONCLUSIVE" in verdicts or issues
               else "FAIL" if "FAIL" in verdicts else "PASS")
    return {"source_verdict": verdict, "streams": streams, "capture_quality": quality,
        "evidence_issues": issues, "clock_offset_spread_ms": spread,
        "source_pacing": pacing, "source_policy": C.CALIBRATION_POLICY,
        "queue_root_drop_deltas": data["queue_root_drop_deltas"],
        "video_meter_totals_by_epoch": manifest["video_meter_totals"],
        "timing_scope": "Whole-run paired software capture times for matched packets; not application delay or standardised jitter. Sparse clock checks are limited."}


def analyze(folder):
    folder = Path(folder)
    manifest, feedback = load(folder, "manifest.json"), load(folder, "energy-feedback-data.json")
    report = {"schema": 1, "protocol": PROTOCOL, "scenario": manifest["scenario"],
        "weights": manifest["weights"], "pair": manifest["pair"], "kind": manifest["kind"],
        "contract_sha256": manifest["contract_sha256"], "parameter_sha256": feedback["parameter_sha256"],
        "parameter_status": feedback["parameters"]["status"], **audit_updates(manifest, feedback),
        "qos_accepted": False, "energy_saving_established": False, "lifetime_gain_established": False,
        "energy_scope": "Each UAV's own observation interval, including preparation/tail. Nominal battery and linear discharge model. No synchronized equal-40s consumption comparison.",
        "guard_scope": "All hovering batteries decline. Strict guard can lock an unused relay at zero protected allocation, preventing the old scenario-B offload.",
        "scope": "Integration PASS verifies arithmetic, estimated-state publication and barrier-confirmed planner configuration only."}
    if manifest["kind"] == "udp":
        report.update(traffic_report(folder, manifest))
    C.write_json(folder / "energy-feedback-report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    report = analyze(args.directory)
    print("FEEDBACK INTEGRATION:", report["integration_verdict"])
    print("Confirmed updates:", report["confirmed_feedback_updates"], "route/profile changes:", report["route_or_profile_changes"])
    if "source_verdict" in report:
        print("SOURCE CRITERIA:", report["source_verdict"])
    for name, row in report["per_uav"].items():
        print("%s: %.3f%% -> %.3f%%; %.3fs; %.3f estimated J; %.6f average W" %
              (name, 100*row["initial_fraction"], 100*row["estimated_fraction"], row["duration_s"],
               row["estimated_total_j"], row["estimated_average_w"]))
    print("No measured energy, lifetime or QoS PASS.")


if __name__ == "__main__":
    main()
