"""Summarize ONE completed fixed/adaptive feedback demonstration pair."""
import argparse
import datetime as dt
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "sim")]
from core.energy_feedback import digest, require
from energy_feedback_report import analyze
import battery_calibration_support as C


def compare(folders):
    folders = [Path(p).resolve() for p in folders]
    require(len(folders) == 2 and folders[0] != folders[1], "Two distinct trials required")
    reports = [analyze(p) for p in folders]
    require({r["weights"] for r in reports} == {"fixed", "adaptive"}, "One run per weight arm required")
    for key in ("scenario", "pair", "kind", "contract_sha256", "parameter_sha256"):
        require(reports[0][key] == reports[1][key], "Pair mismatch: " + key)
    fixed = next(r for r in reports if r["weights"] == "fixed")
    adaptive = next(r for r in reports if r["weights"] == "adaptive")
    differences = {}
    for name, left in fixed["per_uav"].items():
        right = adaptive["per_uav"][name]
        differences[name] = {"fixed_duration_s": left["duration_s"], "adaptive_duration_s": right["duration_s"],
            "fixed_estimated_average_w": left["estimated_average_w"],
            "adaptive_estimated_average_w": right["estimated_average_w"],
            "adaptive_minus_fixed_average_w": right["estimated_average_w"]-left["estimated_average_w"],
            "fixed_final_fraction": left["estimated_fraction"], "adaptive_final_fraction": right["estimated_fraction"]}
    return {"schema": 1, "protocol": fixed["protocol"], "scenario": fixed["scenario"],
        "pair": fixed["pair"], "kind": fixed["kind"], "status": "PAIRED_INTEGRATION_DEMONSTRATION",
        "trials": dict(zip((r["weights"] for r in reports), (str(p) for p in folders))),
        "contract_sha256": fixed["contract_sha256"], "per_uav": differences,
        "source_verdicts": {r["weights"]: r.get("source_verdict", "NOT_A_UDP_TEST") for r in reports},
        "qos_accepted": False, "energy_saving_established": False, "lifetime_gain_established": False,
        "scope": "A single paired feedback demonstration, no independent statistical replication. Separate per-UAV durations and observed work; no matched service, mission energy or longer-lifetime claim."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directories", nargs=2, type=Path)
    args = parser.parse_args()
    report = compare(args.directories)
    name = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    folder = ROOT / "results/energy-feedback-summaries" / name
    folder.mkdir(parents=True)
    C.write_json(folder / "pair-report.json", report)
    print("PAIR", report["scenario"], report["pair"], report["status"])
    print("Source:", report["source_verdicts"])
    for name, r in report["per_uav"].items():
        print("%s: fixed %.6f W; adaptive %.6f W; difference %+.6f W (own observation intervals)" %
              (name, r["fixed_estimated_average_w"], r["adaptive_estimated_average_w"], r["adaptive_minus_fixed_average_w"]))
    print("No measured energy saving, lifetime gain or QoS PASS. Saved:", folder / "pair-report.json")


if __name__ == "__main__":
    main()
