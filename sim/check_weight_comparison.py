"""Offline check of the SAME joint+guard planner with two weight choices."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from config import params as P
from core.lab_scenario import STATES
from core.battery_policy import plan_signature
from core.joint_battery_policy import plan_joint_protected
from core.weight_comparison_policy import common_initial, plan_weight_comparison


def audit(params=P, initial_states=STATES):
    result = {}
    for scenario in ("A", "B"):
        state = copy.deepcopy(initial_states)
        state["UAV1"]["energy_fraction"] = .90
        seed = common_initial(params, state, scenario)
        history = {mode: copy.deepcopy(seed) for mode in ("fixed", "adaptive")}
        legacy = copy.deepcopy(seed)
        rows = []
        for battery in (.90, .30, .25, .25, .21, .20, .19):
            state["UAV1"]["energy_fraction"] = battery
            if battery == .90:
                pair = {mode: copy.deepcopy(seed) for mode in history}
            else:
                pair = {mode: plan_weight_comparison(params, state, scenario, history[mode], mode)
                        for mode in history}
                legacy = plan_joint_protected(params, state, scenario, legacy)
                if plan_signature(legacy) != plan_signature(pair["adaptive"]):
                    raise ValueError("Adaptive arm differs from the validated joint candidate")
            for mode, plan in pair.items():
                if not all(row["admitted"] for row in plan["classes"]):
                    raise ValueError("Unexpected admission failure")
                if battery >= .20 and plan["blocked_relays"]:
                    raise ValueError("Above-threshold plan unexpectedly uses exclusion")
                history[mode] = plan
            rows.append({"battery_fraction": battery, "plans": pair,
                         "different_routes_or_profiles": plan_signature(pair["fixed"]) != plan_signature(pair["adaptive"])})
        result[scenario] = rows
    return result


def main():
    data = audit()
    folder = ROOT / "results/weight-comparison-offline" / (
        dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    report = {"schema": 1, "status": "passed", "scenarios": data,
        "scope": "Offline routes only. Both arms replan with joint+guard. No network changes.",
        "source_sha256": {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
            ("core/weight_comparison_policy.py", "core/joint_battery_policy.py", "core/battery_policy.py",
             "core/model.py", "core/lab_scenario.py", "config/params.py")}}
    (folder / "offline-report.json").write_text(json.dumps(report, indent=2) + "\n")
    for scenario, rows in data.items():
        print("\nSCENARIO", scenario, "| both arms REPLAN, with the same joint planner and guard")
        for row in rows:
            a, b = (row["plans"][mode] for mode in ("fixed", "adaptive"))
            print("UAV1=%2.0f%% | reserved Mbps fixed/adaptive: %.2f / %.2f | different=%s" %
                (100*row["battery_fraction"], a["forward_scheduler_allocations_mbps"]["UAV1"],
                 b["forward_scheduler_allocations_mbps"]["UAV1"], row["different_routes_or_profiles"]))
    print("\nOFFLINE COMPARISON: PASS. These are calculated decisions, not measured improvements.")
    print("Saved:", folder / "offline-report.json")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print("Offline comparison stopped:", error)
        sys.exit(1)
