"""Offline audit of frozen routes, replan/fixed weights and replan/adaptive weights.

Run without sudo, from any directory after placing this file in project/sim.
No Docker, OVS, controller, queue, link or runtime-state operations. Uses the
identical installed plan_protected function with isolated weight-function
bindings. It does not edit or monkey-patch the installed policy module.
This audits deterministic model decisions, not traffic, energy or QoS.
"""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
from types import FunctionType
import uuid

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import params as P
from core.battery_policy import DEFAULT_CONFIG, plan_protected, plan_signature
from core.lab_scenario import STATES, EXPERIMENT_FIXED_WEIGHTS

ENERGIES = (.90, .50, .40, .30, .25, .21, .20, .19, .10, .0)
EXPECTED_SOURCES = {'core/model.py': '5a6f7815aa76e5562429317ae57490bc0e6949618942cdfb27839226f217c03a', 'core/lab_scenario.py': '2243a642809a7f1672ad5999246c5339501c28f248cffcc760374b092af6f458', 'core/battery_policy.py': '299b9d00e107f4c035c9dd456337e0b85d5553d853765aaeaf8b0197cd757d10', 'core/state_store.py': '6adc5ab5e24f9767c1500ea4e35121cd9f3fab4715b2b91c2bbaaa0f9b2c1383'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fixed_weight_planner(weights):
    """Same policy code and helpers, isolated globals, only weights replaced.

    This is an offline intervention, not a new live-controller mode. All UAVs
    receive the same predeclared tuple, so the hard exclusion, admission order,
    capacity and degraded VIDEO rules remain identical to the adaptive arm.
    """
    values = tuple(weights)
    require(len(values) == 3 and all(isinstance(v, (int, float)) and v >= 0 for v in values)
            and abs(sum(values)-1) < 1e-12, "Invalid fixed weight tuple")
    bindings = dict(plan_protected.__globals__)
    bindings["adaptive_weights"] = lambda energy: values
    function = FunctionType(plan_protected.__code__, bindings, "plan_fixed_weights",
                            plan_protected.__defaults__, plan_protected.__closure__)
    function.__kwdefaults__ = plan_protected.__kwdefaults__
    return function


def validate_replanned(plan):
    for row in plan["classes"]:
        if row["admitted"]:
            require(not set(row["path"]) & set(plan["blocked_relays"]),
                    "Replanned class traverses an excluded relay")
            require(row["configured_delay_ms"] <= row["delay_budget_ms"],
                    "Replanned configured delay exceeds its budget")
    for relay, allocation in plan["forward_scheduler_allocations_mbps"].items():
        require(allocation <= plan["usable_capacities_mbps"][relay] + 1e-9,
                "Replanned capacity exceeded at " + relay)


def summary(plan, current_state):
    blocked_now = sorted(name for name, row in current_state.items()
                         if row["energy_fraction"] == 0 or
                         row["energy_fraction"] < DEFAULT_CONFIG.weak_battery_threshold)
    selected = [row for row in plan["classes"] if row["admitted"] and "UAV1" in row["path"]]
    return {
        "uav1_classes": [row["name"] for row in selected],
        "uav1_routed_offered_payload_mbps": sum(row["requested_payload_mbps"] for row in selected),
        "uav1_scheduler_budget_mbps": sum(row["scheduler_budget_mbps"] for row in selected),
        "classes_on_currently_weak_or_dead_relays": [row["name"] for row in plan["classes"]
             if row["admitted"] and set(row["path"]) & set(blocked_now)],
        "classes_on_currently_dead_relays": [row["name"] for row in plan["classes"] if row["admitted"]
             and any(current_state[node]["energy_fraction"] == 0 for node in row["path"][1:-1])],
        "class_decisions": [{key: row[key] for key in
             ("name", "admitted", "decision", "path", "resource_type", "scheduler_budget_mbps", "meter_cap_mbps")
             if key in row} for row in plan["classes"]],
    }


def build_report(params, initial_states, energies=ENERGIES):
    fixed = fixed_weight_planner(EXPERIMENT_FIXED_WEIGHTS)
    output = {"schema": 1, "status": "completed", "fixed_weights": EXPERIMENT_FIXED_WEIGHTS,
              "battery_states": energies, "weak_battery_rule": "energy_fraction < 0.20, or zero",
              "scope": "Deterministic offline policy audit; no traffic, measured load, QoS, energy or recruiting result",
              "method": "Same installed planner code; only the weight-function binding changes for replan_fixed. Static freezes the common adaptive initial plan and profile.",
              "scenarios": {}}
    for case in ("A", "B"):
        initial_state = copy.deepcopy(initial_states)
        initial_state["UAV1"]["energy_fraction"] = .90
        common = plan_protected(params, initial_state, case)
        fixed_initial = fixed(params, initial_state, case)
        validate_replanned(common)
        rows = []
        for energy in energies:
            state = copy.deepcopy(initial_state)
            state["UAV1"]["energy_fraction"] = energy
            adaptive = plan_protected(params, state, case)
            constant = fixed(params, state, case)
            validate_replanned(adaptive)
            validate_replanned(constant)
            variants = {"static_common_initial": copy.deepcopy(common),
                        "replan_fixed": constant, "replan_adaptive": adaptive}
            rows.append({"energy_fraction": energy, "evaluation_states": state,
                "fixed_vs_adaptive_decisions_differ": plan_signature(constant) != plan_signature(adaptive),
                "variants": {name: {"summary": summary(plan, state), "plan": plan}
                             for name, plan in variants.items()}})
        output["scenarios"][case] = {
            "fixed_and_adaptive_initial_signatures_equal": plan_signature(common) == plan_signature(fixed_initial),
            "common_initial_plan": common, "rows": rows}
    return output


def main():
    try:
        require(P.UAV_BW_MBPS == 5, "This audit expects the current 5 Mbps UAV scenario")
        for relative, expected in EXPECTED_SOURCES.items():
            actual = hashlib.sha256((PROJECT_ROOT / relative).read_text(encoding="utf-8").encode()).hexdigest()
            require(actual == expected, "Source differs from audited version: " + relative + "; no changes made")
        report = build_report(P, STATES)
        report["source_sha256"] = {relative: hashlib.sha256((PROJECT_ROOT / relative).read_bytes()).hexdigest()
            for relative in (*EXPECTED_SOURCES, "config/params.py", "sim/audit_battery_weight_variants.py")}
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        folder = PROJECT_ROOT / "results/battery-weight-audits" / (stamp + "-" + uuid.uuid4().hex[:12])
        folder.mkdir(parents=True, exist_ok=False)
        report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        (folder / "weight-audit.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
        print("Results:", folder)
        for case, scenario in report["scenarios"].items():
            print("\nSCENARIO", case, "(offline)")
            print("Same initial fixed/adaptive decisions:", scenario["fixed_and_adaptive_initial_signatures_equal"])
            print("UAV1 battery | UAV1 scheduler budget Mbps: static / replan-fixed / replan-adaptive | different decisions")
            for row in scenario["rows"]:
                summaries = [row["variants"][name]["summary"] for name in
                             ("static_common_initial", "replan_fixed", "replan_adaptive")]
                print("%5.0f%%       | %.2f / %.2f / %.2f | %s" %
                      (row["energy_fraction"] * 100, *(s["uav1_scheduler_budget_mbps"] for s in summaries),
                       row["fixed_vs_adaptive_decisions_differ"]))
                if row["energy_fraction"] == .25:
                    for name in ("replan_fixed", "replan_adaptive"):
                        for flow in row["variants"][name]["summary"]["class_decisions"]:
                            print("  %s %s: %s | %s" % (name, flow["name"], flow["decision"],
                                  " -> ".join(flow.get("path", []))))
        print("\nOffline audit complete. Differences are observations, not automatic improvements.")
        print("Budget/route assignments are model outputs, not measured energy savings.")
        print("Saved:", folder / "weight-audit.json")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Weight audit stopped:", str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
