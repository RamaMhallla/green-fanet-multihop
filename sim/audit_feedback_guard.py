"""OFFLINE: compare strict/zone/no guard with identical fixed/adaptive arms.

Declared input trajectories, NOT a battery-physics or timed energy simulation.
No Docker, Ryu, traffic, network changes or runtime-state writes are needed.
"""
import copy
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "sim")]
from config import params as P
from core.lab_scenario import STATES
from core.feedback_guard_policy import VERSION, shared_guard_initial, plan_feedback_guard
from core.weight_comparison_policy import plan_weight_comparison
from core.joint_battery_policy import require

VARIANTS = (("strict", "strict", None), ("zone25", "battery_zone", .25),
            ("zone30", "battery_zone", .30), ("zone35", "battery_zone", .35), ("none", "none", None))
SOURCES = ("config/params.py", "core/model.py", "core/lab_scenario.py", "core/battery_policy.py",
           "core/joint_battery_policy.py", "core/weight_comparison_policy.py",
           "core/feedback_guard_policy.py", "sim/audit_feedback_guard.py")


def normalized(value):
    return json.loads(json.dumps(value, allow_nan=False))


def trajectory(start_percent):
    require(start_percent in (90, 28), "Only the two declared starts are supported")
    initial = copy.deepcopy(STATES)
    initial["UAV1"]["energy_fraction"] = start_percent / 100
    for percent in range(start_percent, -1, -1):
        drop = (start_percent - percent) / 100
        state = copy.deepcopy(initial)
        for name, row in state.items():
            row["energy_fraction"] = round(max(0.0, initial[name]["energy_fraction"] - drop), 12)
        yield percent, state


def assert_strict_parity(candidate, legacy):
    for key in ("classes", "states", "config", "blocked_relays", "relay_weights",
                "forward_scheduler_allocations_mbps", "forward_gbr_budgets_mbps",
                "guard_capacities_mbps", "guarded_relays", "discharge_caps_mbps",
                "guard_blocks_feasible_voice"):
        require(normalized(candidate[key]) == normalized(legacy[key]), "Existing strict-planner parity failed: " + key)


def decision_row(plan, name, start, percent, scenario, mode, phase):
    flows = {r["name"]: r for r in plan["classes"]}
    row = {"trajectory": "equal_drop_from_%d" % start, "start_uav1_percent": start,
        "uav1_percent": percent, "scenario": scenario, "variant": name, "weights": mode,
        "phase": phase, "blocked_relays": plan["blocked_relays"],
        "guarded_relays": sorted(plan.get("guarded_relays", {})),
        "states": plan["states"], "allocations_mbps": plan["forward_scheduler_allocations_mbps"],
        "guard_capacities_mbps": plan.get("guard_capacities_mbps", plan["usable_capacities_mbps"]),
        "guard_blocks_feasible_voice": plan.get("guard_blocks_feasible_voice", False)}
    for service in ("VOICE", "VIDEO"):
        f = flows[service]
        row[service] = {key: f.get(key) for key in ("admitted", "decision", "path", "cost", "configured_delay_ms",
                        "scheduler_budget_mbps", "resource_type", "meter_cap_mbps")}
    return row


def first(rows, predicate):
    return next((r["uav1_percent"] for r in rows[1:] if predicate(r)), None)


def summary(rows):
    initial_video = rows[0]["VIDEO"]["path"]
    increases = [r for previous, r in zip(rows, rows[1:])
                 if r["allocations_mbps"]["UAV1"] > previous["allocations_mbps"]["UAV1"] + 1e-9]
    return {**{k: rows[0][k] for k in ("trajectory", "scenario", "variant", "weights")},
        "first_admitted_video_route_change_percent": first(rows, lambda r: r["VIDEO"]["admitted"] and r["VIDEO"]["path"] != initial_video),
        "first_video_offload_from_uav1_percent": (first(rows, lambda r: r["VIDEO"]["admitted"] and "UAV1" not in r["VIDEO"]["path"])
            if "UAV1" in initial_video else None),
        "first_video_downgrade_percent": first(rows, lambda r: r["VIDEO"]["decision"] == "VIDEO_DOWNGRADED"),
        "first_video_rejection_percent": first(rows, lambda r: not r["VIDEO"]["admitted"]),
        "first_voice_rejection_percent": first(rows, lambda r: not r["VOICE"]["admitted"]),
        "first_uav1_excluded_percent": first(rows, lambda r: "UAV1" in r["blocked_relays"]),
        "first_uav1_allocation_increase_percent": increases[0]["uav1_percent"] if increases else None,
        "maximum_uav1_allocation_mbps": max(r["allocations_mbps"]["UAV1"] for r in rows),
        "video_rejected_samples": sum(not r["VIDEO"]["admitted"] for r in rows),
        "voice_rejected_samples": sum(not r["VOICE"]["admitted"] for r in rows)}


def run_audit():
    decisions, summaries, parity = [], [], 0
    for start in (90, 28):
        samples = list(trajectory(start))
        for scenario in ("A", "B"):
            common = shared_guard_initial(P, samples[0][1], scenario)
            for name, guard_mode, activation in VARIANTS:
                for mode in ("fixed", "adaptive"):
                    previous = copy.deepcopy(common)
                    old_previous = copy.deepcopy(common)
                    rows = []
                    for i, (percent, state) in enumerate(samples):
                        plan = previous if i == 0 else plan_feedback_guard(P, state, scenario, previous,
                            mode, guard_mode, .30 if activation is None else activation)
                        if guard_mode == "strict" and i:
                            old_plan = plan_weight_comparison(P, state, scenario, old_previous, mode)
                            assert_strict_parity(plan, old_plan)
                            old_previous = old_plan
                            parity += 1
                        rows.append(decision_row(plan, name, start, percent, scenario, mode, "initial" if i == 0 else "replan"))
                        previous = plan
                    decisions.extend(rows)
                    summaries.append(summary(rows))
    return decisions, summaries, parity


def write_results(directory, decisions, summaries, manifest):
    directory.mkdir(parents=True, exist_ok=False)
    for name, obj in (("manifest.json", manifest), ("decisions.json", decisions), ("summary.json", summaries)):
        (directory / name).write_text(json.dumps(obj, indent=2, allow_nan=False) + "\n")
    columns = ["trajectory", "scenario", "variant", "weights", "phase", "uav1_percent",
        "uav1_allocation_mbps", "uav2_allocation_mbps", "uav2_guard_ceiling_mbps",
        "voice_decision", "voice_path", "video_decision", "video_path", "blocked_relays", "guarded_relays"]
    with (directory / "decisions.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for r in decisions:
            writer.writerow({**{k: r[k] for k in columns[:6]},
                "uav1_allocation_mbps": r["allocations_mbps"]["UAV1"],
                "uav2_allocation_mbps": r["allocations_mbps"]["UAV2"],
                "uav2_guard_ceiling_mbps": r["guard_capacities_mbps"]["UAV2"],
                "voice_decision": r["VOICE"]["decision"], "voice_path": " -> ".join(r["VOICE"]["path"] or []),
                "video_decision": r["VIDEO"]["decision"], "video_path": " -> ".join(r["VIDEO"]["path"] or []),
                "blocked_relays": ",".join(r["blocked_relays"]), "guarded_relays": ",".join(r["guarded_relays"])})
    lines = ["# Offline feedback guard comparison", "", manifest["scope"], "",
        "All arms replan. State schedules use equal percentage-point declines, clipped at zero.",
        "They do not use elapsed time, interface traffic or an energy model. Rejected plans are retained.", "",
        "Null cells mean not observed in this input trajectory. Listed percentages refer to UAV1.", "",
        "| Start | Scenario | Guard | Weights | Video off UAV1 | Video downgrade | Video reject | Voice reject | First UAV1 allocation rise | Max UAV1 Mbps |",
        "|---|---|---|---|---|---|---|---|---|---|"]
    for r in summaries:
        values = [r["trajectory"], r["scenario"], r["variant"], r["weights"],
                  r["first_video_offload_from_uav1_percent"], r["first_video_downgrade_percent"],
                  r["first_video_rejection_percent"], r["first_voice_rejection_percent"],
                  r["first_uav1_allocation_increase_percent"], r["maximum_uav1_allocation_mbps"]]
        lines.append("| " + " | ".join("none" if v is None else str(v) for v in values) + " |")
    (directory / "summary.md").write_text("\n".join(lines) + "\n")


def main():
    # Complete all calculations/parity checks before writing any result files.
    decisions, summaries, parity = run_audit()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    directory = ROOT / "results/feedback-guard-audits" / stamp
    manifest = {"schema": 1, "protocol": VERSION, "status": "completed",
        "row_count": len(decisions), "strict_legacy_parity_checks": parity,
        "guard_variants": [{"name": n, "mode": m, "activation_fraction": a} for n, m, a in VARIANTS],
        "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCES},
        "starts": [90, 28], "step_percent": 1, "template_states_before_uav1_start_override": STATES,
        "trajectory_rule": "Each UAV loses the same absolute battery fraction as UAV1 from its declared start, clipped at zero; carbon stays fixed.",
        "threshold_convention": "Guard zone activates at <= activation threshold on discharge, persists on flat battery, releases on a battery rise. Hard exclusion stays <20%.",
        "time_s": None, "energy_j": None, "qos_accepted": False, "live_policy_changed": False,
        "scope": "Synthetic input-state decisions only. No timed/physical discharge, live rerouting, QoS, energy savings or lifetime claim. No preferred threshold selected by this audit."}
    write_results(directory, decisions, summaries, manifest)
    print("OFFLINE FEEDBACK GUARD AUDIT: PASS | %d rows | %d strict parity checks" % (len(decisions), parity))
    print("ALL arms REPLAN; no network/runtime-state changes. Percentages below refer to UAV1.")
    print("Near-critical 28% initial state: scenario / guard / weights | first video off UAV1 / downgrade / rejection / UAV1 allocation rise")
    for r in summaries:
        if r["trajectory"] == "equal_drop_from_28":
            show = lambda k: "none" if r[k] is None else str(r[k]) + "%"
            print("%s %s %s | %s / %s / %s / %s" % (r["scenario"], r["variant"], r["weights"],
                show("first_video_offload_from_uav1_percent"), show("first_video_downgrade_percent"),
                show("first_video_rejection_percent"), show("first_uav1_allocation_increase_percent")))
    print("Both starting conditions and ALL rejected samples are in the saved reports.")
    print("State schedules are not energy-model predictions; no threshold is adopted live.")
    print("Summary:", directory / "summary.md")
    print("Rows:", directory / "decisions.csv")


if __name__ == "__main__":
    main()
