"""OFFLINE ONLY: joint VOICE/VIDEO selection and declining-battery load caps.

Place in ~/green-fanet-multihop/sim and run as your normal user, without sudo.
Never starts Docker, Ryu or traffic; never edits policy, state or topology.
Reports a 2x2 ablation: greedy/joint selection, with/without a discharge guard.
This candidate is not installed in any live controller. Source calibration,
QoS, energy drain and recruiting are outside this deterministic model check.
"""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import uuid

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from config import params as P
from core.battery_policy import DEFAULT_CONFIG, plan_protected, scenario_links
from core.lab_scenario import STATES
from core.model import adaptive_weights, uav_cost

EXPECTED_SOURCES = {'core/model.py': '5a6f7815aa76e5562429317ae57490bc0e6949618942cdfb27839226f217c03a', 'core/lab_scenario.py': '2243a642809a7f1672ad5999246c5339501c28f248cffcc760374b092af6f458', 'core/battery_policy.py': '299b9d00e107f4c035c9dd456337e0b85d5553d853765aaeaf8b0197cd757d10', 'core/state_store.py': '6adc5ab5e24f9767c1500ea4e35121cd9f3fab4715b2b91c2bbaaa0f9b2c1383'}
ENERGIES = (.90, .50, .40, .30, .25, .21, .20, .19, .10, .0)
VARIANTS = ("current_greedy", "greedy_guard", "joint_only", "joint_guard")
EPSILON = 1e-9


def require(condition, message):
    if not condition:
        raise ValueError(message)


def allocations(plan):
    totals = {name: 0.0 for name in plan["states"]}
    for flow in plan["classes"]:
        if flow["admitted"]:
            for relay in flow["path"][1:-1]:
                require(relay in totals, "Unexpected relay in previous plan")
                totals[relay] += flow["scheduler_budget_mbps"]
    require(all(abs(totals[name] - plan["forward_scheduler_allocations_mbps"][name]) < EPSILON
                for name in totals), "Reported allocations differ from class assignments")
    return totals


def all_paths(links, delay, budget, relays):
    """Enumerate simple delay-feasible paths in the fixed four-UAV lab only."""
    graph = {}
    for a, b in links:
        graph.setdefault(a, []).append(b)
        graph.setdefault(b, []).append(a)
    result = []
    pending = [(["u1"], 0.0)]
    while pending:
        path, elapsed = pending.pop()
        if path[-1] == "gs":
            result.append((path, elapsed))
            continue
        for node in reversed(graph.get(path[-1], [])):
            next_delay = elapsed + (delay if node in relays else 0)
            if node not in path and next_delay <= budget:
                pending.append((path + [node], next_delay))
    return result


def candidate(params, states, scenario, previous, joint=True, guard=True):
    """A small exact search, with declared admission and tie-break priorities.

    Admission priority: feasible VOICE first, then full VIDEO if any compatible
    pair exists, then capped VIDEO, then VOICE alone. Within a VIDEO profile,
    minimize VOICE path cost first, then VIDEO path cost. Stable ties follow
    original logical-link traversal order. No load-weighted energy model is
    introduced. The guard caps a relay's NEW scheduler allocation at its last
    accepted allocation when that relay's battery declines. The ceiling is
    retained while its battery is unchanged and released on a battery rise.
    A strict guard can restrict feasible admissions; such cases are reported,
    never silently relaxed or claimed as universal improvements.
    """
    base = plan_protected(params, states, scenario)
    unguarded_voice_feasible = base["classes"][0]["admitted"]
    config = DEFAULT_CONFIG
    relays = set(params.DRONES)
    state = base["states"]
    caps = dict(base["usable_capacities_mbps"])
    guarded, discharge_caps = {}, {}
    if guard:
        require(previous["scenario"] == scenario and previous["config"] == base["config"],
                "Previous plan belongs to a different scenario or configuration")
        require(set(previous["states"]) == relays, "Previous states differ")
        old = allocations(previous)
        for relay in params.DRONES:
            energy, prior = state[relay]["energy_fraction"], previous["states"][relay]["energy_fraction"]
            prior_cap = previous.get("discharge_caps_mbps", {}).get(relay)
            if energy < prior or (energy == prior and prior_cap is not None):
                ceiling = old[relay] if energy < prior else prior_cap
                if prior_cap is not None:
                    ceiling = min(ceiling, prior_cap)
                caps[relay] = min(caps[relay], ceiling)
                discharge_caps[relay] = caps[relay]
                guarded[relay] = {"previous_energy_fraction": previous["states"][relay]["energy_fraction"],
                    "current_energy_fraction": state[relay]["energy_fraction"],
                    "previous_budget_mbps": old[relay], "new_budget_ceiling_mbps": caps[relay],
                    "cause": "battery_decline" if energy < prior else "held_on_plateau"}
    blocked = set(base["blocked_relays"])
    links = [(a, b) for a, b in scenario_links(params, scenario)[0] if a not in blocked and b not in blocked]
    weights = {name: adaptive_weights(row["energy_fraction"]) for name, row in state.items()}

    def paths(delay_budget):
        rows = []
        for path, delay in all_paths(links, params.UAV_DELAY_MS, delay_budget, relays):
            cost = sum(uav_cost(params.UAV_DELAY_MS, state[n]["energy_fraction"],
                               state[n]["carbon_norm"], delay_budget, weights[n]) for n in path[1:-1])
            rows.append({"path": path, "configured_delay_ms": delay, "cost": cost})
        return sorted(rows, key=lambda row: row["cost"])

    def fits(voice, video, video_budget):
        used = {name: 0.0 for name in params.DRONES}
        for route, budget in ((voice, config.voice_scheduler_budget_mbps), (video, video_budget)):
            if route is not None:
                for relay in route["path"][1:-1]:
                    used[relay] += budget
        return all(used[name] <= caps[name] + EPSILON for name in used)

    voices = [row for row in paths(config.voice_delay_budget_ms) if fits(row, None, 0)]
    videos = paths(config.video_delay_budget_ms)
    voice, video, selected_budget = (voices[0] if voices else None), None, 0.0
    if voices:
        considered_voices = voices if joint else voices[:1]
        for video_budget in (config.video_full_scheduler_budget_mbps, config.video_degraded_cap_mbps):
            pairs = [(v, w) for v in considered_voices for w in videos if fits(v, w, video_budget)]
            if pairs:
                voice, video = min(pairs, key=lambda pair: (pair[0]["cost"], pair[1]["cost"]))
                selected_budget = video_budget
                break

    def flow(name, route, budget):
        is_voice = name == "VOICE"
        degraded = not is_voice and budget == config.video_degraded_cap_mbps
        row = {"name": name, "dscp": 46 if is_voice else 34, "admission_rank": 1 if is_voice else 2,
               "preemption_vulnerable": not is_voice,
               "reference_5qi": 1 if is_voice else None if degraded else 2,
               "requested_payload_mbps": config.voice_payload_mbps if is_voice else config.video_payload_mbps,
               "delay_budget_ms": config.voice_delay_budget_ms if is_voice else config.video_delay_budget_ms,
               "admitted": route is not None}
        if route is None:
            row.update(decision=name + "_REJECTED", reason="No compatible protected assignment under this candidate's constraints")
        else:
            row.update(route)
            row.update(resource_type="NON_GBR_EMULATED" if degraded else "GBR_EMULATED",
                       scheduler_budget_mbps=budget, meter_cap_mbps=None if is_voice else budget,
                       gbr_payload_mbps=0.0 if degraded else row["requested_payload_mbps"],
                       decision="VOICE_ADMITTED" if is_voice else "VIDEO_DOWNGRADED" if degraded else "VIDEO_ADMITTED_FULL")
        return row

    base["classes"] = [flow("VOICE", voice, config.voice_scheduler_budget_mbps), flow("VIDEO", video, selected_budget)]
    base["forward_scheduler_allocations_mbps"] = {name: 0.0 for name in params.DRONES}
    base["forward_gbr_budgets_mbps"] = {name: 0.0 for name in params.DRONES}
    for row in base["classes"]:
        if row["admitted"]:
            for relay in row["path"][1:-1]:
                base["forward_scheduler_allocations_mbps"][relay] += row["scheduler_budget_mbps"]
                if row["resource_type"] == "GBR_EMULATED":
                    base["forward_gbr_budgets_mbps"][relay] += row["scheduler_budget_mbps"]
    base.update(policy="joint-battery-candidate-offline", joint_selection=joint, guard_enabled=guard,
                guard_capacities_mbps=caps, guarded_relays=guarded, discharge_caps_mbps=discharge_caps,
                guard_blocks_feasible_voice=bool(guard and unguarded_voice_feasible and voice is None),
                guard_rule="Cap decreases with accepted allocation during discharge, persists on a battery plateau, and resets on a battery rise",
                selection_priority="VOICE admission; VIDEO full/degraded/rejected; VOICE cost; VIDEO cost",
                scope="Offline candidate only; not installed in the controller; no QoS or energy result")
    validate(base)
    return base


def validate(plan):
    total = allocations(plan)
    for name, budget in total.items():
        require(budget <= plan["usable_capacities_mbps"][name] + EPSILON, "Usable capacity exceeded")
        if plan.get("guard_enabled"):
            require(budget <= plan["guard_capacities_mbps"][name] + EPSILON, "Declining-battery guard exceeded")
    for row in plan["classes"]:
        if row["admitted"]:
            require(not set(row["path"]) & set(plan["blocked_relays"]), "Protected path contains an excluded UAV")
            require(row["configured_delay_ms"] <= row["delay_budget_ms"], "Configured path delay exceeds budget")


def signature(plan):
    return tuple((row["name"], row["admitted"], tuple(row.get("path", ())),
                  row.get("scheduler_budget_mbps")) for row in plan["classes"])


def snapshot(plan):
    return {"uav1_scheduler_budget_mbps": plan["forward_scheduler_allocations_mbps"]["UAV1"],
            "voice": plan["classes"][0]["decision"], "video": plan["classes"][1]["decision"],
            "paths": {row["name"]: row.get("path", []) for row in plan["classes"]}}


def audit(params, initial_states):
    report = {"schema": 1, "status": "completed", "energies": ENERGIES, "variants": VARIANTS,
              "scope": "Offline model ablation; no traffic, source-calibration, live QoS, energy or recruiting proof",
              "objective": "Admission profiles first; then VOICE cost and VIDEO cost. Unchanged class budgets and hard battery threshold.",
              "guard_caveat": "Discharge budget ceiling persists on unchanged battery and resets on a battery rise. May reduce feasible admissions. Not a physical energy guarantee.",
              "scenarios": {}}
    for case in ("A", "B"):
        initial_state = copy.deepcopy(initial_states)
        initial_state["UAV1"]["energy_fraction"] = .90
        common = plan_protected(params, initial_state, case)
        previous = {name: copy.deepcopy(common) for name in VARIANTS}
        sequences = {"sequential": [], "single_step_from_common_initial": []}
        for study, rows in sequences.items():
            for energy in ENERGIES:
                states = copy.deepcopy(initial_state)
                states["UAV1"]["energy_fraction"] = energy
                plans = {}
                for name in VARIANTS:
                    reference = previous[name] if study == "sequential" else common
                    if energy == .90:
                        plan = copy.deepcopy(common)  # Common inherited baseline, no optimization at start.
                    elif name == "current_greedy":
                        plan = plan_protected(params, states, case)
                    else:
                        plan = candidate(params, states, case, reference,
                                         joint=name != "greedy_guard", guard=name != "joint_only")
                    validate(plan)
                    plans[name] = {"summary": snapshot(plan), "plan": plan}
                    if study == "sequential":
                        previous[name] = plan
                rows.append({"energy_fraction": energy, "variants": plans,
                    "guard_rejects_otherwise_feasible_voice": plans["joint_guard"]["plan"].get("guard_blocks_feasible_voice", False)})
        report["scenarios"][case] = {"common_initial_plan": common,
            "initialization": "All arms inherit the exact current 90% plan; replanning begins at the first battery update",
            "studies": sequences}
    return report


def main():
    try:
        require(P.UAV_BW_MBPS == 5, "This candidate check expects the current 5 Mbps UAV lab")
        for relative, expected in EXPECTED_SOURCES.items():
            value = hashlib.sha256((PROJECT_ROOT / relative).read_text(encoding="utf-8").encode()).hexdigest()
            require(value == expected, "Existing source differs: " + relative + "; no project changes made")
        report = audit(P, STATES)
        report["source_sha256"] = {relative: hashlib.sha256((PROJECT_ROOT / relative).read_bytes()).hexdigest()
            for relative in (*EXPECTED_SOURCES, "config/params.py", "sim/check_joint_battery_candidate.py")}
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        folder = PROJECT_ROOT / "results/joint-battery-candidate-checks" / (stamp + "-" + uuid.uuid4().hex[:12])
        folder.mkdir(parents=True, exist_ok=False)
        report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        (folder / "candidate-check.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
        print("Results:", folder)
        print("OFFLINE ONLY. Unchanged class budgets and <20% exclusion. Same inherited 90% initial plan.")
        for case, data in report["scenarios"].items():
            print("\nSCENARIO", case, "-- sequential discharge")
            print("UAV1 battery | UAV1 budget Mbps: current / greedy+guard / joint / joint+guard")
            for row in data["studies"]["sequential"]:
                values = [row["variants"][name]["summary"]["uav1_scheduler_budget_mbps"] for name in VARIANTS]
                print("%5.0f%%       | %.2f / %.2f / %.2f / %.2f" % (100*row["energy_fraction"], *values))
                if row["energy_fraction"] in (.25, .19):
                    for name in VARIANTS:
                        summary = row["variants"][name]["summary"]
                        print("  %s: %s; %s | VOICE %s | VIDEO %s" %
                              (name, summary["voice"], summary["video"], " -> ".join(summary["paths"]["VOICE"]),
                               " -> ".join(summary["paths"]["VIDEO"])))
                if row["guard_rejects_otherwise_feasible_voice"]:
                    print("  LIMITATION: strict guard rejected otherwise feasible VOICE; candidate requires review.")
        print("\nBoth sequential and single-step audits saved. Candidate is NOT installed live.")
        print("The guard persists on flat battery, resets on a battery rise, and can restrict admission. It does not fix UDP source timing.")
        print("Saved:", folder / "candidate-check.json")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Candidate check stopped:", str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
