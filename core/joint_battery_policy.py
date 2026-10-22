"""Experimental joint planner, separate from the original battery policy.
Same class budgets, hard exclusion and cost functions. Search full VIDEO
pairs before degradation. Enforce a persistent allocation ceiling during
discharge and flat battery; release on a battery rise. A strict guard can
make admission infeasible. This module performs no network or state I/O.
"""
from core.battery_policy import DEFAULT_CONFIG, plan_protected, scenario_links
from core.model import adaptive_weights, uav_cost

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
                ceiling = old[relay]
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


def plan_joint_protected(params, states, scenario, previous):
    return candidate(params, states, scenario, previous, joint=True, guard=True)
