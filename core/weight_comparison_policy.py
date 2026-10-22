"""Same joint+guard decision algorithm in both replanning weight arms.

No network I/O. The initial assignment is shared, not separately optimised.
Only the relay weight tuple changes between arms. Admission order, exact
path enumeration, delay/capacity rules, tie breaks and guard are identical.
"""
import copy

from core.battery_policy import DEFAULT_CONFIG, plan_protected, scenario_links
from core.joint_battery_policy import all_paths, allocations, validate, require
from core.model import adaptive_weights, uav_cost

FIXED_WEIGHTS = (0.56, 0.20, 0.24)
EPSILON = 1e-9


def weights_for(states, weight_mode):
    require(weight_mode in ("fixed", "adaptive"), "weights must be fixed or adaptive")
    return {name: (FIXED_WEIGHTS if weight_mode == "fixed" else
                   adaptive_weights(row["energy_fraction"]))
            for name, row in states.items()}


def common_initial(params, states, scenario):
    require(states["UAV1"]["energy_fraction"] == .90, "Common start requires UAV1=90%")
    plan = plan_protected(params, copy.deepcopy(states), scenario)
    require(all(row["admitted"] for row in plan["classes"]), "Common full initial plan is infeasible")
    require(plan["classes"][1]["decision"] == "VIDEO_ADMITTED_FULL", "Initial video is not full")
    plan["comparison_phase"] = "common_initial_assignment"
    return plan


def plan_weight_comparison(params, states, scenario, previous, weight_mode):
    """Exact joint search, matching the existing candidate's ordering.

    Both arms recompute on every revision, including a battery plateau.
    The guard uses each arm's own last confirmed plan: later allocation
    histories are outcomes of the weight treatment, not silently shared.
    """
    weights_for(states, weight_mode)  # Reject invalid modes before any search.
    base = plan_protected(params, states, scenario)
    config = DEFAULT_CONFIG
    state = base["states"]
    require(previous["scenario"] == scenario and previous["config"] == base["config"],
            "Previous plan belongs to another scenario or configuration")
    require(set(previous["states"]) == set(params.DRONES), "Previous relay set differs")
    old = allocations(previous)
    caps = dict(base["usable_capacities_mbps"])
    guarded, discharge_caps = {}, {}
    for name in params.DRONES:
        energy, prior = state[name]["energy_fraction"], previous["states"][name]["energy_fraction"]
        prior_cap = previous.get("discharge_caps_mbps", {}).get(name)
        if energy < prior or (energy == prior and prior_cap is not None):
            ceiling = min(old[name], prior_cap) if prior_cap is not None else old[name]
            caps[name] = min(caps[name], ceiling)
            discharge_caps[name] = caps[name]
            guarded[name] = {"previous_energy_fraction": prior, "current_energy_fraction": energy,
                "previous_budget_mbps": old[name], "new_budget_ceiling_mbps": caps[name],
                "cause": "battery_decline" if energy < prior else "held_on_plateau"}
    blocked = set(base["blocked_relays"])
    links = [(a, b) for a, b in scenario_links(params, scenario)[0]
             if a not in blocked and b not in blocked]
    weights = weights_for(state, weight_mode)

    def paths(delay_budget):
        result = []
        for path, delay in all_paths(links, params.UAV_DELAY_MS, delay_budget, set(params.DRONES)):
            cost = sum(uav_cost(params.UAV_DELAY_MS, state[n]["energy_fraction"],
                               state[n]["carbon_norm"], delay_budget, weights[n])
                       for n in path[1:-1])
            result.append({"path": path, "configured_delay_ms": delay, "cost": cost})
        return sorted(result, key=lambda row: row["cost"])

    def fits(voice, video, video_budget):
        used = {name: 0.0 for name in params.DRONES}
        for route, budget in ((voice, config.voice_scheduler_budget_mbps), (video, video_budget)):
            if route is not None:
                for name in route["path"][1:-1]:
                    used[name] += budget
        return all(used[n] <= caps[n] + EPSILON for n in used)

    voices = [row for row in paths(config.voice_delay_budget_ms) if fits(row, None, 0)]
    videos = paths(config.video_delay_budget_ms)
    voice, video, selected = (voices[0] if voices else None), None, 0.0
    if voices:
        for video_budget in (config.video_full_scheduler_budget_mbps, config.video_degraded_cap_mbps):
            pairs = [(v, w) for v in voices for w in videos if fits(v, w, video_budget)]
            if pairs:
                voice, video = min(pairs, key=lambda pair: (pair[0]["cost"], pair[1]["cost"]))
                selected = video_budget
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
            row.update(decision=name + "_REJECTED", reason="No compatible joint+guard assignment")
        else:
            row.update(route)
            row.update(resource_type="NON_GBR_EMULATED" if degraded else "GBR_EMULATED",
                scheduler_budget_mbps=budget, meter_cap_mbps=None if is_voice else budget,
                gbr_payload_mbps=0.0 if degraded else row["requested_payload_mbps"],
                decision="VOICE_ADMITTED" if is_voice else "VIDEO_DOWNGRADED" if degraded else "VIDEO_ADMITTED_FULL")
        return row

    classes = [flow("VOICE", voice, config.voice_scheduler_budget_mbps), flow("VIDEO", video, selected)]
    base.update(classes=classes, forward_scheduler_allocations_mbps={n: 0.0 for n in params.DRONES},
                forward_gbr_budgets_mbps={n: 0.0 for n in params.DRONES})
    for row in classes:
        if row["admitted"]:
            for name in row["path"][1:-1]:
                base["forward_scheduler_allocations_mbps"][name] += row["scheduler_budget_mbps"]
                if row["resource_type"] == "GBR_EMULATED":
                    base["forward_gbr_budgets_mbps"][name] += row["scheduler_budget_mbps"]
    base.update(policy="joint-guard-weight-comparison-v1", joint_selection=True, guard_enabled=True,
        weight_mode=weight_mode, relay_weights=weights, fixed_weights=list(FIXED_WEIGHTS),
        guard_capacities_mbps=caps, guarded_relays=guarded, discharge_caps_mbps=discharge_caps,
        guard_blocks_feasible_voice=bool(base["classes"][0]["admitted"] is False
            and plan_protected(params, states, scenario)["classes"][0]["admitted"]),
        selection_priority="VOICE admission; VIDEO full/degraded/rejected; VOICE cost; VIDEO cost",
        scope="Replanned assignment; no QoS or energy result")
    validate(base)
    return base
