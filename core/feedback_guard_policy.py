"""OFFLINE guard comparison. No controller, network, energy or state-file I/O.

Both weight arms use the same exact joint search and priority/tie rules.
Only guard activation differs between declared guard variants. The old policy
is kept untouched, and the strict variant is checked against it separately.
"""
import copy
import math

from core.battery_policy import DEFAULT_CONFIG, plan_protected, scenario_links
from core.joint_battery_policy import allocations, all_paths, require, validate
from core.model import uav_cost
from core.weight_comparison_policy import weights_for

VERSION = "feedback-guard-offline-v1"
EPSILON = 1e-9


def guard_definition(mode, activation_fraction=.30):
    require(mode in ("strict", "battery_zone", "none"), "Unknown guard variant")
    if mode == "battery_zone":
        require(type(activation_fraction) in (int, float) and math.isfinite(activation_fraction)
                and DEFAULT_CONFIG.weak_battery_threshold < activation_fraction <= 1,
                "Guard activation must be above the hard exclusion threshold and <=1")
    return {"mode": mode, "activation_fraction": float(activation_fraction) if mode == "battery_zone" else None}


def shared_guard_initial(params, states, scenario):
    """One identical full initial assignment supplied to every comparison arm.

    Uses the existing initial-plan builder. Initial assignment is a shared
    condition, not separately optimised per weight arm. A 28% initial UAV1 is
    a NEW declared starting condition, not a timed jump from 90% or a battery
    drain measurement. Every run/trajectory needs fresh independent history.
    """
    plan = plan_protected(params, copy.deepcopy(states), scenario)
    require(all(r["admitted"] for r in plan["classes"])
            and plan["classes"][1]["decision"] == "VIDEO_ADMITTED_FULL",
            "Shared full initial assignment is infeasible")
    plan.update(guard_comparison_phase="common_initial_assignment",
                scope="Offline shared starting assignment only")
    return plan


def guard_capacities(params, base, previous, definition):
    require(previous["scenario"] == base["scenario"] and previous["config"] == base["config"],
            "Previous plan scenario/configuration differs")
    require(set(previous["states"]) == set(params.DRONES), "Previous relay set differs")
    if "guard_definition" in previous:
        require(previous["guard_definition"] == definition, "Do not change guard variant/threshold within a history")
    else:
        require(previous.get("guard_comparison_phase") == "common_initial_assignment",
                "Start this comparison with shared_guard_initial, not an unrelated history")
    old = allocations(previous)
    caps = dict(base["usable_capacities_mbps"])
    guarded, discharge_caps = {}, {}
    for name in params.DRONES:
        energy = base["states"][name]["energy_fraction"]
        prior = previous["states"][name]["energy_fraction"]
        prior_cap = previous.get("discharge_caps_mbps", {}).get(name)
        active_zone = (definition["mode"] == "strict" or
            (definition["mode"] == "battery_zone" and energy <= definition["activation_fraction"]))
        # Same discharge/plateau/charge semantics as the old strict guard.
        # Healthy relays outside the zone keep usable capacity even if they
        # hover and their batteries decline. Charging releases the ceiling.
        if active_zone and (energy < prior or (energy == prior and prior_cap is not None)):
            ceiling = min(old[name], prior_cap) if prior_cap is not None else old[name]
            caps[name] = min(caps[name], ceiling)
            discharge_caps[name] = caps[name]
            guarded[name] = {"previous_energy_fraction": prior, "current_energy_fraction": energy,
                "previous_budget_mbps": old[name], "new_budget_ceiling_mbps": caps[name],
                "cause": "battery_decline" if energy < prior else "held_on_plateau"}
    return caps, guarded, discharge_caps


def plan_feedback_guard(params, states, scenario, previous, weight_mode,
                        guard_mode="battery_zone", activation_fraction=.30):
    """Exact joint planner with declared guard activation, for offline audits.

    VOICE admission first; then full VIDEO, degraded VIDEO, or VOICE alone.
    Among compatible pairs, minimise VOICE cost before VIDEO cost. Paths,
    budgets, hard <20% exclusion, cost functions and stable ties are unchanged.
    The strict variant must match plan_weight_comparison on the same history.
    A zone guard can still restrict admission. It is not a universal optimum.
    """
    definition = guard_definition(guard_mode, activation_fraction)
    weights_for(states, weight_mode)
    if "guard_definition" in previous:
        require(previous["weight_mode"] == weight_mode, "Do not switch weight arm within a history")
    base = plan_protected(params, states, scenario)
    unguarded_voice = base["classes"][0]["admitted"]
    caps, guarded, discharge_caps = guard_capacities(params, base, previous, definition)
    config, state = DEFAULT_CONFIG, base["states"]
    relays = set(params.DRONES)
    blocked = set(base["blocked_relays"])
    links = [(a, b) for a, b in scenario_links(params, scenario)[0]
             if a not in blocked and b not in blocked]
    weights = weights_for(state, weight_mode)

    def paths(delay_budget):
        result = []
        for path, delay in all_paths(links, params.UAV_DELAY_MS, delay_budget, relays):
            cost = sum(uav_cost(params.UAV_DELAY_MS, state[n]["energy_fraction"],
                               state[n]["carbon_norm"], delay_budget, weights[n]) for n in path[1:-1])
            result.append({"path": path, "configured_delay_ms": delay, "cost": cost})
        return sorted(result, key=lambda row: row["cost"])

    def fits(voice, video, video_budget):
        used = {n: 0.0 for n in params.DRONES}
        for route, budget in ((voice, config.voice_scheduler_budget_mbps), (video, video_budget)):
            if route is not None:
                for n in route["path"][1:-1]:
                    used[n] += budget
        return all(used[n] <= caps[n] + EPSILON for n in used)

    voices = [p for p in paths(config.voice_delay_budget_ms) if fits(p, None, 0)]
    videos = paths(config.video_delay_budget_ms)
    voice, video, selected = (voices[0] if voices else None), None, 0.0
    if voices:
        for budget in (config.video_full_scheduler_budget_mbps, config.video_degraded_cap_mbps):
            pairs = [(v, w) for v in voices for w in videos if fits(v, w, budget)]
            if pairs:
                voice, video = min(pairs, key=lambda pair: (pair[0]["cost"], pair[1]["cost"]))
                selected = budget
                break

    def flow(name, route, budget):
        is_voice = name == "VOICE"
        degraded = not is_voice and budget == config.video_degraded_cap_mbps
        row = {"name": name, "dscp": 46 if is_voice else 34, "admission_rank": 1 if is_voice else 2,
            "preemption_vulnerable": not is_voice, "reference_5qi": 1 if is_voice else None if degraded else 2,
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
            for n in row["path"][1:-1]:
                base["forward_scheduler_allocations_mbps"][n] += row["scheduler_budget_mbps"]
                if row["resource_type"] == "GBR_EMULATED":
                    base["forward_gbr_budgets_mbps"][n] += row["scheduler_budget_mbps"]
    base.update(policy=VERSION, guard_comparison_phase="replan", guard_definition=definition,
        joint_selection=True, guard_enabled=guard_mode != "none", weight_mode=weight_mode,
        relay_weights=weights, guard_capacities_mbps=caps, guarded_relays=guarded,
        discharge_caps_mbps=discharge_caps,
        guard_blocks_feasible_voice=bool(unguarded_voice and not classes[0]["admitted"]),
        selection_priority="VOICE admission; VIDEO full/degraded/rejected; VOICE cost; VIDEO cost",
        scope="OFFLINE guard candidate only; not installed live; no timed energy drain, QoS, energy saving or lifetime result")
    validate(base)
    return base
