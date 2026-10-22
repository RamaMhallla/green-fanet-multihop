"""Offline 3x2 planner family: same costs, budgets, exclusion and tie order.

Greedy fixes the cheapest feasible VOICE route before selecting VIDEO.
Joint searches all feasible VOICE/VIDEO pairs, preferring full VIDEO first.
The persistent discharge guard is the same as the current joint candidate.
No live planner, controller or runtime state is changed.
"""
from core.battery_policy import DEFAULT_CONFIG, plan_protected, scenario_links
from core.joint_battery_policy import all_paths, allocations, validate, require
from core.weight_comparison_policy import weights_for
from core.model import uav_cost

METHODS=("greedy","greedy_guard","joint_guard")


def plan_family(params, states, scenario, previous, method, weight_mode):
    require(method in METHODS,"Unknown planner method")
    weights_for(states,weight_mode)
    base=plan_protected(params,states,scenario)
    unguarded_voice=base["classes"][0]["admitted"]
    config=DEFAULT_CONFIG
    state=base["states"]
    guard=method!="greedy"
    joint=method=="joint_guard"
    caps=dict(base["usable_capacities_mbps"])
    guarded,discharge_caps={},{}
    if guard:
        require(previous["scenario"]==scenario and previous["config"]==base["config"],"Previous scenario/configuration differs")
        require(set(previous["states"])==set(params.DRONES),"Previous UAV set differs")
        old=allocations(previous)
        for name in params.DRONES:
            energy,prior=state[name]["energy_fraction"],previous["states"][name]["energy_fraction"]
            prior_cap=previous.get("discharge_caps_mbps",{}).get(name)
            if energy<prior or (energy==prior and prior_cap is not None):
                ceiling=old[name] if prior_cap is None else min(old[name],prior_cap)
                caps[name]=min(caps[name],ceiling)
                discharge_caps[name]=caps[name]
                guarded[name]={"previous_energy_fraction":prior,"current_energy_fraction":energy,
                    "previous_budget_mbps":old[name],"new_budget_ceiling_mbps":caps[name],
                    "cause":"battery_decline" if energy<prior else "held_on_plateau"}
    blocked=set(base["blocked_relays"])
    links=[(a,b) for a,b in scenario_links(params,scenario)[0] if a not in blocked and b not in blocked]
    weights=weights_for(state,weight_mode)

    def paths(delay_budget):
        rows=[]
        for path,delay in all_paths(links,params.UAV_DELAY_MS,delay_budget,set(params.DRONES)):
            cost=sum(uav_cost(params.UAV_DELAY_MS,state[n]["energy_fraction"],state[n]["carbon_norm"],
                              delay_budget,weights[n]) for n in path[1:-1])
            rows.append({"path":path,"configured_delay_ms":delay,"cost":cost})
        return sorted(rows,key=lambda r:r["cost"])

    def fits(voice,video,budget):
        used={n:0.0 for n in params.DRONES}
        for route,value in ((voice,config.voice_scheduler_budget_mbps),(video,budget)):
            if route is not None:
                for n in route["path"][1:-1]:used[n]+=value
        return all(used[n]<=caps[n]+1e-9 for n in used)

    voices=[r for r in paths(config.voice_delay_budget_ms) if fits(r,None,0)]
    videos=paths(config.video_delay_budget_ms)
    voice,video,budget=(voices[0] if voices else None),None,0.0
    if voices:
        considered=voices if joint else voices[:1]
        for amount in (config.video_full_scheduler_budget_mbps,config.video_degraded_cap_mbps):
            pairs=[(v,w) for v in considered for w in videos if fits(v,w,amount)]
            if pairs:
                voice,video=min(pairs,key=lambda pair:(pair[0]["cost"],pair[1]["cost"]))
                budget=amount
                break

    def flow(name,route,amount):
        is_voice=name=="VOICE"
        degraded=not is_voice and amount==config.video_degraded_cap_mbps
        row={"name":name,"dscp":46 if is_voice else 34,"admission_rank":1 if is_voice else 2,
            "preemption_vulnerable":not is_voice,"reference_5qi":1 if is_voice else None if degraded else 2,
            "requested_payload_mbps":config.voice_payload_mbps if is_voice else config.video_payload_mbps,
            "delay_budget_ms":config.voice_delay_budget_ms if is_voice else config.video_delay_budget_ms,
            "admitted":route is not None}
        if route is None:
            row.update(decision=name+"_REJECTED",reason="No compatible assignment for this planner family member")
        else:
            row.update(route)
            row.update(resource_type="NON_GBR_EMULATED" if degraded else "GBR_EMULATED",
                scheduler_budget_mbps=amount,meter_cap_mbps=None if is_voice else amount,
                gbr_payload_mbps=0.0 if degraded else row["requested_payload_mbps"],
                decision="VOICE_ADMITTED" if is_voice else "VIDEO_DOWNGRADED" if degraded else "VIDEO_ADMITTED_FULL")
        return row

    classes=[flow("VOICE",voice,config.voice_scheduler_budget_mbps),flow("VIDEO",video,budget)]
    base.update(classes=classes,forward_scheduler_allocations_mbps={n:0.0 for n in params.DRONES},
        forward_gbr_budgets_mbps={n:0.0 for n in params.DRONES})
    for row in classes:
        if row["admitted"]:
            for name in row["path"][1:-1]:
                base["forward_scheduler_allocations_mbps"][name]+=row["scheduler_budget_mbps"]
                if row["resource_type"]=="GBR_EMULATED":base["forward_gbr_budgets_mbps"][name]+=row["scheduler_budget_mbps"]
    base.update(policy="planner-decision-map-v1",method=method,weight_mode=weight_mode,
        relay_weights=weights,joint_selection=joint,guard_enabled=guard,
        guard_capacities_mbps=caps,guarded_relays=guarded,discharge_caps_mbps=discharge_caps,
        guard_blocks_feasible_voice=bool(guard and unguarded_voice and voice is None),
        scope="OFFLINE decisions, not QoS/energy measurements or a live controller change")
    validate(base)
    return base
