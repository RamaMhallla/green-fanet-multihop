"""Offline, forward-only admission policy for the battery-protection experiment.

Nothing in this module installs flows, meters, queues or link failures. It is
5G-inspired lab admission, not a 5GC or a guarantee of measured QoS. The static
baseline must freeze the SAME initial plan; it must not call this planner on
subsequent battery events. Recruiting/GWO is outside this policy.
"""

from dataclasses import asdict, dataclass
import math

from core.model import NoFeasiblePath, adaptive_weights, capacity_filtered_links, feasible_path, uav_cost


@dataclass(frozen=True)
class ProtectionConfig:
    weak_battery_threshold: float = 0.20
    relay_headroom_mbps: float = 0.10
    voice_payload_mbps: float = 1.20
    voice_scheduler_budget_mbps: float = 1.30
    video_payload_mbps: float = 4.20
    video_full_scheduler_budget_mbps: float = 4.40
    video_degraded_cap_mbps: float = 3.60
    voice_delay_budget_ms: float = 100.0
    video_delay_budget_ms: float = 150.0

    def validate(self):
        values = asdict(self)
        if any(isinstance(value, bool) or not isinstance(value, (int, float))
               or not math.isfinite(value) for value in values.values()):
            raise ValueError("Policy settings must be finite numbers")
        if not 0 <= self.weak_battery_threshold <= 1:
            raise ValueError("Battery threshold must be within [0, 1]")
        if self.relay_headroom_mbps < 0:
            raise ValueError("Relay headroom must be nonnegative")
        if any(value <= 0 for name, value in values.items()
               if name not in ("weak_battery_threshold", "relay_headroom_mbps")):
            raise ValueError("Rates and delay budgets must be positive")
        if self.voice_scheduler_budget_mbps < self.voice_payload_mbps:
            raise ValueError("Voice scheduler budget cannot be below requested payload rate")
        if self.video_full_scheduler_budget_mbps < self.video_payload_mbps:
            raise ValueError("Full video scheduler budget cannot be below requested payload rate")
        if self.video_degraded_cap_mbps >= self.video_full_scheduler_budget_mbps:
            raise ValueError("Degraded video cap must be below the full video scheduler budget")


DEFAULT_CONFIG = ProtectionConfig()
DRONES = {"UAV1", "UAV2", "UAV3", "UAV4"}


def scenario_links(params, scenario):
    """B adds a logical u1--UAV3 edge; A uses the original logical graph.

    Capacities remain unchanged. B changes possible hop counts, so experiments
    must compare FIXED/ADAPTIVE within each scenario, not pool A and B results.
    These logical links do not create physical links or change the running lab.
    """
    if scenario not in ("A", "B"):
        raise ValueError("Scenario must be A or B")
    links, seen = [], set()
    allowed = DRONES | {"u1", "gs"}
    for link in params.LOGICAL_LINKS:
        if not isinstance(link, (tuple, list)) or len(link) != 2:
            raise ValueError("Each logical link must have exactly two endpoints")
        first, second = link
        if first not in allowed or second not in allowed or first == second:
            raise ValueError("Unexpected node or self-loop in the logical graph")
        key = frozenset((first, second))
        if key in seen:
            raise ValueError("Duplicate undirected logical link")
        links.append((first, second))
        seen.add(key)
    additions = []
    if scenario == "B":
        if frozenset(("u1", "UAV3")) in seen:
            raise ValueError("B requires u1--UAV3 to be an additional link, not already present in A")
        additions = [("u1", "UAV3")]
        links.extend(additions)
    return links, additions


def _snapshot(params, states, config):
    config.validate()
    if set(params.DRONES) != DRONES or len(params.DRONES) != len(DRONES):
        raise ValueError("This policy expects the current four UAVs")
    if not {"u1", "gs"} <= set(params.HOSTS):
        raise ValueError("Source u1 and destination gs must exist")
    if set(states) != DRONES:
        raise ValueError("Battery/carbon states must cover exactly the four UAVs")
    snapshot = {}
    for name in params.DRONES:
        row = {}
        for key in ("energy_fraction", "carbon_norm"):
            value = states[name][key]
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or not 0 <= value <= 1):
                raise ValueError("Invalid " + key + " for " + name)
            row[key] = float(value)
        snapshot[name] = row
    capacity, delay = params.UAV_BW_MBPS, params.UAV_DELAY_MS
    if (isinstance(capacity, bool) or not isinstance(capacity, (int, float))
            or not math.isfinite(capacity) or capacity <= 0):
        raise ValueError("Relay capacity must be positive and finite")
    if (isinstance(delay, bool) or not isinstance(delay, (int, float))
            or not math.isfinite(delay) or delay < 0):
        raise ValueError("Configured relay delay must be nonnegative and finite")
    return snapshot


def plan_protected(params, states, scenario="A", config=DEFAULT_CONFIG):
    """Admit VOICE first; then try full VIDEO, then one explicit BE profile.

    Every protected test flow, including downgraded video, excludes weak/dead
    UAVs. This deliberate rule is stricter than excluding only GBR flows.
    Best-effort use of weak UAVs by other traffic is not implemented here.
    Forward scheduler allocations and GBR budgets are distinct: a capped BE
    video flow consumes planned peak capacity but receives no GBR reservation.
    No caller data is changed. Cost minimization is per priority class, not a
    global optimization over all assignments.
    """
    state = _snapshot(params, states, config)
    links, additions = scenario_links(params, scenario)
    blocked = sorted(name for name, row in state.items()
                     if row["energy_fraction"] == 0
                     or row["energy_fraction"] < config.weak_battery_threshold)
    links = [(a, b) for a, b in links if a not in blocked and b not in blocked]
    capacities = {name: float(params.UAV_BW_MBPS) for name in params.DRONES}
    usable = {name: max(0.0, value-config.relay_headroom_mbps)
              for name, value in capacities.items()}
    allocated = {name: 0.0 for name in params.DRONES}
    gbr = {name: 0.0 for name in params.DRONES}
    weights = {name: adaptive_weights(row["energy_fraction"]) for name, row in state.items()}

    def find(budget_mbps, delay_budget_ms):
        available = capacity_filtered_links(links, usable, allocated, budget_mbps)

        def delay(first, second):
            return params.UAV_DELAY_MS if second in DRONES else 0.0

        def cost(first, second):
            if second not in DRONES:
                return 0.0
            row = state[second]
            return uav_cost(params.UAV_DELAY_MS, row["energy_fraction"],
                            row["carbon_norm"], delay_budget_ms, weights[second])

        return feasible_path(available, "u1", "gs", cost, delay, delay_budget_ms)

    def commit(record, solution, budget, resource_type, meter_cap):
        path, cost, delay = solution
        for relay in path[1:-1]:
            allocated[relay] += budget
            if resource_type == "GBR_EMULATED":
                gbr[relay] += budget
        record.update(admitted=True, path=path, cost=cost, configured_delay_ms=delay,
                      resource_type=resource_type, scheduler_budget_mbps=budget,
                      meter_cap_mbps=meter_cap,
                      gbr_payload_mbps=(record["requested_payload_mbps"]
                                        if resource_type == "GBR_EMULATED" else 0.0))

    voice = {"name": "VOICE", "dscp": 46, "admission_rank": 1,
             "reference_5qi": 1, "preemption_vulnerable": False,
             "requested_payload_mbps": config.voice_payload_mbps,
             "delay_budget_ms": config.voice_delay_budget_ms}
    try:
        solution = find(config.voice_scheduler_budget_mbps, config.voice_delay_budget_ms)
    except NoFeasiblePath as error:
        voice.update(admitted=False, decision="VOICE_REJECTED", reason=str(error))
    else:
        commit(voice, solution, config.voice_scheduler_budget_mbps, "GBR_EMULATED", None)
        voice["decision"] = "VOICE_ADMITTED"

    video = {"name": "VIDEO", "dscp": 34, "admission_rank": 2,
             "reference_5qi": 2, "preemption_vulnerable": True,
             "requested_payload_mbps": config.video_payload_mbps,
             "delay_budget_ms": config.video_delay_budget_ms}
    try:
        solution = find(config.video_full_scheduler_budget_mbps, config.video_delay_budget_ms)
    except NoFeasiblePath as full_error:
        try:
            solution = find(config.video_degraded_cap_mbps, config.video_delay_budget_ms)
        except NoFeasiblePath as degraded_error:
            video.update(admitted=False, decision="VIDEO_REJECTED",
                         reason=str(degraded_error), full_profile_rejection=str(full_error))
        else:
            commit(video, solution, config.video_degraded_cap_mbps, "NON_GBR_EMULATED",
                   config.video_degraded_cap_mbps)
            # The 5QI metadata is a GBR reference only; it is not retained as
            # a claim that this downgraded profile is standardized 5QI 2.
            video["reference_5qi"] = None
            video.update(decision="VIDEO_DOWNGRADED", full_profile_rejection=str(full_error),
                         downgrade_reason="No healthy capacity/delay-feasible full video path")
    else:
        commit(video, solution, config.video_full_scheduler_budget_mbps, "GBR_EMULATED",
               config.video_full_scheduler_budget_mbps)
        video["decision"] = "VIDEO_ADMITTED_FULL"

    return {
        "schema": 1, "policy": "battery-protection-v1-offline", "scenario": scenario,
        "enforcement": "NOT_INSTALLED", "config": asdict(config), "states": state,
        "logical_links": [list(link) for link in scenario_links(params, scenario)[0]],
        "added_logical_links": [list(link) for link in additions], "blocked_relays": blocked,
        "capacities_mbps": capacities, "usable_capacities_mbps": usable,
        "forward_scheduler_allocations_mbps": allocated,
        "forward_gbr_budgets_mbps": gbr, "classes": [voice, video],
        "accounting": {
            "requests": "UDP payload Mbps",
            "budgets": "Configured tc/meter Mbps, distinct from requested payload Mbps",
            "headroom": "Explicit lab assumptions, requiring live frame/accounting verification",
            "reverse": "Not admitted/reserved by this forward-only policy",
        },
        "transition_requirements": [
            "Install and verify real bottleneck queues and new internal rules/meters",
            "Apply and confirm the video profile before moving voice onto a shared bottleneck",
            "Activate voice ingress and confirm its barrier before reporting policy ready",
        ],
        "scope": "Planned admission only; no OpenFlow/tc actions, media adaptation, QoS proof, energy drain or recruiting",
    }


def plan_signature(plan):
    """A rate/profile-only change must trigger a future controller transaction."""
    return tuple((row["name"], row["admitted"], tuple(row.get("path", ())),
                  row.get("resource_type"), row.get("scheduler_budget_mbps"),
                  row.get("meter_cap_mbps"), row.get("gbr_payload_mbps"))
                 for row in plan["classes"])
