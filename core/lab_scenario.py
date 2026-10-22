"""Shared synthetic scenario; battery and carbon values are not telemetry."""

from core.model import (
    NoFeasiblePath, adaptive_weights, capacity_filtered_links,
    feasible_path, uav_cost,
)

# Keep the existing functional-test default for backwards compatibility.
WEIGHTS = (0.4, 0.4, 0.2)
# Comparison baseline: beta=0.20; remaining weight split 70%/30%, as in
# adaptive_weights. These are explicit experiment choices, not tuned results.
EXPERIMENT_FIXED_WEIGHTS = (0.56, 0.20, 0.24)
STATES = {
    "UAV1": {"energy_fraction": 0.1, "carbon_norm": 0.2},
    "UAV2": {"energy_fraction": 0.5, "carbon_norm": 0.8},
    "UAV3": {"energy_fraction": 0.8, "carbon_norm": 0.3},
    "UAV4": {"energy_fraction": 0.6, "carbon_norm": 0.7},
}
# Rates and DSCP mappings are lab choices, not a 5G-core implementation.
TRAFFIC_CLASSES = (
    {"name": "VOICE", "dscp": 46, "demand_mbps": 1.2, "budget_ms": 100},
    {"name": "VIDEO", "dscp": 34, "demand_mbps": 4.2, "budget_ms": 150},
)


def plan_forward(params, states=None, weight_mode="fixed", fixed_weights=WEIGHTS):
    """Plan aggregate classes in u1 -> gs only, starting with zero reservations.

    Demand is the total budget for a DSCP aggregate, not for each IP flow.
    No policing, queues or reverse reservations are installed by this function.
    Caller-supplied state is copied and never changed. Every call computes a
    fresh plan: this is not an in-flight route update or energy evolution.
    weight_mode may be fixed or adaptive. For comparison experiments pass
    EXPERIMENT_FIXED_WEIGHTS explicitly; the live test keeps its old default.
    """
    if weight_mode not in ("fixed", "adaptive"):
        raise ValueError("weight_mode must be 'fixed' or 'adaptive'")
    snapshot = STATES if states is None else states
    snapshot = {drone: dict(state) for drone, state in snapshot.items()}
    if set(params.DRONES) != set(snapshot):
        raise ValueError("This scenario expects UAV1, UAV2, UAV3 and UAV4")
    relay_weights = {
        drone: (adaptive_weights(snapshot[drone]["energy_fraction"])
                if weight_mode == "adaptive" else tuple(fixed_weights))
        for drone in params.DRONES
    }
    capacities = {drone: params.UAV_BW_MBPS for drone in params.DRONES}
    reservations = {
        "forward": {drone: 0.0 for drone in params.DRONES},
        "reverse": {drone: 0.0 for drone in params.DRONES},
    }
    reserved = reservations["forward"]
    classes = []
    for traffic in TRAFFIC_CLASSES:
        record = dict(traffic)
        demand, budget = traffic["demand_mbps"], traffic["budget_ms"]
        available = capacity_filtered_links(
            params.LOGICAL_LINKS, capacities, reserved, demand,
        )

        def edge_delay(source, destination):
            return 0.0 if destination in params.HOSTS else params.UAV_DELAY_MS

        def edge_cost(source, destination):
            if destination in params.HOSTS:
                return 0.0
            state = snapshot[destination]
            return uav_cost(params.UAV_DELAY_MS, state["energy_fraction"],
                            state["carbon_norm"], budget,
                            relay_weights[destination])

        try:
            path, cost, delay = feasible_path(
                available, "u1", "gs", edge_cost, edge_delay, budget,
            )
        except NoFeasiblePath as error:
            record.update(admitted=False, reason=str(error))
        else:
            for relay in path[1:-1]:
                reserved[relay] += demand
            record.update(admitted=True, path=path, cost=cost, delay_ms=delay)
        classes.append(record)
    return {"classes": classes, "capacities": capacities,
            "reservations": reservations, "weight_mode": weight_mode,
            "relay_weights": relay_weights}
