"""Offline fixed-weight example; battery and carbon inputs are synthetic."""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import params as P
from core.model import shortest_path, uav_cost


def main():
    # Arithmetic examples, not measured batteries or charging-source data.
    states = {
        "UAV1": {"energy_fraction": 0.9, "carbon_norm": 0.2},
        "UAV2": {"energy_fraction": 0.5, "carbon_norm": 0.8},
        "UAV3": {"energy_fraction": 0.8, "carbon_norm": 0.3},
        "UAV4": {"energy_fraction": 0.6, "carbon_norm": 0.7},
    }
    weights = (0.4, 0.4, 0.2)
    delay_budget_ms = 100  # Example one-way budget, not a class configuration.

    if set(P.DRONES) != set(states):
        raise ValueError("This example expects UAV1, UAV2, UAV3 and UAV4")

    def relay_cost(drone):
        state = states[drone]
        return uav_cost(
            delay_ms=P.UAV_DELAY_MS,
            energy_fraction=state["energy_fraction"],
            carbon_norm=state["carbon_norm"],
            delay_budget_ms=delay_budget_ms,
            weights=weights,
        )

    def edge_cost(source, destination):
        # Charge each relay once on entry; its delay is incurred at its egress.
        # Endpoint delays are omitted in this first arithmetic example.
        if destination in P.HOSTS:
            return 0.0
        return relay_cost(destination)

    def show_choice(label):
        print("\n" + label)
        print("Weights:", weights)
        for drone in P.DRONES:
            print("%s: EW=%.2f, cost=%.3f" %
                  (drone, states[drone]["energy_fraction"], relay_cost(drone)))
        path, cost = shortest_path(P.LOGICAL_LINKS, "u1", "gs", edge_cost)
        print("Path:", " -> ".join(path))
        print("Total cost: %.3f" % cost)

    print("SYNTHETIC OFFLINE EXAMPLE; no network rules are changed.")
    print("Configured relay delay: %s ms" % P.UAV_DELAY_MS)
    show_choice("Initial state")

    states["UAV1"]["energy_fraction"] = 0.1
    show_choice("After setting UAV1 battery to 10% (same weights)")


if __name__ == "__main__":
    main()
