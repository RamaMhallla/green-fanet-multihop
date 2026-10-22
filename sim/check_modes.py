"""Compare two weight policies on identical synthetic state snapshots."""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import params as P
from core.lab_scenario import EXPERIMENT_FIXED_WEIGHTS, STATES, plan_forward


def main():
    print("OFFLINE SNAPSHOTS ONLY; no live controller or rules are changed.")
    print("Comparison fixed weights:", EXPERIMENT_FIXED_WEIGHTS)
    print("Adaptive: threshold=0.20, steepness=15, delay/carbon split=70/30.")
    print("Same graph, capacities, delays, states and VOICE-first admission.")
    for energy in (0.90, 0.10):
        snapshot = {drone: dict(state) for drone, state in STATES.items()}
        snapshot["UAV1"]["energy_fraction"] = energy
        print("\nUAV1 battery = %.0f%% (other batteries/carbon unchanged)" %
              (100 * energy))
        for mode in ("fixed", "adaptive"):
            plan = plan_forward(
                P, states=snapshot, weight_mode=mode,
                fixed_weights=EXPERIMENT_FIXED_WEIGHTS,
            )
            print("  %s" % mode.upper())
            for record in plan["classes"]:
                if not record["admitted"]:
                    print("    %s REJECTED: %s" %
                          (record["name"], record["reason"]))
                    continue
                print("    %s: %s | cost=%.3f | delay=%.1f/%.1f ms" %
                      (record["name"], " -> ".join(record["path"]),
                       record["cost"], record["delay_ms"], record["budget_ms"]))
    print("\nCosts use different weights: do not treat them as performance scores.")
    print("Both classes together use all four UAVs in these examples.")
    print("This is not evidence of lower energy/carbon, longer life or better QoS.")
    print("No real battery drain, standby policy or live rerouting is simulated.")


if __name__ == "__main__":
    main()
