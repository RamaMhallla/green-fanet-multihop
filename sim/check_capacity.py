"""Print the same synthetic forward admission plan used by CostPaths."""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import params as P
from core.lab_scenario import plan_forward


def main():
    plan = plan_forward(P)
    print("SYNTHETIC CAPACITY + DELAY CHECK: forward direction only.")
    print("No OpenFlow rules or real bandwidth reservations are installed.")
    for record in plan["classes"]:
        name = record["name"]
        if not record["admitted"]:
            print("\n%s: REJECTED (%s)" % (name, record["reason"]))
            continue
        print("\n%s: requested %.1f Mbps" % (name, record["demand_mbps"]))
        print("Path:", " -> ".join(record["path"]))
        print("Cost: %.3f" % record["cost"])
        print("Configured one-way delay: %.1f / %.1f ms (PASS)" %
              (record["delay_ms"], record["budget_ms"]))

    print("\nForward reservations:")
    for drone in P.DRONES:
        capacity = plan["capacities"][drone]
        reserved = plan["reservations"]["forward"][drone]
        print("%s: reserved %.1f / %.1f Mbps, free %.1f Mbps" %
              (drone, reserved, capacity, capacity - reserved))
    print("Reverse reservations are still zero.")
    print("Delay check uses configured delays, not measured queueing delay.")


if __name__ == "__main__":
    main()
