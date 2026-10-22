"""Manage synthetic battery snapshots read by the LivePaths controller."""

import argparse
import os
from pathlib import Path
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import params as P
from core.lab_scenario import STATES
from core.state_store import load_state, save_state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path,
                        default=Path(PROJECT_ROOT) / "config" / "runtime_state.json")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create the file from the current lab STATES")
    commands.add_parser("show", help="Display the stored snapshot")
    change = commands.add_parser("set", help="Set one synthetic battery fraction")
    change.add_argument("drone", type=str.upper, choices=P.DRONES)
    change.add_argument("energy", type=float, help="Fraction from 0 to 1, not percent")
    args = parser.parse_args()

    try:
        if args.command == "init":
            if args.file.exists():
                raise ValueError("State file already exists; use show or set")
            document = {
                "schema": 1, "revision": 0,
                "states": {drone: dict(STATES[drone]) for drone in P.DRONES},
            }
            document = save_state(args.file, document, P.DRONES)
        else:
            document = load_state(args.file, P.DRONES)
            if args.command == "set":
                document["states"][args.drone]["energy_fraction"] = args.energy
                document["revision"] += 1
                document = save_state(args.file, document, P.DRONES)
    except (OSError, ValueError) as error:
        parser.exit(2, "Error: %s\n" % error)

    print("Synthetic state file:", args.file)
    print("Revision:", document["revision"])
    for drone in P.DRONES:
        state = document["states"][drone]
        print("%s: battery=%.1f%%, carbon_norm=%.3f" %
              (drone, state["energy_fraction"] * 100, state["carbon_norm"]))
    print("This command updates the state file; routing depends on the running controller.")


if __name__ == "__main__":
    main()
