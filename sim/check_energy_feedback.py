"""Offline feedback arithmetic/planner check; NO Docker, topology or traffic."""
import copy
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "sim")]
from config import params as P
from core.lab_scenario import STATES
from core.battery_policy import plan_signature
from core.weight_comparison_policy import common_initial, plan_weight_comparison
from core.energy_feedback import BatteryLedger, load_profile, require


def synthetic_snapshot(seconds, rates):
    """Explicit ideal workload fixture; counted bytes are NOT measurements."""
    stamp = 1_000_000_000 + int(seconds * 1e9)
    nodes = {}
    for index, name in enumerate(P.DRONES):
        interfaces = {}
        for port in (0, 1):
            row = {"ifindex": 10*index+port+1, "address": "02:00:00:00:%02x:%02x" % (index, port)}
            for direction in ("rx", "tx"):
                byte_count = int(seconds * rates.get(name, 0.0) * 1e6 / 8) if (direction, port) in (("rx", 0), ("tx", 1)) else 0
                row.update({direction+"_bytes": byte_count, direction+"_packets": byte_count//1200,
                            direction+"_dropped": 0, direction+"_errors": 0})
            interfaces[name.lower()+"-eth"+str(port)] = row
        nodes[name] = {"container_id": "offline-"+name, "container_pid": 100+index,
            "begin": {"monotonic_ns": stamp, "wall_ns": stamp+1_000_000_000_000},
            "end": {"monotonic_ns": stamp+1_000_000, "wall_ns": stamp+1_000_001_000_000},
            "interfaces": interfaces}
    return nodes


def workload(plan):
    rates = {n: 0.0 for n in P.DRONES}
    for row in plan["classes"]:
        if row["admitted"]:
            for name in row["path"][1:-1]:
                rates[name] += row["requested_payload_mbps"]
    return rates


def main():
    profile, _ = load_profile(ROOT / "config/energy_feedback.reference.json")
    require(abs(profile["uavs"]["UAV1"]["battery_capacity_j"] - 359640) < 1e-9, "Reference battery differs")
    require(abs(profile["uavs"]["UAV1"]["aircraft_baseline_w"] - .9*359640/1020) < 1e-9, "Reference baseline differs")
    print("OFFLINE ONLY: synthetic counters, real model seconds, no network changes.")
    for scenario in ("A", "B"):
        arms = {}
        for mode in ("fixed", "adaptive"):
            state = copy.deepcopy(STATES)
            state["UAV1"]["energy_fraction"] = .90
            initial = common_initial(P, state, scenario)
            previous = initial
            rates = workload(initial)
            ledger = BatteryLedger({"schema": 1, "revision": 0, "states": state},
                                   synthetic_snapshot(0, rates), profile)
            changes = 0
            for second in range(5, 41, 5):
                energy = ledger.advance(synthetic_snapshot(second, rates))
                plan = plan_weight_comparison(P, energy["states"], scenario, previous, mode)
                changes += plan_signature(plan) != plan_signature(previous)
                require(all(c["admitted"] for c in plan["classes"]), "Unexpected short-check rejection")
                previous = plan
            require(all(0 < energy["states"][n]["energy_fraction"] < state[n]["energy_fraction"] for n in P.DRONES),
                    "All hovering UAV batteries must drain, including unused UAVs")
            # This fixture assumes the original workload remains assigned.
            require(changes == 0, "Synthetic workload replay requires unchanged routes in this initial window")
            arms[mode] = previous
            print("%s %s | 8 state updates | UAV1 %.3f%% -> %.3f%% | route changes %d" %
                  (scenario, mode, 100*state["UAV1"]["energy_fraction"],
                   100*energy["states"]["UAV1"]["energy_fraction"], changes))
        require(plan_signature(arms["fixed"]) == plan_signature(arms["adaptive"]), "Unexpected 40s assignment difference")
    state = copy.deepcopy(STATES)
    state["UAV1"]["energy_fraction"] = .90
    initial = common_initial(P, state, "B")
    changed = copy.deepcopy(state)
    for name in changed:
        changed[name]["energy_fraction"] -= .001
    changed["UAV1"]["energy_fraction"] = .25
    plan = plan_weight_comparison(P, changed, "B", initial, "adaptive")
    require(plan["guard_capacities_mbps"]["UAV2"] == 0, "Strict idle-relay guard was silently changed")
    print("Guard check: a declining, previously unused UAV2 has a zero protected-allocation ceiling.")
    print("The old B offload at 26% is NOT assumed under all-UAV feedback.")
    print("ENERGY FEEDBACK OFFLINE CHECK: PASS (arithmetic/planner only; no live or QoS result)")


if __name__ == "__main__":
    main()
