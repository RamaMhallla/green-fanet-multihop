"""Offline counter/model/planner rehearsal; no network tools are called."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT/"sim")]
from config import params as P
from core.guard_zone_protocol import initial_states, initial_zone_plan, next_zone_plan
from core.energy_feedback import BatteryLedger, load_profile, require
from core.battery_policy import plan_signature


def counter_snapshot(seconds, cumulative_bytes):
    """Ideal synthetic one-way workload only. Counts are not measurements."""
    stamp = 1_000_000_000+round(seconds*1e9)
    result = {}
    for index, name in enumerate(P.DRONES):
        interfaces = {}
        for port in (0, 1):
            row = {"ifindex": 10*index+port+1, "address": "02:00:00:00:%02x:%02x" % (index, port)}
            for direction in ("rx", "tx"):
                amount = int(cumulative_bytes[name]) if (direction, port) in (("rx", 0), ("tx", 1)) else 0
                row.update({direction+"_bytes": amount, direction+"_packets": amount//1200,
                            direction+"_dropped": 0, direction+"_errors": 0})
            interfaces[name.lower()+"-eth"+str(port)] = row
        result[name] = {"container_id": "synthetic-"+name, "container_pid": 100+index,
            "begin": {"monotonic_ns": stamp, "wall_ns": stamp+10**15},
            "end": {"monotonic_ns": stamp+1_000_000, "wall_ns": stamp+10**15+1_000_000},
            "interfaces": interfaces}
    return result


def rehearse(scenario, mode, profile):
    states = initial_states(P)
    previous = initial_zone_plan(P, states, scenario, mode)
    counters = {n: 0.0 for n in P.DRONES}
    ledger = BatteryLedger({"schema": 1, "revision": 0, "states": states}, counter_snapshot(0, counters), profile)
    history = []
    for second in range(5, 41, 5):
        for row in previous["classes"]:
            require(row["admitted"], "Offline rehearsal unexpectedly rejected a service")
            rate = row["requested_payload_mbps"]
            if row["decision"] == "VIDEO_DOWNGRADED":
                rate = min(rate, row["meter_cap_mbps"])
            for name in row["path"][1:-1]:
                counters[name] += rate*1e6*5/8
        snapshot = counter_snapshot(second, counters)
        energy = ledger.advance(snapshot)
        current = next_zone_plan(P, energy["states"], scenario, previous, mode)
        history.append({"second": second, "snapshot": snapshot, "energy": energy,
                        "plan": current, "changed": plan_signature(current) != plan_signature(previous)})
        previous = current
    return history


def main():
    profile, _ = load_profile(ROOT/"config/energy_feedback.reference.json")
    print("OFFLINE synthetic counter/model rehearsal. NO topology, controller, traffic or runtime-state changes.")
    for scenario in ("A", "B"):
        for mode in ("fixed", "adaptive"):
            rows = rehearse(scenario, mode, profile)
            require(all(c["admitted"] for r in rows for c in r["plan"]["classes"]), "Unexpected rejection")
            require(all(r["plan"]["guard_definition"]["activation_fraction"] == .30 for r in rows), "Guard differs")
            changes = [r for r in rows if r["changed"]]
            print("%s %s | UAV1 28%% -> %.3f%% | %d calculated route/profile change(s)" %
                  (scenario, mode, 100*rows[-1]["energy"]["states"]["UAV1"]["energy_fraction"], len(changes)))
            if changes:
                for r in changes:
                    print("  synthetic t=%ds; sampled UAV1=%.3f%%; VIDEO %s" %
                          (r["second"], 100*r["energy"]["states"]["UAV1"]["energy_fraction"],
                           " -> ".join(r["plan"]["classes"][1]["path"])))
    print("GUARD ZONE OFFLINE CHECK: PASS (rehearsal only; no live, QoS or energy-saving result)")


if __name__ == "__main__":
    main()
