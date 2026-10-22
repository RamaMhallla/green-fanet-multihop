"""Offline battery-policy acceptance checks against the user's actual lab graph.

Run as normal user; no sudo, controller or running topology required.
No state, topology, flow, meter or qdisc is changed. A JSON report is saved
under results/battery-policy-checks/<unique-id>. This is not a traffic test.
"""

import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import uuid

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import params as P
from core.lab_scenario import STATES, TRAFFIC_CLASSES
from core.battery_policy import DEFAULT_CONFIG, plan_protected, plan_signature


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_plan(plan):
    blocked = set(plan["blocked_relays"])
    require(plan["enforcement"] == "NOT_INSTALLED", "Offline result mislabeled as enforced")
    for row in plan["classes"]:
        if row["admitted"]:
            require(not blocked.intersection(row["path"]), "Protected flow traverses weak/dead UAV")
            require(row["configured_delay_ms"] <= row["delay_budget_ms"], "Configured delay exceeds budget")
    for relay, allocation in plan["forward_scheduler_allocations_mbps"].items():
        require(allocation <= plan["usable_capacities_mbps"][relay] + 1e-9,
                "Allocation exceeds usable capacity at " + relay)
        require(plan["forward_gbr_budgets_mbps"][relay] <= allocation + 1e-9,
                "GBR budget exceeds total allocation")


def main():
    report = {"schema": 1, "status": "starting", "policy": "battery-protection-v1-offline",
              "scope": "Offline model check only; no running network changes", "source_sha256": {}}
    for relative in ("core/model.py", "core/lab_scenario.py", "core/battery_policy.py",
                     "config/params.py", "sim/check_battery_policy.py"):
        path = PROJECT_ROOT / relative
        report["source_sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = PROJECT_ROOT / "results" / "battery-policy-checks" / (stamp + "-" + uuid.uuid4().hex[:12])
    directory.mkdir(parents=True, exist_ok=False)
    print("Results:", directory)
    try:
        profiles = {row["name"]: row for row in TRAFFIC_CLASSES}
        for name, payload, dscp, delay in (("VOICE", 1.2, 46, 100), ("VIDEO", 4.2, 34, 150)):
            row = profiles[name]
            require((row["demand_mbps"], row["dscp"], row["budget_ms"]) == (payload, dscp, delay),
                    "Current " + name + " profile differs from the explicitly configured protection profile")
        require(P.UAV_BW_MBPS == 5, "A/B check expects the current 5 Mbps UAV capacities")
        report["scenarios"] = {}
        for scenario in ("A", "B"):
            plans = {}
            print("\nSCENARIO", scenario)
            if scenario == "B":
                print("OFFLINE ONLY: additional logical edge u1--UAV3; all UAV capacities stay 5 Mbps.")
            for label, energy in (("initial", .90), ("weak", .10), ("failed", 0.0)):
                snapshot = {name: dict(value) for name, value in STATES.items()}
                snapshot["UAV1"]["energy_fraction"] = energy
                plan = plan_protected(P, snapshot, scenario)
                validate_plan(plan)
                plans[label] = plan
                print("UAV1=%.0f%%; excluded=%s" % (100*energy, plan["blocked_relays"]))
                for row in plan["classes"]:
                    if row["admitted"]:
                        print("  %s: PLANNED %s | %s | scheduler budget %.2f Mbps" %
                              (row["name"], row["decision"], " -> ".join(row["path"]),
                               row["scheduler_budget_mbps"]))
                    else:
                        print("  %s: PLANNED %s (%s)" % (row["name"], row["decision"], row["reason"]))
            initial, weak, failed = (plans[label] for label in ("initial", "weak", "failed"))
            require(all(row["admitted"] and row["resource_type"] == "GBR_EMULATED"
                        for row in initial["classes"]), scenario + ": initial full admission failed")
            require(any("UAV1" in row["path"] for row in initial["classes"]),
                    scenario + ": frozen initial baseline does not use UAV1; outage comparison would differ")
            require(weak["classes"][0]["admitted"], scenario + ": voice cannot be admitted after exclusion")
            expected = "VIDEO_DOWNGRADED" if scenario == "A" else "VIDEO_ADMITTED_FULL"
            require(weak["classes"][1]["decision"] == expected,
                    scenario + ": actual graph does not produce the declared video decision")
            require(plan_signature(weak) == plan_signature(failed),
                    scenario + ": weak/failed plans differ; expected no protected path change at zero")
            require(weak["forward_scheduler_allocations_mbps"]["UAV1"] == 0,
                    scenario + ": weak UAV1 still has planned test traffic")
            # A future FIXED arm freezes this exact common initial plan. This
            # checker never claims that such frozen paths remain feasible.
            affected = [row["name"] for row in initial["classes"] if "UAV1" in row["path"]]
            print("  Frozen common initial plan would retain UAV1 for:", ", ".join(affected))
            report["scenarios"][scenario] = {"plans": plans,
                "fixed_baseline": "Freeze the common initial plan and profile; never replan on battery events",
                "fixed_flows_using_failed_uav": affected}
        report["status"] = "passed"
        print("\nPOLICY MODEL CHECK: PASS (offline only)")
    except (KeyError, TypeError, ValueError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        print("\nPOLICY MODEL CHECK: FAIL:", error, file=sys.stderr)
    finally:
        report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        (directory / "policy-check.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
        print("Saved:", directory / "policy-check.json")
        print("No flows, meters, queues or link failures were installed. Live enforcement is a separate stage.")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
