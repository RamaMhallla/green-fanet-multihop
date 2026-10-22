"""Experimental subclass: same OpenFlow transaction engine, joint planner.

History is derived only from the last confirmed plan, including no-flow-change
revisions. No speculative planning result is committed before its transaction.
This controller is for the separate bounded functional check, not production.
"""
import copy
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from controller import battery_paths as legacy
from core.joint_battery_policy import plan_joint_protected


class JointBatteryPaths(legacy.BatteryPaths):
    def _plan(self, document):
        if self.initial_plan is None:
            if document["states"]["UAV1"]["energy_fraction"] != .90:
                raise ValueError("The common initial plan requires UAV1 at 90%")
            self.initial_plan = legacy.plan_protected(legacy.P, document["states"], self.scenario)
            plan = copy.deepcopy(self.initial_plan)
        elif self.mode == "fixed":
            plan = copy.deepcopy(self.initial_plan)
        else:
            plan = plan_joint_protected(legacy.P, document["states"], self.scenario,
                                        self.applied_plan or self.initial_plan)
            if plan.get("guard_blocks_feasible_voice"):
                raise ValueError("Experimental guard would reject otherwise feasible VOICE; candidate update refused")
        for row in plan["classes"]:
            if row["admitted"]:
                legacy.validate_relays(row["path"][1:-1], self.scenario)
        return plan
