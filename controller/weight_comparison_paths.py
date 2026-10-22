"""Shared OpenFlow engine, replanning in BOTH weight comparison arms."""
import copy
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from controller import battery_paths as legacy
from core.weight_comparison_policy import common_initial, plan_weight_comparison


class WeightComparisonPaths(legacy.BatteryPaths):
    def _plan(self, document):
        # Legacy 'fixed' means frozen, so the legacy engine must remain adaptive.
        if self.mode != "adaptive":
            raise ValueError("Both comparison arms must use the replanning engine")
        weight_mode = os.environ.get("FANET_COST_WEIGHTS")
        if weight_mode not in ("fixed", "adaptive"):
            raise ValueError("FANET_COST_WEIGHTS must explicitly name fixed or adaptive")
        if self.initial_plan is None:
            self.initial_plan = common_initial(legacy.P, document["states"], self.scenario)
            plan = copy.deepcopy(self.initial_plan)
            plan.update(weight_mode=weight_mode, comparison_phase="common_initial_assignment")
        else:
            plan = plan_weight_comparison(legacy.P, document["states"], self.scenario,
                                         self.applied_plan or self.initial_plan, weight_mode)
            if plan.get("guard_blocks_feasible_voice"):
                raise ValueError("Guard would reject otherwise feasible VOICE; update refused")
        for row in plan["classes"]:
            if row["admitted"]:
                legacy.validate_relays(row["path"][1:-1], self.scenario)
        logger = getattr(self,"logger",None)
        if logger is not None:
            logger.info("WEIGHTS_COMPARISON routing=REPLAN weights=%s joint=True guard=True",weight_mode)
        return plan
