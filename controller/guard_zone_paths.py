"""Zone-guard planning on the existing VLAN/barrier enforcement engine."""
import copy
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from controller import battery_paths as engine
from core.guard_zone_protocol import PROTOCOL, DEFINITION, initial_zone_plan, next_zone_plan


class GuardZonePaths(engine.BatteryPaths):
    def _plan(self, document):
        if self.mode != "adaptive":
            raise ValueError("Both weight arms must use the replanning engine")
        if os.environ.get("FANET_GUARD_ZONE_PROTOCOL") != PROTOCOL:
            raise ValueError("Start this controller only with run_guard_zone_feedback.py")
        mode = os.environ.get("FANET_COST_WEIGHTS")
        if mode not in ("fixed", "adaptive"):
            raise ValueError("Explicit fixed/adaptive cost-weight mode required")
        if self.initial_plan is None:
            if document["revision"] != 0:
                raise ValueError("Initial revision must be zero")
            self.initial_plan = initial_zone_plan(engine.P, document["states"], self.scenario, mode)
            plan = copy.deepcopy(self.initial_plan)
        else:
            plan = next_zone_plan(engine.P, document["states"], self.scenario,
                                  self.applied_plan or self.initial_plan, mode)
        if plan["guard_definition"] != DEFINITION:
            raise ValueError("Guard configuration differs from the declared protocol")
        if not all(row["admitted"] for row in plan["classes"]):
            raise ValueError("Bounded zone integration trial would reject a service; update refused")
        for row in plan["classes"]:
            engine.validate_relays(row["path"][1:-1], self.scenario)
        logger = getattr(self, "logger", None)
        if logger is not None:
            logger.info("GUARD_ZONE protocol=%s routing=REPLAN weights=%s activation=0.30", PROTOCOL, mode)
        return plan
