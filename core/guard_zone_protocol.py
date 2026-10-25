"""Declared 28% start / 30% allocation-guard experiment; no I/O."""
import copy

from core.lab_scenario import STATES
from core.feedback_guard_policy import shared_guard_initial, plan_feedback_guard, guard_definition
from core.weight_comparison_policy import weights_for
from core.joint_battery_policy import require, validate
from core.model import uav_cost

PROTOCOL = "guard-zone-energy-feedback-v1"
INITIAL_UAV1 = .28
GUARD_ACTIVATION = .30
DURATION_S = 40
DEFINITION = guard_definition("battery_zone", GUARD_ACTIVATION)


def initial_states(params):
    require(set(params.DRONES) == set(STATES), "Initial-state relay set differs")
    state = copy.deepcopy(STATES)
    state["UAV1"]["energy_fraction"] = INITIAL_UAV1
    return state


def annotate(plan):
    plan.update(policy=PROTOCOL, enforcement="PLAN_ONLY_CONTROLLER_CONFIRMATION_SEPARATE",
        scope="Calculated 30% guard assignment. Controller confirmation and packet measurements are separate; no QoS/energy/lifetime guarantee.")
    return plan


def initial_zone_plan(params, states, scenario, weight_mode):
    require(states == initial_states(params), "This protocol requires its declared common 28% initial state")
    weights = weights_for(states, weight_mode)
    plan = shared_guard_initial(params, states, scenario)
    # Paths/profiles are identical in both arms. Recalculate the COST of that
    # supplied assignment using each arm's actual weights, without reoptimising.
    for row in plan["classes"]:
        row["cost"] = sum(uav_cost(params.UAV_DELAY_MS, states[n]["energy_fraction"],
            states[n]["carbon_norm"], row["delay_budget_ms"], weights[n]) for n in row["path"][1:-1])
    plan.update(weight_mode=weight_mode, relay_weights=weights, joint_selection=True,
        guard_enabled=True, guard_definition=copy.deepcopy(DEFINITION),
        guard_capacities_mbps=dict(plan["usable_capacities_mbps"]),
        guarded_relays={}, discharge_caps_mbps={}, guard_blocks_feasible_voice=False,
        initial_assignment_rule="Same supplied full assignment in both arms; guard ceilings start on first discharge update")
    validate(plan)
    return annotate(plan)


def next_zone_plan(params, states, scenario, previous, weight_mode):
    plan = plan_feedback_guard(params, states, scenario, previous, weight_mode,
                               "battery_zone", GUARD_ACTIVATION)
    return annotate(plan)
