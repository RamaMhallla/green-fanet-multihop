"""Reference-based battery feedback, independent of Docker, Ryu and file I/O.

The aircraft baseline is an effective whole-aircraft hover estimate. It must
not be labelled pure motor power or added to a second platform baseline.
The extra NIC is a separate reference device, not DJI's built-in radio.
"""
import copy
import hashlib
import json
import math
from pathlib import Path

from core.state_store import validate_state
from core.uav_energy_model import snapshot_energy

PROTOCOL = "energy-feedback-joint-guard-v1"
MODEL = "composite-reference-hover-radio-v1"
UPDATE_INTERVAL_S = 5.0
DURATION_S = 40


def require(condition, message):
    if not condition:
        raise ValueError(message)


def positive(value, label, zero=False):
    require(type(value) in (int, float) and math.isfinite(value)
            and (value >= 0 if zero else value > 0), label + ": invalid number")
    return float(value)


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def validate_profile(profile):
    require(isinstance(profile, dict) and type(profile.get("schema")) is int and profile.get("schema") == 1
            and profile.get("model") == MODEL, "Wrong feedback parameter schema/model")
    require(profile.get("status") == "REFERENCE_DERIVED_COMPOSITE",
            "This protocol requires an explicitly reference-derived composite profile")
    require(profile.get("assumptions") == {
        "all_uavs_hovering": True, "extra_radio_powered": True,
        "automatic_landing": False, "battery_feedback": True,
        "linear_state_of_charge": True, "time_acceleration": 1.0},
        "Explicit hovering, linear battery and real-time assumptions required")
    require(isinstance(profile.get("sources"), list) and len(profile["sources"]) >= 2,
            "Aircraft and radio source provenance required")
    for row in profile["sources"]:
        require(isinstance(row, dict) and all(isinstance(row.get(k), str) and row[k].strip()
                for k in ("title", "url", "used_for")), "Source provenance is incomplete")
    nodes = profile.get("uavs")
    names = {"UAV1", "UAV2", "UAV3", "UAV4"}
    require(isinstance(nodes, dict) and set(nodes) == names, "Expected exactly four UAVs")
    fields = {"battery_capacity_j", "aircraft_baseline_w", "radio_idle_w",
              "radio_tx_w", "radio_rx_w", "reference_phy_rate_bps"}
    for name, row in nodes.items():
        require(isinstance(row, dict) and set(row) == fields, "Energy fields differ at " + name)
        for field, value in row.items():
            positive(value, name + "." + field, zero=field.endswith("_w"))
        require(row["radio_tx_w"] >= row["radio_idle_w"]
                and row["radio_rx_w"] >= row["radio_idle_w"], "Radio increments must be nonnegative")
    return copy.deepcopy(profile)


def load_profile(path):
    raw = Path(path).read_bytes()
    return validate_profile(json.loads(raw)), hashlib.sha256(raw).hexdigest()


def counter_parameters(profile):
    """Adapt to the existing validated counter differencer, without a second baseline."""
    profile = validate_profile(profile)
    return {"uavs": {name: {
        "hover_w": p["aircraft_baseline_w"], "platform_w": 0.0,
        "radio_idle_w": p["radio_idle_w"],
        "tx_increment_j_per_bit": (p["radio_tx_w"] - p["radio_idle_w"]) / p["reference_phy_rate_bps"],
        "rx_increment_j_per_bit": (p["radio_rx_w"] - p["radio_idle_w"]) / p["reference_phy_rate_bps"],
    } for name, p in profile["uavs"].items()}}


class BatteryLedger:
    """Cumulative origin-to-current accounting prevents double subtraction.

    Every UAV has its own bracketed counter-read interval. No snapshots are
    interpolated into a common instantaneous observation. Interface byte work
    is not wireless airtime: ACKs, contention, losses/retries and host processing
    power are absent. A depleted UAV is reported, not silently recharged.
    """
    def __init__(self, document, origin, profile):
        self.profile = validate_profile(profile)
        self.initial = validate_state(document, self.profile["uavs"])
        require(set(origin) == set(self.profile["uavs"]), "Origin UAV set differs")
        self.origin = copy.deepcopy(origin)
        self.previous_snapshot = copy.deepcopy(origin)
        self.parameters = counter_parameters(self.profile)
        self.last = None
        self.updates = 0

    def advance(self, current):
        # Consecutive validation detects a reset even if a counter has already
        # risen back above its original value. Origin differences avoid drift.
        snapshot_energy(self.previous_snapshot, current, self.parameters)
        estimate = snapshot_energy(self.origin, current, self.parameters)
        states = copy.deepcopy(self.initial["states"])
        rows = {}
        for name, raw in estimate["per_uav"].items():
            row = copy.deepcopy(raw)
            row["aircraft_baseline_j"] = row.pop("hover_j")
            row.pop("platform_j")
            p = self.profile["uavs"][name]
            initial = self.initial["states"][name]["energy_fraction"]
            used = row["estimated_total_j"]
            prior_used = 0.0 if self.last is None else self.last["per_uav"][name]["estimated_total_j"]
            require(used >= prior_used, "Cumulative energy decreased at " + name)
            lower_e, upper_e = row["energy_bounds_due_to_snapshot_timing_j"]
            fraction = max(0.0, initial - used / p["battery_capacity_j"])
            states[name]["energy_fraction"] = fraction
            row.update(initial_fraction=initial, estimated_fraction=fraction,
                fraction_bounds_due_to_snapshot_timing=[
                    max(0.0, initial - upper_e / p["battery_capacity_j"]),
                    max(0.0, initial - lower_e / p["battery_capacity_j"])],
                increment_since_previous_j=used-prior_used,
                battery_capacity_j=p["battery_capacity_j"],
                estimated_average_w=used / row["duration_s"],
                radio_work_airtime_proxy_s=8*(row["tx_bytes"]+row["rx_bytes"]) / p["reference_phy_rate_bps"],
                depleted=used >= initial*p["battery_capacity_j"])
            require(row["radio_work_airtime_proxy_s"] <= row["duration_bounds_s"][1],
                    "Reference radio workload exceeds one-radio time budget at " + name)
            rows[name] = row
        result = {"update": self.updates+1, "states": states, "per_uav": rows,
            "sum_per_node_interval_energy_j": sum(r["estimated_total_j"] for r in rows.values()),
            "scope": "Estimated energy over each UAV's own interval, not an equal-40s or synchronized mission energy measurement"}
        self.updates += 1
        self.last = copy.deepcopy(result)
        self.previous_snapshot = copy.deepcopy(current)
        return result
