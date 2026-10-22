"""Validated synthetic state snapshots, shared by CLI and future live control."""

import json
import math
import os
from pathlib import Path
import tempfile


def validate_state(document, drones):
    """Validate and copy a complete snapshot; never mutate the caller's data."""
    if not isinstance(document, dict) or set(document) != {"schema", "revision", "states"}:
        raise ValueError("State file must contain schema, revision and states")
    if type(document["schema"]) is not int or document["schema"] != 1:
        raise ValueError("Unsupported state schema (expected 1)")
    revision = document["revision"]
    if type(revision) is not int or revision < 0:
        raise ValueError("Revision must be a nonnegative integer")
    states = document["states"]
    if not isinstance(states, dict) or set(states) != set(drones):
        raise ValueError("State must contain exactly the configured UAV names")
    normalized = {}
    for drone in drones:
        state = states[drone]
        if not isinstance(state, dict) or set(state) != {"energy_fraction", "carbon_norm"}:
            raise ValueError("%s must contain energy_fraction and carbon_norm" % drone)
        normalized[drone] = {}
        for field in ("energy_fraction", "carbon_norm"):
            value = state[field]
            if (type(value) not in (int, float) or not math.isfinite(value)
                    or not 0 <= value <= 1):
                raise ValueError("%s.%s must be a finite number in [0, 1]" %
                                 (drone, field))
            normalized[drone][field] = float(value)
    return {"schema": 1, "revision": revision, "states": normalized}


def load_state(path, drones):
    with Path(path).open(encoding="utf-8") as handle:
        return validate_state(json.load(handle), drones)


def save_state(path, document, drones):
    """Publish one complete snapshot with a same-directory atomic replace.

    This prevents a reader seeing a partly written JSON file. It does not
    provide a lock for concurrent writers; the lab uses one state CLI writer.
    """
    checked = validate_state(document, drones)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(path.parent),
            prefix=path.name + ".", suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(checked, handle, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return checked
