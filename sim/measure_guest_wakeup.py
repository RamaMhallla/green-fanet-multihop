"""Bounded normal-priority wake-up probe, not a real-time or whole-VM proof.

Place in ~/green-fanet-multihop/sim and run without sudo. No traffic, Docker,
OVS, controller or Windows operations. Leave topology idle for the first run.
Records monotonic deadlines and actual wake-ups, buffers data in memory, and
writes logs only after measurement. A late wake can reflect guest scheduling,
host scheduling or another delay; it cannot by itself identify the cause.
"""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
import uuid

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def clock_mark():
    before = time.monotonic_ns()
    wall = time.time_ns()
    after = time.monotonic_ns()
    return {"monotonic_ns": before, "wall_ns": wall,
            "wall_sample_bracket_end_ns": after}


def measure(duration_s, period_ms, rows, clock=time.monotonic_ns, sleep=time.sleep):
    """Absolute deadlines; skip missed periods rather than busy catch-up."""
    period = round(period_ms * 1e6)
    origin = clock()
    end = origin + round(duration_s * 1e9)
    target = origin + period
    while target <= end:
        now = clock()
        if now < target:
            sleep((target-now) / 1e9)
        actual = clock()
        if actual < target:
            continue
        late = actual-target
        missed = late // period
        rows.append({"deadline_monotonic_ns": target, "actual_monotonic_ns": actual,
                     "overshoot_ns": late, "missed_periods": missed})
        target += (missed+1) * period
        if actual >= end:
            break
    return origin


def statistics(rows):
    values = sorted(row["overshoot_ns"] / 1e6 for row in rows)
    if not values:
        return {"samples": 0}
    percentile = lambda p: values[max(0, math.ceil(p*len(values))-1)]
    return {"samples": len(values), "maximum_overshoot_ms": values[-1],
            "median_overshoot_ms": percentile(.5), "p99_overshoot_ms": percentile(.99),
            "wakeups_over_20ms": sum(v > 20 for v in values),
            "wakeups_over_100ms": sum(v > 100 for v in values),
            "missed_periods": sum(row["missed_periods"] for row in rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=40)
    parser.add_argument("--period-ms", type=float, default=10)
    parser.add_argument("--label", choices=("idle", "with-traffic"), default="idle",
                        help="Describes the user's setup; this probe never starts traffic")
    args = parser.parse_args()
    if not math.isfinite(args.duration) or not 10 <= args.duration <= 120:
        parser.error("Duration must be 10 through 120 seconds")
    if not math.isfinite(args.period_ms) or not 5 <= args.period_ms <= 100:
        parser.error("Period must be 5 through 100 ms")
    if os.geteuid() == 0:
        parser.error("Run as your normal user, without sudo")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = PROJECT_ROOT / "results/guest-wakeup-probes" / (stamp + "-" + args.label + "-" + uuid.uuid4().hex[:12])
    directory.mkdir(parents=True, exist_ok=False)
    rows = []
    report = {"schema": 1, "status": "measuring", "label": args.label,
              "requested_duration_s": args.duration, "period_ms": args.period_ms,
              "logical_cpus": os.cpu_count(), "python": sys.version,
              "scheduler_policy": os.sched_getscheduler(0),
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "clock": vars(time.get_clock_info("monotonic")),
              "scope": "Wake-up latency of one normal-priority guest process, not a UDP QoS or whole-VM pause diagnosis"}
    print("Results:", directory, flush=True)
    print("Measuring %.0fs with %.0fms deadlines; no traffic is started. Logs are buffered until the end." %
          (args.duration, args.period_ms), flush=True)
    start = clock_mark()
    cpu_start = time.process_time_ns()
    interrupted = False
    try:
        measure(args.duration, args.period_ms, rows)
        report["status"] = "completed"
    except KeyboardInterrupt:
        interrupted = True
        report["status"] = "interrupted"
    finally:
        report["start"] = start
        report["end"] = clock_mark()
        report["probe_cpu_time_s"] = (time.process_time_ns()-cpu_start) / 1e9
        report["observed_duration_s"] = (report["end"]["monotonic_ns"]-start["monotonic_ns"]) / 1e9
        report["statistics"] = statistics(rows)
        with (directory / "wakeups.jsonl").open("w") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
        (directory / "manifest.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print("GUEST WAKE-UP PROBE:", report["status"].upper())
    for key, value in report["statistics"].items():
        print("%s: %s" % (key, round(value, 3) if isinstance(value, float) else value))
    print("Probe CPU time: %.3fs" % report["probe_cpu_time_s"])
    print("These are observed wake-up delays, not a proof of host/VM cause or source acceptance.")
    print("Saved:", directory / "manifest.json")
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
