"""Read-only summary of a bounded 5 FIXED + 5 ADAPTIVE UDP batch.

Reports whole-trial receiver results AND the prospectively specified 5--35s
receiver-log window. Includes every selected run and all loss-bearing intervals.
No fractional attribution of an interval that crosses a window boundary.
"""

import argparse
from collections import Counter
import datetime as dt
import json
import math
from pathlib import Path
import re
import statistics
import uuid

from run_udp_trial import receiver_summary

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLASSES = ("VOICE", "VIDEO")
WINDOW = (5.0, 35.0)
T95_DF4 = 2.7764451051977987
ANALYSIS_RECORD = re.compile(
    r"^\[\s*\d+\]\s+([0-9.]+)-\s*([0-9.]+)\s+sec\s+"
    r"[0-9.]+\s+\S+\s+([0-9.]+)\s+([KMG]?bits/sec)\s+"
    r"([0-9.]+)\s+ms\s+([+-]?\d+)\s*/\s*(\d+)\s+"
    r"\(\s*([+-]?[0-9.]+)%\)\s*(sender|receiver)?\s*$"
)


def analysis_records(text):
    """Preserve signed changes in iperf's cumulative missing-packet counter.

    Reordered arrivals can decrease this counter in a later reporting interval.
    This is not negative physical packet loss. Full summaries remain subject
    to nonnegative validation by receiver_summary; no experiment code changes.
    """
    records = []
    units = {"bits/sec": 1, "Kbits/sec": 1e3, "Mbits/sec": 1e6, "Gbits/sec": 1e9}
    for number, line in enumerate(text.splitlines(), 1):
        match = ANALYSIS_RECORD.fullmatch(line)
        if match is None:
            if re.match(r"^\[\s*\d+\]\s+[0-9.]+-\s*[0-9.]+\s+sec\b", line):
                raise ValueError("Unsupported interval format at line %s: %s" % (number, line))
            continue
        start, end, rate, unit, jitter, delta, total, percent, role = match.groups()
        row = {"start_s": finite(float(start), "Interval start"),
               "end_s": finite(float(end), "Interval end"),
               "bitrate_mbps": finite(float(rate), "Interval rate") * units[unit] / 1e6,
               "jitter_ms": finite(float(jitter), "Jitter"),
               "lost_packets": int(delta), "total_packets": int(total),
               "displayed_loss_percent": float(percent), "role": role or "interval",
               "source_line": number}
        if (row["end_s"] < row["start_s"] or not math.isfinite(row["displayed_loss_percent"])
                or row["lost_packets"] > row["total_packets"]
                or (row["role"] != "interval" and row["lost_packets"] < 0)):
            raise ValueError("Invalid UDP counter record at line %s" % number)
        records.append(row)
    return records


def counter_totals(rows):
    return {"missing_counter_net_change": sum(row["lost_packets"] for row in rows),
            "missing_counter_increases": sum(max(row["lost_packets"], 0) for row in rows),
            "late_counter_corrections": sum(-min(row["lost_packets"], 0) for row in rows),
            "reported_sequence_count": sum(row["total_packets"] for row in rows)}


def timestamp(value):
    try:
        parsed = dt.datetime.strptime(value, "%Y%m%dT%H%M%SZ")
        if parsed.strftime("%Y%m%dT%H%M%SZ") != value:
            raise ValueError("Noncanonical timestamp")
    except ValueError:
        raise argparse.ArgumentTypeError("Use UTC timestamp YYYYMMDDTHHMMSSZ")
    return value


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def finite(value, label):
    if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
        raise ValueError("%s must be finite and nonnegative" % label)
    return float(value)


def stats(values):
    if len(values) != 5:
        raise ValueError("Expected exactly five run-level observations")
    for value in values:
        finite(value, "Run statistic")
    mean, sd = statistics.mean(values), statistics.stdev(values)
    half = T95_DF4 * sd / math.sqrt(5)
    return {"mean": mean, "sample_sd": sd, "min": min(values), "max": max(values),
            "approximate_t95_interval": [mean - half, mean + half]}


def phase(row):
    low, high = WINDOW
    if row["end_s"] <= low:
        return "before_5s"
    if row["start_s"] >= high:
        return "after_35s"
    if row["start_s"] >= low and row["end_s"] <= high:
        return "window_5_to_35s"
    return "boundary_crossing"


def window_metrics(rows):
    selected = [row for row in rows if phase(row) == "window_5_to_35s"]
    seconds = sum(row["end_s"] - row["start_s"] for row in selected)
    if not selected or seconds <= 0:
        raise ValueError("No positive-duration complete intervals within 5--35s")
    weighted_rate = sum(row["bitrate_mbps"] * (row["end_s"] - row["start_s"])
                        for row in selected) / seconds
    counters = counter_totals(selected)
    net = counters["missing_counter_net_change"]
    total = counters["reported_sequence_count"]
    jitter = sorted(row["jitter_ms"] for row in selected)
    return {"complete_intervals": len(selected), "covered_seconds": seconds,
            "coverage_fraction_of_30s": seconds / (WINDOW[1] - WINDOW[0]),
            **counters,
            "missing_counter_net_percent": 100.0 * net / total if total else None,
            "time_weighted_displayed_bitrate_mbps": weighted_rate,
            "interval_jitter_snapshot_median_ms": statistics.median(jitter),
            "interval_jitter_snapshot_p95_ms": jitter[math.ceil(.95 * len(jitter)) - 1],
            "interval_jitter_snapshot_max_ms": max(jitter)}


def parse_stream(directory, name, recorded):
    path = directory / (name.lower() + "-server.log")
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        rows = analysis_records(text)
    except ValueError as error:
        raise ValueError("%s/%s: %s" % (directory.name, name, error)) from error
    whole = receiver_summary(text)
    for key in ("lost_packets", "total_packets", "bitrate_mbps", "jitter_ms"):
        if whole[key] != recorded[key]:
            raise ValueError("%s/%s: log and manifest disagree on %s" % (directory.name, name, key))
    intervals = [row for row in rows if row["role"] == "interval"]
    previous_end = 0.0
    for row in intervals:
        if row["start_s"] < previous_end - 0.011:
            raise ValueError("%s/%s: overlapping interval records" % (directory.name, name))
        previous_end = row["end_s"]
    partitions = {key: counter_totals([row for row in intervals if phase(row) == key])
                  for key in ("before_5s", "window_5_to_35s", "after_35s", "boundary_crossing")}
    result = {"whole_receiver": whole, "window": window_metrics(intervals),
              "interval_counters_by_phase": partitions,
              "interval_net_missing_minus_final_loss": sum(r["lost_packets"] for r in intervals) - whole["lost_packets"],
              "sender_summary": recorded["sender"],
              "sender_total_minus_receiver_total": recorded["sender"]["total_packets"] - whole["total_packets"],
              "counter_change_intervals": [dict(row, phase=phase(row),
                                                change_kind="increase" if row["lost_packets"] > 0 else "late_correction")
                                           for row in intervals if row["lost_packets"] != 0]}
    return result


def vmstat_observations(path):
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 19 or not fields[0].isdigit():
            continue
        try:
            rows.append({"run_queue": int(fields[0]), "cpu_idle_percent": int(fields[14]),
                         "swap_in": int(fields[6]), "swap_out": int(fields[7]),
                         "time": dt.datetime.strptime(" ".join(fields[17:19]), "%Y-%m-%d %H:%M:%S")})
        except (ValueError, IndexError):
            continue
    rows = rows[1:]  # First vmstat data row summarizes time since boot.
    if not rows:
        return {"warning": "No usable per-interval vmstat samples"}
    gaps = [(b["time"] - a["time"]).total_seconds() for a, b in zip(rows, rows[1:])]
    return {"samples": len(rows), "minimum_observed_cpu_idle_percent": min(r["cpu_idle_percent"] for r in rows),
            "maximum_observed_run_queue": max(r["run_queue"] for r in rows),
            "largest_timestamp_step_s": max(gaps) if gaps else None,
            "any_swap_activity": any(r["swap_in"] or r["swap_out"] for r in rows),
            "note": "Timestamp gaps/CPU samples describe observations; they do not identify the root cause."}


def load_trial(directory):
    manifest = read_json(directory / "manifest.json")
    if manifest.get("status") != "completed":
        raise ValueError("%s: status=%r; selected failed runs cannot be silently discarded" %
                         (directory.name, manifest.get("status")))
    if manifest.get("trial_protocol") != "udp-v1-container-readiness-gate":
        raise ValueError("%s: unexpected trial protocol" % directory.name)
    mode = manifest["mode"]
    if mode not in ("fixed", "adaptive"):
        raise ValueError("Unknown mode")
    ready = read_json(directory / "topology-ready.json")
    if not ready.get("uavs") or not ready.get("endpoints"):
        raise ValueError("Missing readiness evidence")
    initial = read_json(directory / "state-initial.json")
    event = read_json(directory / "state-event.json")
    if (initial["states"]["UAV1"]["energy_fraction"] != .9
            or event["states"]["UAV1"]["energy_fraction"] != .1):
        raise ValueError("Unexpected battery event")
    data_ready = finite(manifest["both_streams_confirmed_after_first_client_launch_s"], "Data-ready time")
    published = finite(manifest["event_publish_start_offset_s"], "Event offset")
    confirmed = finite(manifest["confirmation_observed_offset_s"], "Confirmation offset")
    if confirmed < published:
        raise ValueError("Confirmation precedes publication")
    epochs = manifest["epochs"]
    if any(type(epochs[key]) is not int or epochs[key] < 0 for key in ("before", "after")):
        raise ValueError("Invalid epoch")
    return {"trial": directory.name, "mode": mode, "epochs": epochs,
            "host_event_after_first_client_launch_s": data_ready + published,
            "host_confirmation_after_first_client_launch_s": data_ready + confirmed,
            "streams": {name: parse_stream(directory, name, manifest["udp"][name]) for name in CLASSES},
            "vmstat": vmstat_observations(directory / "vmstat.log"),
            "queue_root_drop_deltas": manifest["queue_root_drop_deltas"],
            "comparison": {"states_initial": initial["states"], "states_event": event["states"],
                           "options": {key: value for key, value in manifest["options"].items() if key != "mode"},
                           "profiles": manifest["profiles"], "source_sha256": manifest["source_sha256"],
                           "docker_version": manifest["docker_version"],
                           "fixed_weights": manifest["fixed_weights"]}}


def summarize(root, start, end):
    directories = sorted(path for path in root.iterdir() if path.is_dir() and start <= path.name[:16] <= end)
    if not directories:
        raise ValueError("No trials within the requested UTC range")
    trials = [load_trial(path) for path in directories]
    counts = Counter(trial["mode"] for trial in trials)
    if counts != {"fixed": 5, "adaptive": 5}:
        raise ValueError("Expected 5 FIXED + 5 ADAPTIVE, found %s" % dict(counts))
    common = trials[0]["comparison"]
    if not common["source_sha256"] or any(t["comparison"] != common for t in trials[1:]):
        raise ValueError("Source fingerprints, settings or states differ inside this batch")
    groups = {}
    for mode in ("fixed", "adaptive"):
        group = [trial for trial in trials if trial["mode"] == mode]
        summary = {"runs": 5, "runs_with_epoch_change": sum(t["epochs"]["before"] != t["epochs"]["after"] for t in group),
                   "streams": {}}
        for name in CLASSES:
            streams = [trial["streams"][name] for trial in group]
            whole_lost = sum(s["whole_receiver"]["lost_packets"] for s in streams)
            whole_total = sum(s["whole_receiver"]["total_packets"] for s in streams)
            window_net = sum(s["window"]["missing_counter_net_change"] for s in streams)
            window_total = sum(s["window"]["reported_sequence_count"] for s in streams)
            if window_total <= 0:
                raise ValueError("No received/sequence-counted window traffic for %s/%s" % (mode, name))
            summary["streams"][name] = {
                "whole_lost_packets": whole_lost, "whole_total_packets": whole_total,
                "whole_loss_percent": 100.0 * whole_lost / whole_total,
                "whole_receiver_bitrate_mbps": stats([s["whole_receiver"]["bitrate_mbps"] for s in streams]),
                "end_jitter_snapshots_ms": stats([s["whole_receiver"]["jitter_ms"] for s in streams]),
                "window_missing_counter_net_change": window_net, "window_reported_sequence_count": window_total,
                "window_missing_counter_net_percent": 100.0 * window_net / window_total,
                "window_missing_counter_increases": sum(s["window"]["missing_counter_increases"] for s in streams),
                "window_late_counter_corrections": sum(s["window"]["late_counter_corrections"] for s in streams),
                "window_covered_seconds_sum": sum(s["window"]["covered_seconds"] for s in streams),
                "window_bitrate_mbps": stats([s["window"]["time_weighted_displayed_bitrate_mbps"] for s in streams]),
                "window_jitter_snapshot_max_ms": max(s["window"]["interval_jitter_snapshot_max_ms"] for s in streams)}
        groups[mode] = summary
    return {"schema": 2, "selection_utc": {"start": start, "end_inclusive": end},
            "receiver_log_window_s": list(WINDOW), "comparison_inputs": common,
            "groups": groups, "trials": [{k: v for k, v in t.items() if k != "comparison"} for t in trials],
            "notes": [
                "Whole-trial results retain startup and tail effects. Window results are a separate, prospectively specified analysis for this batch.",
                "The 5--35s window uses each server's own interval clock, not host time. Do not align an exact FlowMod event to a receiver interval without synchronized timestamps.",
                "Only complete intervals inside the window are used. Boundary-crossing intervals are reported separately; coverage is shown, and no packet counts are fractionally imputed.",
                "Signed interval counters are preserved: positive = missing-counter increase; negative = later correction after out-of-order arrivals. Net change is NOT an independent true packet-loss rate for the window; a correction may refer to a gap from outside that window.",
                "Whole-trial loss is the final receiver summary. Counter increases and corrections are printed separately; no negatives are clamped to zero or converted to absolute losses.",
                "Window bitrate is the duration-weighted mean of rounded iperf interval rates.",
                "Window jitter values summarize interval-end jitter snapshots, not a per-packet jitter distribution. The whole-trial jitter field is an end snapshot, not the average over the test.",
                "Approximate Student-t intervals use five independent, approximately normal run statistics (df=4); interpret cautiously with sequential VM runs.",
                "All nonzero counter-change intervals (including negative corrections) are reported for every phase; no selected completed run is removed because of loss.",
                "Sender/receiver packet-count differences and interval/summary discrepancies are retained for inspection, not silently converted into extra loss.",
                "These measurements do not establish energy/carbon savings, one-way PDB compliance, or a causal advantage for either policy."
            ]}


def report_text(report):
    lines = ["UDP BATCH: 5 FIXED + 5 ADAPTIVE", "WHOLE-TRIAL RECEIVER RESULTS (startup and tail included)",
             "Mode      Class   Lost/Total       Loss      Mean receiver Mbps across 5 runs"]
    for mode, group in report["groups"].items():
        for name, values in group["streams"].items():
            lines.append("%-9s %-6s %5d/%-8d  %6.3f%%   %.3f" %
                         (mode.upper(), name, values["whole_lost_packets"], values["whole_total_packets"],
                          values["whole_loss_percent"], values["whole_receiver_bitrate_mbps"]["mean"]))
    lines += ["", "RECEIVER WINDOW 5--35s (complete intervals only)",
              "Window counters describe reported missing-counter changes, NOT independently measured window loss.",
              "Mode      Class     Net/SeqCount    Net%     +Gaps/-Corrections   Covered/150s   Mbps mean +/- run SD   Max jitter snapshot"]
    for mode, group in report["groups"].items():
        for name, values in group["streams"].items():
            rate = values["window_bitrate_mbps"]
            lines.append("%-9s %-6s %+5d/%-8d %+6.3f%%    +%d/-%d          %6.2f/150   %.3f +/- %.3f        %.3f ms" %
                         (mode.upper(), name, values["window_missing_counter_net_change"], values["window_reported_sequence_count"],
                          values["window_missing_counter_net_percent"], values["window_missing_counter_increases"],
                          values["window_late_counter_corrections"], values["window_covered_seconds_sum"],
                          rate["mean"], rate["sample_sd"], values["window_jitter_snapshot_max_ms"]))
    lines += ["", "PER-RUN WINDOW AUDIT:"]
    for trial in report["trials"]:
        for name, stream in trial["streams"].items():
            window = stream["window"]
            counts = stream["interval_counters_by_phase"]
            lines.append("%s %s | window %.2fs %.3f Mbps net %+d/%d | counter deltas before5/window/after35/boundary = %+d/%+d/%+d/%+d" %
                         (trial["trial"], name, window["covered_seconds"], window["time_weighted_displayed_bitrate_mbps"],
                          window["missing_counter_net_change"], window["reported_sequence_count"], counts["before_5s"]["missing_counter_net_change"],
                          counts["window_5_to_35s"]["missing_counter_net_change"], counts["after_35s"]["missing_counter_net_change"],
                          counts["boundary_crossing"]["missing_counter_net_change"]))
            if stream["sender_total_minus_receiver_total"] or stream["interval_net_missing_minus_final_loss"]:
                lines.append("  COUNTER CHECK: sender-total minus receiver-total=%s; interval-loss sum minus summary=%s" %
                             (stream["sender_total_minus_receiver_total"], stream["interval_net_missing_minus_final_loss"]))
    lines += ["", "ALL NONZERO MISSING-COUNTER CHANGES (positive gaps and negative corrections):"]
    any_loss = False
    for trial in report["trials"]:
        for name, stream in trial["streams"].items():
            for row in stream["counter_change_intervals"]:
                any_loss = True
                lines.append("%s %s | %.2f--%.2fs | %+d/%d | %s | %s" %
                             (trial["trial"], name, row["start_s"], row["end_s"], row["lost_packets"],
                              row["total_packets"], row["phase"], row["change_kind"]))
    if not any_loss:
        lines.append("None reported.")
    lines += ["", "INTERPRETATION:"] + ["- " + note for note in report["notes"]]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=timestamp, required=True)
    parser.add_argument("--end", type=timestamp, required=True)
    parser.add_argument("--trials-root", type=Path, default=PROJECT_ROOT / "results" / "udp-trials")
    args = parser.parse_args()
    if args.start > args.end:
        parser.error("Start must precede end")
    try:
        report = summarize(args.trials_root, args.start, args.end)
        text = report_text(report)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = PROJECT_ROOT / "results" / "udp-summaries" / (stamp + "-" + uuid.uuid4().hex[:8])
        output.mkdir(parents=True, exist_ok=False)
        (output / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        (output / "summary.txt").write_text(text, encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, "Cannot summarize UDP batch: %s\nRaw trials were not changed.\n" % error)
    print(text)
    print("Saved summary:", output)
    print("Read-only analysis; raw trials and network state were not changed.")


if __name__ == "__main__":
    main()
