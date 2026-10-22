"""Summarize one explicitly bounded batch of five FIXED and five ADAPTIVE trials.

Reads saved files only; never changes network rules, state files or raw trials.
Writes a new timestamped report directory under results/summaries.
The selection includes every trial directory in the requested UTC interval;
failed/incomplete trials cause an error, rather than being silently discarded.
"""

import argparse
from collections import Counter
import datetime as dt
import json
import math
from pathlib import Path
import re
import statistics
import sys
import uuid

PROJECT_ROOT = Path(__file__).resolve().parent.parent
T95_DF4 = 2.7764451051977987


def timestamp(value):
    try:
        dt.datetime.strptime(value, "%Y%m%dT%H%M%SZ")
    except ValueError:
        raise argparse.ArgumentTypeError("Use UTC timestamp YYYYMMDDTHHMMSSZ")
    return value


def read_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def finite(value, label):
    if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
        raise ValueError("%s must be a finite nonnegative number" % label)
    return float(value)


def five_run_stats(values):
    if len(values) != 5:
        raise ValueError("This batch summary requires exactly five trials per mode")
    mean = statistics.mean(values)
    sd = statistics.stdev(values)
    half = T95_DF4 * sd / math.sqrt(5)
    return {"mean": mean, "sample_sd": sd, "min": min(values), "max": max(values),
            "t95_interval": [mean - half, mean + half]}


def packet_details(directory, transmitted, received):
    """Describe first replies using RTTs printed by ping (rounded display).

    Nearest-rank empirical percentiles, without interpolation. Duplicates are
    counted separately; missing replies remain losses, not percentile samples.
    These are round-trip measurements, not one-way budgets or UDP jitter.
    """
    replies = {}
    duplicates = 0
    for line in (directory / "ping.log").read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.search(r"\bicmp_seq=(\d+)\b.*?\btime=([0-9.]+)\s*ms\b", line)
        if not match:
            continue
        seq = int(match[1])
        if not 1 <= seq <= transmitted:
            raise ValueError("%s: reply sequence outside expected range" % directory.name)
        value = finite(float(match[2]), "Printed RTT")
        if seq in replies:
            duplicates += 1
        else:
            replies[seq] = value
    if len(replies) != received or not replies:
        raise ValueError("%s: ping.log has %d distinct parsed replies; manifest says %d. "
                         "Inspect log format/completeness before analysis." %
                         (directory.name, len(replies), received))
    ordered = sorted(replies.values())
    def percentile(p):
        return ordered[math.ceil(p * len(ordered)) - 1]
    maximum = max(ordered)
    return {"distinct_replies": len(replies), "duplicate_replies": duplicates,
            "p50_ms": percentile(.50), "p95_ms": percentile(.95), "p99_ms": percentile(.99),
            "maximum_printed_ms": maximum,
            "sequences_at_printed_maximum": [seq for seq, value in replies.items() if value == maximum]}


def load_trial(directory, inspect_packets=False):
    manifest = read_json(directory / "manifest.json")
    if manifest.get("status") != "completed":
        raise ValueError("%s: status=%r; retained trial cannot be silently omitted" %
                         (directory.name, manifest.get("status")))
    if manifest.get("trial_protocol") != "v2-container-readiness-gate":
        raise ValueError("%s: no matching readiness-gate protocol" % directory.name)
    # A successful readiness snapshot must also have been saved.
    ready = read_json(directory / "topology-ready.json")
    if not ready.get("uavs") or not ready.get("endpoints"):
        raise ValueError("%s: readiness evidence is incomplete" % directory.name)
    mode = manifest.get("mode")
    if mode not in ("fixed", "adaptive"):
        raise ValueError("%s: unknown mode" % directory.name)
    ping = manifest["ping"]
    tx, rx = ping["transmitted"], ping["received"]
    if type(tx) is not int or type(rx) is not int or tx <= 0 or not 0 <= rx <= tx:
        raise ValueError("%s: invalid packet counts" % directory.name)
    if tx != manifest["options"]["count"]:
        raise ValueError("%s: ping count differs from the planned trial" % directory.name)
    rtt = ping.get("rtt_ms", {})
    rtt_values = {key: finite(rtt[key], "RTT " + key)
                  for key in ("min", "mean", "max", "mdev")}
    if not rtt_values["min"] <= rtt_values["mean"] <= rtt_values["max"]:
        raise ValueError("%s: inconsistent RTT values" % directory.name)
    epochs = manifest["epochs"]
    if any(type(epochs[k]) is not int or epochs[k] < 0 for k in ("before", "after")):
        raise ValueError("%s: invalid epoch values" % directory.name)
    lag = (finite(manifest["confirmation_observed_offset_s"], "Confirmation offset")
           - finite(manifest["event_publish_end_offset_s"], "Event publication offset"))
    if lag < 0:
        raise ValueError("%s: confirmation was recorded before state publication" % directory.name)
    initial = read_json(directory / "state-initial.json")
    event = read_json(directory / "state-event.json")
    if (initial["states"]["UAV1"]["energy_fraction"] != 0.9
            or event["states"]["UAV1"]["energy_fraction"] != 0.1):
        raise ValueError("%s: unexpected battery event" % directory.name)
    result = {"trial": directory.name, "mode": mode, "transmitted": tx, "received": rx,
            "loss_percent": 100.0 * (tx - rx) / tx, "rtt_ms": rtt_values,
            "epoch_before": epochs["before"], "epoch_after": epochs["after"],
            "epoch_changed": epochs["before"] != epochs["after"],
            "confirmation_observed_delay_s": lag,
            "event_publish_start_offset_s": finite(manifest["event_publish_start_offset_s"],
                                                   "Event start offset"),
            "initial_plan": read_json(directory / "plan-initial.json"),
            "event_plan": read_json(directory / "plan-event.json"),
            "comparison": {"initial_states": initial["states"], "event_states": event["states"],
                           "source_sha256": manifest["source_sha256"],
                           "options": {key: manifest["options"][key] for key in
                                       ("count", "interval", "change_after")},
                           "fixed_weights": manifest["fixed_weights"],
                           "docker_version": manifest["docker_version"]}}
    if inspect_packets:
        result["packet_rtt"] = packet_details(directory, tx, rx)
    return result


def summarize(trials_root, start, end, inspect_packets=False):
    directories = sorted(p for p in trials_root.iterdir() if p.is_dir()
                         and start <= p.name[:16] <= end)
    if not directories:
        raise ValueError("No trial directories within the requested UTC interval")
    trials = [load_trial(directory, inspect_packets) for directory in directories]
    counts = Counter(trial["mode"] for trial in trials)
    if counts != {"fixed": 5, "adaptive": 5}:
        raise ValueError("Expected exactly 5 FIXED + 5 ADAPTIVE; found %s. "
                         "Do not choose only favourable runs." % dict(counts))
    reference = trials[0]["comparison"]
    if not reference["source_sha256"]:
        raise ValueError("Source fingerprints are missing")
    if any(trial["comparison"] != reference for trial in trials[1:]):
        raise ValueError("Inputs, options, source fingerprints or Docker versions differ "
                         "inside this batch; inspect raw trials before comparing")
    groups = {}
    for mode in ("fixed", "adaptive"):
        group = [trial for trial in trials if trial["mode"] == mode]
        tx = sum(t["transmitted"] for t in group)
        rx = sum(t["received"] for t in group)
        groups[mode] = {"runs": len(group), "transmitted": tx, "received": rx,
                        "pooled_loss_percent": 100.0 * (tx - rx) / tx,
                        "runs_with_epoch_change": sum(t["epoch_changed"] for t in group),
                        "run_mean_rtt_ms": five_run_stats([t["rtt_ms"]["mean"] for t in group]),
                        "largest_observed_rtt_ms": max(t["rtt_ms"]["max"] for t in group),
                        "observed_confirmation_delay_s": five_run_stats(
                            [t["confirmation_observed_delay_s"] for t in group])}
    return {"schema": 1, "packet_details_included": inspect_packets,
            "selection_utc": {"start": start, "end_inclusive": end},
            "comparison_inputs": reference, "groups": groups,
            "trials": [{k: v for k, v in trial.items() if k != "comparison"}
                       for trial in trials],
            "notes": [
                "Only DSCP-46 ICMP is measured. VIDEO paths are planned but no VIDEO load is generated.",
                "RTT includes both directions; it is not measured one-way delay or iperf jitter.",
                "Optional packet percentiles are per run, nearest-rank over first received replies, using rounded RTTs printed in ping.log; duplicates and losses are not percentile samples.",
                "RTT statistics use five per-run means, not 1000 independent packet observations.",
                "The approximate 95% Student-t interval (df=4) assumes independent, approximately normal run means; interpret cautiously with five sequential VM runs.",
                "Zero observed losses does not establish a zero underlying loss probability.",
                "Confirmation delay is local polling/log observation after file publication, not disruption time or isolated FlowMod latency.",
                "Epoch changes show route version changes; they do not quantify energy savings or QoS improvements.",
                "Earlier setup/debug runs outside the explicit UTC range remain stored and are not included."
            ]}


def report_text(report):
    lines = ["LIVE PING BATCH: 5 FIXED + 5 ADAPTIVE",
             "UTC selection: %s through %s (inclusive)" %
             (report["selection_utc"]["start"], report["selection_utc"]["end_inclusive"]), "",
             "Mode      Replies    Loss     Epoch-change runs   RTT mean +/- SD (ms)   Approx. t95 interval"]
    for mode, group in report["groups"].items():
        rtt = group["run_mean_rtt_ms"]
        lines.append("%-9s %4d/%-4d  %6.2f%%     %d/5             %7.3f +/- %-7.3f  [%.3f, %.3f]" %
                     (mode.upper(), group["received"], group["transmitted"],
                      group["pooled_loss_percent"], group["runs_with_epoch_change"],
                      rtt["mean"], rtt["sample_sd"], *rtt["t95_interval"]))
    lines += ["", "Per-run evidence (all 10 trials):"]
    for trial in report["trials"]:
        lines.append("%s | %d/%d | loss %.2f%% | mean/max RTT %.3f/%.3f ms | epoch %d -> %d" %
                     (trial["trial"], trial["received"], trial["transmitted"],
                      trial["loss_percent"], trial["rtt_ms"]["mean"], trial["rtt_ms"]["max"],
                      trial["epoch_before"], trial["epoch_after"]))
    if report.get("packet_details_included"):
        lines += ["", "PACKET RTT TAILS (ms; rounded ping display; per run):",
                  "Trial | P50 | P95 | P99 | Printed max | Seq at printed max"]
        for trial in report["trials"]:
            packet = trial["packet_rtt"]
            lines.append("%s | %.3f | %.3f | %.3f | %.3f | %s" %
                         (trial["trial"], packet["p50_ms"], packet["p95_ms"], packet["p99_ms"],
                          packet["maximum_printed_ms"],
                          ",".join(map(str, packet["sequences_at_printed_maximum"]))))
    lines += ["", "Interpretation:"] + ["- " + note for note in report["notes"]]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=timestamp, required=True, help="First trial UTC timestamp")
    parser.add_argument("--end", type=timestamp, required=True, help="Last trial UTC timestamp (inclusive)")
    parser.add_argument("--trials-root", type=Path, default=PROJECT_ROOT / "results" / "trials")
    parser.add_argument("--packet-details", action="store_true",
                        help="Also read existing ping logs for P50/P95/P99 and peak sequence numbers")
    args = parser.parse_args()
    if args.start > args.end:
        parser.error("Start must precede end")
    try:
        report = summarize(args.trials_root, args.start, args.end, args.packet_details)
        text = report_text(report)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = PROJECT_ROOT / "results" / "summaries" / (stamp + "-" + uuid.uuid4().hex[:8])
        output.mkdir(parents=True, exist_ok=False)
        (output / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        (output / "summary.txt").write_text(text, encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, "Cannot summarize this batch: %s\nRaw trials were not changed.\n" % error)
    print(text)
    print("Saved summary:", output)
    print("Raw trial files were not modified. No network commands were executed.")


if __name__ == "__main__":
    main()
