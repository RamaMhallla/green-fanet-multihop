"""Predeclared analysis for the weights-only protocol; no network mutations."""
import hashlib
import json
import math
from pathlib import Path

PROTOCOL = "weights-only-joint-guard-v1"
DURATION = 40
SCHEDULE = (("battery30", 8.0, .30), ("battery25", 16.0, .25), ("plateau25", 24.0, .25))
WINDOW = (2, 6)
BUFFER_LIMITS = {"VOICE": 128, "VIDEO": 100, "CONTROL": 100}


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def distribution(values):
    values = sorted(values)
    if not values:
        return None
    return {"count": len(values), "minimum": values[0], "median": values[(len(values)-1)//2],
            "p99": values[max(0, math.ceil(.99*len(values))-1)], "maximum": values[-1]}


def cohort_metrics(source, destination, lower, upper):
    """Denominator is observed source IDs; late deliveries count by capture end."""
    selected = {seq: stamp for seq, stamp in source.items() if lower <= stamp < upper}
    matched = sorted(set(selected) & set(destination))
    absent = sorted(set(selected) - set(destination))
    duration = (upper-lower)/1e9
    delays = {seq: (destination[seq]-selected[seq])/1e6 for seq in matched}
    # Only neighbouring IDs with both timestamps enter this descriptive IPDV.
    ipdv = [abs(delays[b]-delays[a]) for a, b in zip(matched, matched[1:]) if b == a+1]
    arrivals = sum(lower <= stamp < upper for stamp in destination.values())
    timing = distribution(delays.values())
    if timing is not None:
        timing.update(above_100ms=sum(v>100 for v in delays.values()),
                      above_150ms=sum(v>150 for v in delays.values()))
    return {"source_packets": len(selected), "observed_at_gs_by_capture_end": len(matched),
        "source_ids_not_observed_at_gs": absent,
        "observed_delivery_percent": 100*len(matched)/len(selected) if selected else None,
        "source_payload_mbps": len(selected)*1200*8/duration/1e6,
        "gs_arrival_payload_mbps": arrivals*1200*8/duration/1e6,
        "capture_time_ms": timing, "absolute_capture_ipdv_ms": distribution(ipdv),
        "arrival_window_scope": "Arrivals in window differ from source-cohort delivery by capture end",
        "timing_scope": "Paired software timestamps for observed packets only; not application delay or standardised jitter"}


def analyze(directory):
    from battery_calibration_support import (read_capture, tcpdump_stats, assess_source,
        stream_statistics, CALIBRATION_POLICY, PROFILES, write_json)
    directory = Path(directory)
    manifest = json.loads((directory/"manifest.json").read_text())
    data = json.loads((directory/"weight-data.json").read_text())
    if (manifest.get("protocol") != PROTOCOL or manifest.get("kind") != "udp"
            or manifest.get("status") != "completed" or manifest.get("cleanup_errors")
            or data.get("status") != "completed" or data.get("cleanup_errors")):
        raise ValueError("A completed weights-only UDP run with verified cleanup is required")
    if data.get("policy") != CALIBRATION_POLICY or data.get("profiles") != list(PROFILES):
        raise ValueError("Source settings or acceptance criteria differ")
    captures, quality, issues = {}, {}, []
    for endpoint in ("u1", "gs"):
        count, captures[endpoint] = read_capture(directory/(endpoint+".pcap"), data["source_ip"], data["destination_ip"])
        quality[endpoint] = tcpdump_stats((directory/(endpoint+"-tcpdump.log")).read_text())
        if quality[endpoint]["kernel_dropped"] or count != quality[endpoint]["captured"]:
            issues.append(endpoint+": dropped capture records or count mismatch")
    pacing = data["source_pacing"]
    if (pacing.get("dropped_packets_delta") != 0 or pacing.get("final_queued_packets") != 0
            or pacing.get("final_backlog_bytes") != 0 or pacing.get("noqueue_restored") is not True):
        issues.append("Source pacing drops/backlog/restoration requires review")
    stages = manifest["stages"]
    if set(stages) != {"initial", *(label for label, _, _ in SCHEDULE)}:
        raise ValueError("Incomplete battery schedule")
    anchors = {"initial": data["timing_marks"]["both_streams_observed"]}
    anchors.update({label: stages[label]["confirmation_observed"] for label, _, _ in SCHEDULE})
    marks = list(anchors.values()) + [data["timing_marks"]["begin"], data["timing_marks"]["end"]]
    offsets = [m["wall_ns"]-m["monotonic_ns"] for m in marks]
    spread_ms = (max(offsets)-min(offsets))/1e6
    labels = ["initial"]+[s[0] for s in SCHEDULE]
    result = {"schema": 1, "protocol": PROTOCOL, "weights": manifest["weights"],
        "scenario": manifest["scenario"], "pair": manifest["pair"], "contract_sha256": manifest["contract_sha256"],
        "capture_quality": quality, "evidence_issues": issues, "source_pacing": pacing,
        "clock_offset_spread_ms": spread_ms, "source_policy": CALIBRATION_POLICY,
        "queue_root_drop_deltas": data["queue_root_drop_deltas"],
        "video_meter_totals_by_epoch": manifest["video_meter_totals"], "streams": {},
        "qos_accepted": False, "energy_saving_established": False,
        "scope": "Weights-only diagnostic. Source failures retained. No QoS or energy PASS is issued."}
    for profile in PROFILES:
        name, port = profile["name"], profile["port"]
        source, destination = captures["u1"][port], captures["gs"][port]
        row = assess_source(source, data["udp"][name]["sender"], DURATION, profile["rate_mbps"])
        source_set, dest_set = set(source["ids"]), set(destination["ids"])
        extra = sorted(dest_set-source_set)
        ambiguous = bool(issues or row["evidence_issues"] or extra
                         or destination["datagrams"] != len(dest_set))
        windows = {}
        for i, label in enumerate(labels):
            mark = anchors[label]
            lower, upper = (mark["wall_ns"]+int(s*1e9) for s in WINDOW)
            limit = (stages[labels[i+1]]["publish_start"]["wall_ns"] if i+1 < len(labels)
                     else data["timing_marks"]["traffic_finished"]["wall_ns"])
            if spread_ms > 5 or upper > limit:
                windows[label] = {"status": "INCONCLUSIVE", "issue": "Clock check failed or window overlaps next stage/end"}
                continue
            window = cohort_metrics(source["ids"], destination["ids"], lower, upper)
            negative = window["capture_time_ms"] and window["capture_time_ms"]["minimum"] < 0
            window.update(window_wall_ns=[lower, upper],
                status="INCONCLUSIVE" if ambiguous or not window["source_packets"] or negative else "OBSERVABLE",
                uav1_planned_mbps=stages[label]["applied"]["plan"]["forward_scheduler_allocations_mbps"]["UAV1"])
            windows[label] = window
        row.update(source_unique_packets=len(source_set), gs_unique_packets=len(dest_set),
            source_ids_not_observed_at_gs=sorted(source_set-dest_set), gs_ids_not_observed_at_source=extra,
            packet_set_audit="INCONCLUSIVE" if ambiguous else "COMPLETE_CAPTURE_AUDIT", windows=windows,
            gs_statistics=stream_statistics(destination, DURATION) if len(dest_set)>1 else None,
            receiver_summary=data["udp"][name]["receiver"])
        result["streams"][name] = row
    verdicts = [row["verdict"] for row in result["streams"].values()]
    result["source_verdict"] = ("INCONCLUSIVE" if "INCONCLUSIVE" in verdicts or any(x.startswith("u1:") for x in issues)
                                else "FAIL" if "FAIL" in verdicts else "PASS")
    write_json(directory/"weight-report.json", result)
    print("SOURCE CRITERIA:", result["source_verdict"], "| weights:", result["weights"], "| scenario:", result["scenario"])
    for name, row in result["streams"].items():
        print("%s source/GS: %d/%d; missing by capture end: %d" %
              (name, row["source_unique_packets"], row["gs_unique_packets"], len(row["source_ids_not_observed_at_gs"])))
        for label, window in row["windows"].items():
            print(" ", label, window["status"],
                ("delivery=%d/%d; GS arrivals=%.3f Mbps" % (window["observed_at_gs_by_capture_end"],
                window["source_packets"], window["gs_arrival_payload_mbps"])) if "source_packets" in window else window["issue"])
    print("No QoS/energy claim. Saved:", directory/"weight-report.json")
    return result
