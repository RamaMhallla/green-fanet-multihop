"""Print controller hook times and host-observed iperf report times."""
import argparse
import json
from pathlib import Path
import re

INTERVAL = re.compile(
    r"^\[\s*\d+\]\s+([\d.]+)-\s*([\d.]+)\s+sec\s+"
    r"[\d.]+\s+\S+\s+[\d.]+\s+\S+\s+[\d.]+\s+ms\s+"
    r"([+-]?\d+)/\s*(\d+)\s+\([^)]*\)\s*(receiver|sender)?\s*$")


def report(directory):
    data = json.loads((directory / "manifest.json").read_text())
    marks = data.get("timing_marks", {})
    if "event_publish_start" not in marks:
        raise ValueError("No event publish timestamp; trial may have failed before event")
    zero = marks["event_publish_start"]["monotonic_ns"]
    rows = []
    for name, mark in marks.items():
        rows.append((mark["monotonic_ns"], "RUNNER", name))
    for line in (directory / "controller.log").read_text().splitlines():
        if not line.startswith("TIMING "):
            continue
        item = json.loads(line[len("TIMING "):])
        desc = item["event"] + " rev=%s epoch=%s" % (item.get("revision"), item.get("epoch"))
        if "traffic_class" in item:
            desc += " %s %s" % (item["traffic_class"], item["direction"])
        rows.append((item["monotonic_ns"], "CONTROLLER", desc))
    print("TRIAL:", directory.name, "status=", data.get("status"))
    print("SECONDS RELATIVE TO EVENT PUBLISH START (host monotonic clock)")
    print("Controller hooks/runner marks are observation points, not packet timestamps.")
    for timestamp, source, desc in sorted(rows):
        print("%+10.6f  %-10s %s" % ((timestamp - zero) / 1e9, source, desc))
    print("\nRECEIVER REPORTS: host-observed lines (NOT exact receiver interval end times)")
    print("All nonzero signed counters plus reports observed from -3s through +5s are shown.")
    for name in ("voice", "video"):
        path = directory / (name + "-server.timing.jsonl")
        print("\n" + name.upper())
        previous = None
        intervals = []
        for line in path.read_text().splitlines():
            row = json.loads(line)
            match = INTERVAL.match(row["text"])
            if not match or match[5]:
                continue
            start, end, lost, total = float(match[1]), float(match[2]), int(match[3]), int(match[4])
            seen = (row["observed_monotonic_ns"] - zero) / 1e9
            gap = None if previous is None else (row["observed_monotonic_ns"] - previous) / 1e9
            previous = row["observed_monotonic_ns"]
            intervals.append((seen, gap, start, end, lost, total))
        if not intervals:
            raise ValueError("No receiver interval records: " + str(path))
        print("Observed(s)  Since previous observed report(s)  iperf interval(s)  Counter")
        for seen, gap, start, end, lost, total in intervals:
            if lost or -3 <= seen <= 5:
                print("%+10.6f  %8s  %6.2f--%6.2f  %+d/%d" % (
                    seen, "n/a" if gap is None else "%.6f" % gap,
                    start, end, lost, total))
        print("Parsed %d intervals. Maximum gap between observed reports: %.6fs" % (
            len(intervals), max((x[1] for x in intervals if x[1] is not None), default=0)))
    print("\nA report arriving after a controller hook does NOT prove its loss occurred after that hook.")
    print("Keep this timed protocol separate from the previous UDP batch.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("--latest", action="store_true")
    args = parser.parse_args()
    if bool(args.directory) == args.latest:
        parser.error("Choose one directory OR --latest")
    directory = args.directory
    if args.latest:
        root = Path(__file__).resolve().parent.parent / "results" / "udp-timed-trials"
        candidates = sorted(p.parent for p in root.glob("*/manifest.json"))
        if not candidates:
            parser.error("No timed trials found")
        directory = candidates[-1]
    try:
        report(directory)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, "Cannot report timing: %s\n" % error)


if __name__ == "__main__":
    main()
