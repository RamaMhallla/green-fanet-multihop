"""Offline timestamp comparison for the existing app-only calibration.

No sudo, traffic jobs, controller or topology changes. Reads existing pcaps.
Requires sim/capture_udp_fixed.py. Validated for iperf3 3.9 32-bit counters.
The embedded timestamp is sampled before Nwrite, not at physical transmission.
Clock domains are compared through intervals, never absolute subtraction.
"""
import json
import struct
import sys
from pathlib import Path

root = Path.home() / "green-fanet-multihop"
sys.path.insert(0, str(root / "sim"))
from capture_udp_fixed import pcap_records, decode_packet, read_capture

folder = root / "results/udp-source-calibration-app-only/20261019T231445Z-fixed-5e2197f42d3d"
manifest = json.loads((folder / "manifest.json").read_text())
settings = manifest["capture_settings"]
if (manifest.get("status") != "completed"
    or manifest.get("trial_protocol") != "udp-v4-fixed-source-calibration-app-only"
    or not manifest.get("mn.u1_iperf_version", "").startswith("iperf 3.9")
    or any("--udp-counters-64bit" in argv for argv in manifest["job_commands"].values())):
    raise ValueError("Expected the completed app-only calibration with iperf3 3.9 default counters")
report = json.loads((folder / "calibration-report.json").read_text())
if any(row["kernel_dropped"] != 0 for row in report["capture_quality"].values()):
    raise ValueError("Capture reported dropped packets; review capture quality first")

def app_stamp(raw):
    offset = 14
    kind = struct.unpack_from("!H", raw, 12)[0]
    while kind in (0x8100, 0x88a8):
        kind = struct.unpack_from("!H", raw, offset + 2)[0]
        offset += 4
    payload = offset + (raw[offset] & 15) * 4 + 8
    sec, usec, sequence = struct.unpack_from("!III", raw, payload)
    if usec >= 1_000_000:
        raise ValueError("Invalid embedded timestamp")
    return sec * 1_000_000 + usec, sequence

def gap_rows(rows, duration):
    origin = rows[0][0]
    lower, upper = origin + 5_000_000_000, origin + (duration-5)*1_000_000_000
    pairs = []
    for a, b in zip(rows, rows[1:]):
        if b[0] < a[0]:
            raise ValueError("Capture clock moved backwards")
        overlap = min(b[0], upper) - max(a[0], lower)
        if overlap > 0:
            pairs.append((overlap, a, b))
    return origin, sorted(pairs, key=lambda row: row[0], reverse=True)[:3]

source = {5201: [], 5202: []}
for stamp, raw in pcap_records(folder / "u1.pcap"):
    packet = decode_packet(raw)
    if (not packet or packet["protocol"] != "UDP"
        or packet.get("payload_length") != 1200
        or packet["source"] != settings["source_ip"]
        or packet["destination"] != settings["destination_ip"]
        or packet["dport"] not in source):
        continue
    prepared, sequence = app_stamp(raw)
    source[packet["dport"]].append((stamp, prepared, sequence))

_, gs = read_capture(folder / "gs.pcap", settings["source_ip"], settings["destination_ip"])
for name, port in (("VOICE", 5201), ("VIDEO", 5202)):
    origin, pairs = gap_rows(source[port], manifest["options"]["duration"])
    print("\n", name, "- largest interior source gaps")
    print("First-to-last source capture span (s):",
          round((source[port][-1][0]-source[port][0][0])/1e9, 6))
    print("First-to-last embedded preparation span (s):",
          round((source[port][-1][1]-source[port][0][1])/1e6, 6))
    for _, a, b in pairs:
        print("IDs:", a[2], "->", b[2])
        print("Source-relative start (s):", round((a[0]-origin)/1e9, 6))
        print("Capture gap (ms):", round((b[0]-a[0])/1e6, 3))
        print("iperf embedded preparation gap (ms):", round((b[1]-a[1])/1000, 3))
        stamps = gs[port]["ids"]
        print("GS gap for same IDs (ms):",
              round((stamps[b[2]]-stamps[a[2]])/1e6, 3)
              if a[2] in stamps and b[2] in stamps else "one ID not observed")
print("\nSeparate-clock interval comparison; not one-way delay or an exact queue-delay measurement.")

