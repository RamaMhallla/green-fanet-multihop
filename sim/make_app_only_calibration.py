"""Create a separate no-event calibration with the socket pacing cap disabled.

Run as normal user; this installer does not start a trial or require sudo.
Keeps run_udp_calibration.py unchanged and refuses to overwrite a different
run_udp_calibration_app_only.py. Requires the exact validated control script.
"""
import argparse
import ast
import hashlib
from pathlib import Path
import sys


CONTROL_SHA256 = "44982ac104d8b6ca8d8990f899decb74e0030f2cb34d0d7fa82a08ca4b434002"
CONTROL_FILENAME = "run_udp_calibration.py"
OUTPUT_FILENAME = "run_udp_calibration_app_only.py"


def build_variant(source):
    if hashlib.sha256(source.encode("utf-8")).hexdigest() != CONTROL_SHA256:
        raise ValueError("The control script differs from the validated version. "
                         "No file changed. Keep the control and report this message.")

    def replace(old, new, count=1):
        nonlocal source
        if source.count(old) != count:
            raise ValueError("Unexpected control block: " + old[:80])
        source = source.replace(old, new)

    replace(CONTROL_FILENAME, OUTPUT_FILENAME, 2)
    replace("udp-source-calibration", "udp-source-calibration-app-only", 2)
    replace("udp-v4-fixed-source-calibration", "udp-v4-fixed-source-calibration-app-only", 2)
    replace("Uses the existing fq settings, application targets and socket caps unchanged.",
            "Uses unchanged fq settings/application targets; disables the socket pacing cap.")
    replace("PACING_HEADROOM = 1.05\n", "")
    replace('"method": "iperf3 SO_MAX_PACING_RATE plus sender sch_fq",',
            '"method": "iperf3 application pacing with sender sch_fq; socket cap disabled",\n'
            '        "socket_pacing_enabled": False,')
    replace('"socket_pacing_cap_mbps": {p["name"]: p["rate_mbps"] * PACING_HEADROOM for p in PROFILES},',
            '"socket_pacing_cap_mbps": {p["name"]: 0.0 for p in PROFILES},')
    replace('"headroom_factor": PACING_HEADROOM,', '"headroom_factor": None,')
    replace('"headroom_reason": "5% margin for packet/header accounting; target -b stays unchanged",',
            '"headroom_reason": "Socket cap disabled in this ablation; -b targets unchanged",')
    replace('"--fq-rate", "%gM" % (profile["rate_mbps"] * PACING_HEADROOM),',
            '"--fq-rate", "0",')
    replace("Sender fq installed: application targets 1.2/4.2 Mbps; socket caps 1.26/4.41 Mbps.",
            "Sender fq unchanged; application targets 1.2/4.2 Mbps; socket pacing cap DISABLED (--fq-rate 0).")
    ast.parse(source, filename=OUTPUT_FILENAME, feature_version=(3, 10))
    compile(source, OUTPUT_FILENAME, "exec")
    return source


def install(project):
    control = project / "sim" / CONTROL_FILENAME
    output = project / "sim" / OUTPUT_FILENAME
    source = control.read_text(encoding="utf-8")
    variant = build_variant(source)
    if output.exists():
        if output.read_text(encoding="utf-8") != variant:
            raise ValueError("Destination already exists with different content; left untouched: " + str(output))
        print("Matching variant already installed:", output)
    else:
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(variant)
        print("Created:", output)
    print("Control unchanged:", control)
    print("Only traffic-setting change: --fq-rate 0; -b targets and root fq options unchanged.")
    print("Same duration and acceptance criteria. Separate protocol and result directory.")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path,
                        default=Path.home() / "green-fanet-multihop")
    args = parser.parse_args()
    try:
        install(args.project_root.expanduser().resolve())
    except (OSError, ValueError, SyntaxError) as error:
        print("Installation stopped: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
