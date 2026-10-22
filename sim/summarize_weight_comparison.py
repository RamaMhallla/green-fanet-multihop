"""Compare explicitly named matched UDP runs; never select or filter a latest batch."""
import argparse
import datetime as dt
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT),str(ROOT/"sim")]
from weight_comparison_analysis import PROTOCOL, fingerprint


def summarize(paths):
    groups = {}
    for path in paths:
        folder = Path(path).expanduser().resolve()
        manifest = json.loads((folder/"manifest.json").read_text())
        if manifest.get("protocol") != PROTOCOL or manifest.get("kind") != "udp":
            raise ValueError("Not a weights-only UDP run: "+str(folder))
        if fingerprint(manifest["contract"]) != manifest["contract_sha256"]:
            raise ValueError("Contract hash does not match manifest")
        key = (manifest["scenario"],manifest["pair"])
        arm = manifest["weights"]
        pair = groups.setdefault(key,{})
        if arm not in ("fixed","adaptive") or arm in pair:
            raise ValueError("Duplicate/unknown arm in pair %s; retain it, do not silently select a replacement" % (key,))
        report_file = folder/"weight-report.json"
        report = json.loads(report_file.read_text()) if report_file.exists() else None
        if report is not None and any(report.get(k)!=manifest.get(k) for k in
                                     ("protocol","weights","scenario","pair","contract_sha256")):
            raise ValueError("Analysis report belongs to a different run/contract: "+str(folder))
        pair[arm] = {"directory":str(folder),"manifest":manifest,"report":report}
    if not groups:
        raise ValueError("No runs supplied")
    result = {"protocol":PROTOCOL,"pairs":[],"qos_accepted":False,"energy_saving_established":False,
        "scope":"Descriptive matched-run comparison. Runs, not packets, are repetitions. Source failures retained."}
    for (scenario,label),pair in sorted(groups.items()):
        if set(pair) != {"fixed","adaptive"}:
            raise ValueError("Pair %s/%s lacks one arm" % (scenario,label))
        f,a = pair["fixed"],pair["adaptive"]
        if f["manifest"]["contract_sha256"] != a["manifest"]["contract_sha256"]:
            raise ValueError("Pair %s/%s differs in scenario/settings/source code; cannot pool it" % (scenario,label))
        row = {"scenario":scenario,"pair":label,"arms":{},"status":"DIAGNOSTIC_ONLY"}
        for arm,item in pair.items():
            m,r = item["manifest"],item["report"]
            clean = m["status"] == "completed" and not m.get("cleanup_errors") and r is not None
            row["arms"][arm] = {"directory":item["directory"],"collection_status":m["status"],
                "source_verdict":r["source_verdict"] if r else "UNAVAILABLE",
                "planned_uav1_mbps_by_stage":{k:s["applied"]["plan"]["forward_scheduler_allocations_mbps"]["UAV1"]
                    for k,s in m.get("stages",{}).items()}, "streams":r["streams"] if r else {},
                "evidence_issues":r["evidence_issues"] if r else ["Analysis report unavailable"]}
            if not clean:
                row["status"] = "INCOMPLETE_OR_FAILED_PAIR"
        if (row["status"] == "DIAGNOSTIC_ONLY" and
                all(item["source_verdict"] == "PASS" for item in row["arms"].values()) and
                all(not item["evidence_issues"] for item in row["arms"].values())):
            row["status"] = "SOURCE_ACCEPTED_DESCRIPTIVE_PAIR"
        result["pairs"].append(row)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs",type=Path,nargs="+",help="Explicit fixed/adaptive directories from the same named pair")
    args = parser.parse_args(argv)
    try:
        result = summarize(args.runs)
    except (OSError,ValueError,KeyError,TypeError) as error:
        print("Comparison summary stopped:",error)
        return 1
    folder = ROOT/"results/weight-comparison-summaries"/(
        dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    (folder/"comparison.json").write_text(json.dumps(result,indent=2)+"\n")
    lines = ["# Weights-only comparison", "", "Both arms replan with the same joint planner and guard.",
             "No QoS or energy saving is inferred from this summary.", ""]
    for pair in result["pairs"]:
        print("SCENARIO",pair["scenario"],"PAIR",pair["pair"],pair["status"])
        lines += ["## Scenario %s, pair %s" % (pair["scenario"],pair["pair"]),"",pair["status"],"",
                  "| Arm | Source verdict | UAV1 planned Mbps: initial / 30% / 25% / plateau |",
                  "|---|---|---|"]
        for arm,item in pair["arms"].items():
            values = [item["planned_uav1_mbps_by_stage"].get(k) for k in ("initial","battery30","battery25","plateau25")]
            print(" ",arm,"source:",item["source_verdict"],"UAV1 allocations:",values)
            lines.append("| %s | %s | %s |" % (arm,item["source_verdict"]," / ".join(map(str,values))))
        lines += ["", "Window rates, packet IDs, paired capture-time summaries and descriptive IPDV are in comparison.json.",
                  "Failed and inconclusive runs are retained. Independent paired repetitions are needed before inference.", ""]
    (folder/"comparison.md").write_text("\n".join(lines)+"\n")
    print("Saved:",folder)
    return 0


if __name__ == "__main__":
    sys.exit(main())
