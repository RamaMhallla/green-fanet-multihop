"""Read explicit weights-only runs and write separate, labelled energy estimates."""
import argparse
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from core.uav_energy_model import VERSION, digest, load_parameters, nominal_plan, old_tx_component, snapshot_energy, require


def read(path):
    return json.loads(Path(path).read_text())


def build_report(paths, parameters, parameter_sha256):
    runs=[]
    groups={}
    for value in paths:
        folder=Path(value).expanduser().resolve()
        manifest=read(folder/"manifest.json")
        require(manifest.get("protocol")=="weights-only-joint-guard-v1" and manifest.get("kind")=="udp", "Expected a weights-only UDP trial")
        require(manifest.get("status")=="completed" and not manifest.get("cleanup_errors"), "Incomplete/failed run retained; cannot treat it as a completed energy observation: "+str(folder))
        require(digest(manifest["contract"])==manifest["contract_sha256"],"Invalid comparison contract")
        traffic=read(folder/"weight-report.json")
        require(all(traffic.get(k)==manifest.get(k) for k in ("protocol","scenario","pair","weights","contract_sha256")), "Traffic report belongs to another trial")
        plan=manifest["stages"]["battery25"]["applied"]["plan"]
        row={"directory":str(folder),"scenario":manifest["scenario"],"pair":manifest["pair"],
            "weights":manifest["weights"],"contract_sha256":manifest["contract_sha256"],
            "source_verdict_retained":traffic["source_verdict"],
            "traffic_evidence_issues":traffic["evidence_issues"],
            "nominal_25pct_4s":nominal_plan(plan,parameters),
            "delivery":{name:{"source_unique_packets":s["source_unique_packets"],
                "gs_unique_packets":s["gs_unique_packets"],"window25":s["windows"]["battery25"]}
                for name,s in traffic["streams"].items()},
            "input_sha256":{name:hashlib.sha256((folder/name).read_bytes()).hexdigest()
                for name in ("manifest.json","weight-report.json")}}
        try:
            row["old_qdisc_tx_component"]=old_tx_component(folder,parameters)
            for node in parameters["uavs"]:
                for i in (0,1):
                    for phase in ("before","final"):
                        name="queue-%s-%s-eth%d.txt" % (phase,node.lower(),i)
                        row["input_sha256"][name]=hashlib.sha256((folder/name).read_bytes()).hexdigest()
        except (OSError,ValueError,KeyError) as error:
            row["old_qdisc_tx_component"]={"status":"INCONCLUSIVE","issue":str(error),"estimated_total_energy_j":None}
        observation=folder/"energy-counters.json"
        if observation.exists():
            data=read(observation)
            require(data.get("status")=="completed" and data.get("model")==VERSION,"Incomplete/unknown energy instrumentation")
            require(data.get("parameter_sha256")==parameter_sha256,"Observation and energy parameter file differ")
            require(data.get("comparison_contract_sha256")==manifest["contract_sha256"],"Energy observation belongs to another contract")
            require(manifest["contract"].get("energy_instrumentation",{}).get("parameter_sha256")==parameter_sha256,"Missing instrumentation contract")
            row["counter_informed_estimate"]=snapshot_energy(data["before"],data["after"],parameters)
            observed_mbit=sum(s["gs_unique_packets"] for s in traffic["streams"].values())*1200*8/1e6
            estimate=row["counter_informed_estimate"]
            estimate["observed_delivered_udp_mbit"]=observed_mbit
            estimate["conditional_j_per_observed_delivered_udp_mbit"]=(estimate["sum_per_node_interval_energy_j"]/observed_mbit if observed_mbit else None)
            estimate["normalization_caveat"]="Observation interval includes setup/tail/control traffic. Denominator is captured UDP payload, not on-time service. Source/evidence failures remain. Unequal runtimes and losses can change this ratio."
            row["input_sha256"]["energy-counters.json"]=hashlib.sha256(observation.read_bytes()).hexdigest()
        else:
            row["counter_informed_estimate"]={"status":"UNAVAILABLE","estimated_total_energy_j":None,
                "reason":"Old runs did not record timed per-UAV RX/TX snapshots. No zero RX, sleep state or duration is invented."}
        group=groups.setdefault((row["scenario"],row["pair"]),{})
        require(row["weights"] in ("fixed","adaptive") and row["weights"] not in group,"Duplicate/unknown arm; name explicit independent pairs")
        group[row["weights"]]=len(runs)
        runs.append(row)
    pairs=[]
    for (scenario,label),indices in groups.items():
        if set(indices)!={"fixed","adaptive"}:
            pairs.append({"scenario":scenario,"pair":label,"status":"UNPAIRED","comparison":None})
            continue
        fixed,adaptive=(runs[indices[w]] for w in ("fixed","adaptive"))
        require(fixed["contract_sha256"]==adaptive["contract_sha256"],"Different settings/code/resources; cannot compare this pair")
        a,b=fixed["nominal_25pct_4s"],adaptive["nominal_25pct_4s"]
        sensitivity=[]
        for hover_factor in (.5,1,2):
            for communication_factor in (.5,1,2):
                changed=copy.deepcopy(parameters)
                for p in changed["uavs"].values():
                    p["hover_w"]*=hover_factor
                    for key in ("tx_increment_j_per_bit","rx_increment_j_per_bit"):
                        p[key]*=communication_factor
                values=[]
                for run in (fixed,adaptive):
                    selected=read(Path(run["directory"])/"manifest.json")["stages"]["battery25"]["applied"]["plan"]
                    values.append(nominal_plan(selected,changed))
                sensitivity.append({"hover_factor":hover_factor,"communication_factor":communication_factor,
                    "fixed_estimated_j":values[0]["estimated_total_j"],"adaptive_estimated_j":values[1]["estimated_total_j"],
                    "adaptive_minus_fixed_j":values[1]["estimated_total_j"]-values[0]["estimated_total_j"]})
        pairs.append({"scenario":scenario,"pair":label,"status":"ASSUMPTION_BASED_COMPARISON",
            "nominal_adaptive_minus_fixed_j":b["estimated_total_j"]-a["estimated_total_j"],
            "nominal_per_uav_adaptive_minus_fixed_j":{n:b["per_uav"][n]["estimated_total_j"]-a["per_uav"][n]["estimated_total_j"] for n in parameters["uavs"]},
            "nominal_parameter_sensitivity":sensitivity,
            "scope":"Equal assumed full-delivery workload for 4s, not a measured energy saving. Traffic-only unloading does not remove hover/platform/idle power."})
    return {"schema":1,"model":VERSION,"parameters":parameters,"parameter_sha256":parameter_sha256,
        "runs":runs,"pairs":pairs,"qos_accepted":False,"energy_saving_established":False,
        "scope":"All values are ESTIMATED under the supplied assumptions. Nominal full delivery, partial old TX accounting, and new link-counter estimates are separate. Source failures are retained.",
        "software_sha256":{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ("core/uav_energy_model.py","sim/report_uav_energy.py")}}


def write_report(result, folder):
    folder=Path(folder)
    folder.mkdir(parents=True,exist_ok=False)
    (folder/"energy-report.json").write_text(json.dumps(result,indent=2,allow_nan=False)+"\n")
    lines=["# Estimated UAV energy", "", "Parameter status: **"+result["parameters"]["status"]+"**.",
        "",result["scope"],"", "No QoS PASS or energy-saving claim is issued.",""]
    for row in result["runs"]:
        title="Scenario %s, %s, %s" % (row["scenario"],row["weights"],row["pair"])
        print("\n"+title+" | source: "+row["source_verdict_retained"])
        estimate=row["nominal_25pct_4s"]
        print("ASSUMED same 4s full-delivery workload; NOT measured consumption")
        lines += ["## "+title,"","Source verdict retained: "+row["source_verdict_retained"],"",
            "### Nominal equal workload (4 seconds; payload bytes only)","",
            "| UAV | Hover J | Platform + idle J | TX + RX increment J | Estimated total J |",
            "|---|---:|---:|---:|---:|"]
        for name,e in estimate["per_uav"].items():
            print("  %s: total %.6f J; traffic increment %.6f J" % (name,e["estimated_total_j"],e["tx_increment_j"]+e["rx_increment_j"]))
            lines.append("| %s | %.6f | %.6f | %.6f | %.6f |" % (name,e["hover_j"],e["platform_j"]+e["radio_idle_j"],e["tx_increment_j"]+e["rx_increment_j"],e["estimated_total_j"]))
        print("  ALL UAVs:",round(estimate["estimated_total_j"],6),"J (assumed workload)")
        lines += ["", "Nominal total: %.6f J." % estimate["estimated_total_j"],"",
            "Old TX component: "+row["old_qdisc_tx_component"]["status"]+". This is not a full energy total.","",
            "New timed RX/TX observation: "+row["counter_informed_estimate"]["status"]+".",""]
        full=row["counter_informed_estimate"]
        print("  Timed RX/TX observation:",full["status"])
        if full["status"]=="ESTIMATED_FROM_LINK_COUNTERS":
            print("  Sum over observed per-node intervals:",round(full["sum_per_node_interval_energy_j"],6),"estimated J; NOT an equal-40s comparison")
            lines += ["| UAV | Observation seconds | RX bytes | TX bytes | Estimated J |",
                "|---|---:|---:|---:|---:|"]
            for name,e in full["per_uav"].items():
                lines.append("| %s | %.6f | %d | %d | %.6f |" % (name,e["duration_s"],e["rx_bytes"],e["tx_bytes"],e["estimated_total_j"]))
            lines += ["",full["scope"],"",full["normalization_caveat"],""]
    for pair in result["pairs"]:
        print("PAIR",pair["scenario"],pair["pair"],pair["status"])
        if "nominal_adaptive_minus_fixed_j" in pair:
            print("  Nominal adaptive minus fixed:",round(pair["nominal_adaptive_minus_fixed_j"],9),"J")
            print("  Per-UAV nominal differences:",{k:round(v,9) for k,v in pair["nominal_per_uav_adaptive_minus_fixed_j"].items()})
            lines += ["## Pair %s/%s" % (pair["scenario"],pair["pair"]),"",
                "Nominal adaptive minus fixed: %.9f J." % pair["nominal_adaptive_minus_fixed_j"],"",pair["scope"],""]
    (folder/"energy-report.md").write_text("\n".join(lines)+"\n")
    print("\nParameter status:",result["parameters"]["status"],"| No measured-energy/QoS claim.")
    print("Saved:",folder)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs",type=Path,nargs="+")
    parser.add_argument("--parameters",type=Path,required=True)
    parser.add_argument("--allow-illustrative",action="store_true")
    args=parser.parse_args(argv)
    try:
        params,sha=load_parameters(args.parameters,args.allow_illustrative)
        result=build_report(args.runs,params,sha)
        folder=ROOT/"results/energy-estimates"/(dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:12])
        write_report(result,folder)
        return 0
    except (OSError,ValueError,KeyError,TypeError) as error:
        print("Energy analysis stopped:",error)
        return 1


if __name__=="__main__":
    sys.exit(main())
