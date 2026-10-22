"""Fully offline 90..0% decision map, six arms, A/B, two history designs.

Uses only Python's standard library. No sudo, traffic, containers, Ryu or
runtime-state writes. Figures are standalone SVG files plus an HTML index.
"""
import copy
import csv
import datetime as dt
import hashlib
from html import escape
import json
from pathlib import Path
import sys
import uuid

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from core.planner_map_policy import METHODS, plan_family
from core.weight_comparison_policy import common_initial, plan_weight_comparison, weights_for
from core.joint_battery_policy import candidate, plan_joint_protected, validate
from core.battery_policy import DEFAULT_CONFIG, plan_protected, plan_signature
from core.lab_scenario import STATES
from config import params as P

WEIGHTS=("fixed","adaptive")
HISTORIES=("sequential","single_step")
PERCENTS=tuple(range(90,-1,-1))
PALETTE=("#286c87","#6c4d96","#28734e","#9c591b","#93495e","#42629a","#756522","#326a6a")


def compact(plan,scenario,history,method,mode,percent):
    seeded=percent==90
    def flow(row):
        return {k:(None if k=="cost" and seeded else copy.deepcopy(row.get(k))) for k in
            ("name","admitted","decision","path","resource_type","scheduler_budget_mbps",
             "meter_cap_mbps","configured_delay_ms","delay_budget_ms","cost")}
    return {"scenario":scenario,"history":history,"method":method,"weights":mode,
        "battery_pct":percent,"decision_origin":"SHARED_INITIAL_ASSIGNMENT" if seeded else "REPLAN",
        "blocked_relays":plan["blocked_relays"],"allocations_mbps":plan["forward_scheduler_allocations_mbps"],
        "uav1_allocated_mbps":plan["forward_scheduler_allocations_mbps"]["UAV1"],
        "guard_enabled":method!="greedy","joint_selection":method=="joint_guard",
        "guard_caps_mbps":plan.get("guard_capacities_mbps",plan["usable_capacities_mbps"]),
        "discharge_caps_mbps":plan.get("discharge_caps_mbps",{}),
        "guard_blocks_feasible_voice":plan.get("guard_blocks_feasible_voice",False),
        "relay_weights":weights_for(plan["states"],mode),
        "voice":flow(plan["classes"][0]),"video":flow(plan["classes"][1])}


def event_summary(rows):
    summary={key:None for key in ("first_voice_route_change_pct","first_video_route_change_pct",
        "first_video_leaves_uav1_pct","first_video_downgrade_pct","first_uav1_excluded_pct",
        "first_uav1_allocation_increase_pct","first_voice_rejection_pct")}
    transitions=[]
    previous=None
    def route(row,name):return tuple(row[name]["path"] or [])
    for row in rows:
        p=row["battery_pct"]
        for key,condition in (("first_video_downgrade_pct",row["video"]["decision"]=="VIDEO_DOWNGRADED"),
            ("first_uav1_excluded_pct","UAV1" in row["blocked_relays"]),
            ("first_voice_rejection_pct",not row["voice"]["admitted"])):
            if condition and summary[key] is None:summary[key]=p
        if previous is not None:
            changes=[]
            for name in ("voice","video"):
                if route(row,name)!=route(previous,name):
                    changes.append(name+"_route")
                    key="first_"+name+"_route_change_pct"
                    if summary[key] is None:summary[key]=p
                if row[name]["decision"]!=previous[name]["decision"]:changes.append(name+"_profile")
            if ("UAV1" in route(previous,"video") and row["video"]["admitted"]
                    and "UAV1" not in route(row,"video") and summary["first_video_leaves_uav1_pct"] is None):
                summary["first_video_leaves_uav1_pct"]=p
            if row["uav1_allocated_mbps"]>previous["uav1_allocated_mbps"]+1e-9:
                changes.append("uav1_allocation_increase")
                if summary["first_uav1_allocation_increase_pct"] is None:summary["first_uav1_allocation_increase_pct"]=p
            if row["blocked_relays"]!=previous["blocked_relays"]:changes.append("exclusion")
            if changes:
                transitions.append({"previous_sample_pct":previous["battery_pct"],"first_changed_sample_pct":p,
                    "changes":changes,"voice_path":row["voice"]["path"],"video_path":row["video"]["path"],
                    "video_decision":row["video"]["decision"],"uav1_allocated_mbps":row["uav1_allocated_mbps"]})
        previous=row
    return {**summary,"transitions":transitions}


def scan(params=P, initial_states=STATES):
    rows=[];summaries=[];checks=0;seeds={}
    for scenario in ("A","B"):
        initial=copy.deepcopy(initial_states)
        initial["UAV1"]["energy_fraction"]=.90
        seed=common_initial(params,initial,scenario)
        seeds[scenario]=seed
        for history in HISTORIES:
            for method in METHODS:
                for mode in WEIGHTS:
                    previous=copy.deepcopy(seed)
                    trajectory=[]
                    for percent in PERCENTS:
                        state=copy.deepcopy(initial)
                        state["UAV1"]["energy_fraction"]=percent/100
                        prior=previous if history=="sequential" else seed
                        if percent==90:
                            plan=copy.deepcopy(seed)
                        else:
                            plan=plan_family(params,state,scenario,prior,method,mode)
                            reference=None
                            if method=="joint_guard":
                                reference=(plan_joint_protected(params,state,scenario,prior) if mode=="adaptive"
                                    else plan_weight_comparison(params,state,scenario,prior,"fixed"))
                            elif mode=="adaptive":
                                reference=(plan_protected(params,state,scenario) if method=="greedy" else
                                    candidate(params,state,scenario,prior,joint=False,guard=True))
                            if reference is not None:
                                if plan_signature(plan)!=plan_signature(reference):
                                    raise ValueError("Existing planner parity failed: %s/%s/%s/%s/%d" % (scenario,history,method,mode,percent))
                                checks+=1
                        validate(plan)
                        if history=="sequential" and method!="greedy" and percent<90:
                            if plan["forward_scheduler_allocations_mbps"]["UAV1"]>previous["forward_scheduler_allocations_mbps"]["UAV1"]+1e-9:
                                raise ValueError("Guard allowed an allocation increase during sequential discharge")
                        row=compact(plan,scenario,history,method,mode,percent)
                        rows.append(row);trajectory.append(row)
                        previous=plan
                    summaries.append({"scenario":scenario,"history":history,"method":method,"weights":mode,
                        **event_summary(trajectory)})
    return {"schema":1,"protocol":"planner-decision-map-v1","status":"OFFLINE_CHECK_PASSED",
        "resolution_percentage_points":1,"battery_samples":list(PERCENTS),"methods":list(METHODS),
        "weight_modes":list(WEIGHTS),"histories":list(HISTORIES),"shared_initial_plans":seeds,
        "selection_priorities":{
            "greedy":"Choose the cheapest feasible VOICE route first; then full VIDEO, capped VIDEO, or no VIDEO",
            "greedy_guard":"Same greedy choice with persistent discharge allocation caps",
            "joint_guard":"VOICE admission; VIDEO full/capped/rejected; VOICE cost; VIDEO cost, with persistent discharge caps"},
        "policy_config":copy.deepcopy(seeds["A"]["config"]),
        "legacy_parity_checks":checks,"rows":rows,"summaries":summaries,
        "qos_accepted":False,"energy_saving_established":False,
        "scope":"Deterministic planner decisions under fixed model inputs. No traffic, measured delay, physical battery drain, recruiting or energy proof.",
        "history_scope":{"sequential":"90% common seed, then 89..0% using each arm's own previous accepted plan",
            "single_step":"Every 89..0% point starts independently from the SAME shared 90% plan; not a continuous trajectory"},
        "threshold_scope":"Strict battery <20% exclusion: 20% is allowed; first excluded integer sample is 19%. Transition resolution is 1 percentage point, not an exact continuous threshold.",
        "initial_scope":"The 90% allocation is inherited and shared, not re-optimized for each method. Costs at this seed point are null; subsequent points replan with the selected weights."}


def route_registry(rows):
    routes=sorted({tuple(r[name]["path"]) for r in rows for name in ("voice","video") if r[name]["path"]})
    return {path:("R"+str(i+1),PALETTE[i%len(PALETTE)]) for i,path in enumerate(routes)}


def figure(rows,scenario,history,method,registry):
    selected={w:[r for r in rows if r["scenario"]==scenario and r["history"]==history and r["method"]==method and r["weights"]==w] for w in WEIGHTS}
    routes=sorted({tuple(r[n]["path"]) for values in selected.values() for r in values for n in ("voice","video") if r[n]["path"]})
    width=1100;height=660+len(routes)*24
    left,right=220,1040;span=right-left
    def x(p):return left+(90-p)/90*span
    out=['<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="%d" viewBox="0 0 1100 %d" role="img">'%(height,height),
        '<title>%s: scenario %s, %s. Offline route decisions, not measured QoS.</title>'%(escape(method),scenario,history),
        '<rect width="1100" height="%d" fill="white"/>'%height,
        '<style>text{font-family:DejaVu Sans,Arial,sans-serif;fill:#172c40;font-size:13px}.title{font-size:22px;font-weight:bold}.muted{fill:#526474;font-size:12px}.tick{font-size:12px}</style>']
    def text(px,py,value,klass="",anchor="start"):
        out.append('<text x="%.2f" y="%.2f" class="%s" text-anchor="%s">%s</text>'%(px,py,klass,anchor,escape(str(value))))
    text(36,35,"Scenario %s | %s | %s"%(scenario,method.replace('_',' + '),history.replace('_',' ')),"title")
    text(36,60,"Fixed and adaptive WEIGHTS; both replan. Shared 90% initial assignment. 91 samples per arm.","muted")
    text(36,80,"Sequential = each arm keeps its own history. Single step = every point starts again from 90%.","muted")
    ys={('fixed','voice'):122,('fixed','video'):160,('adaptive','voice'):214,('adaptive','video'):252}
    for (mode,name),top in ys.items():
        values=selected[mode]
        text(36,top+20,mode.title()+" / "+name.upper())
        start=0
        while start<len(values):
            a=values[start];key=(tuple(a[name]["path"] or []),a[name]["decision"])
            end=start
            while end+1<len(values) and (tuple(values[end+1][name]["path"] or []),values[end+1][name]["decision"])==key:end+=1
            x1=max(left,x(a["battery_pct"]+.5));x2=min(right,x(values[end]["battery_pct"]-.5))
            code,color=registry.get(key[0],("NONE","#8c939b"))
            label=code+" / "+("capped 3.6" if key[1]=="VIDEO_DOWNGRADED" else "rejected" if not a[name]["admitted"] else "full")
            tip="%d%% to %d%%: %s; %s"%(a["battery_pct"],values[end]["battery_pct"]," -> ".join(key[0]),key[1])
            out.append('<rect x="%.3f" y="%d" width="%.3f" height="28" fill="%s" stroke="white"><title>%s</title></rect>'%(x1,top,x2-x1,color,escape(tip)))
            if key[1]=="VIDEO_DOWNGRADED":out.append('<rect x="%.3f" y="%d" width="%.3f" height="5" fill="#f7b548"/>'%(x1,top+23,x2-x1))
            if x2-x1>100:
                out.append('<text x="%.2f" y="%d" text-anchor="middle" style="fill:white;font-size:12px">%s</text>'%((x1+x2)/2,top+18,escape(label)))
            elif x2-x1>30:
                out.append('<text x="%.2f" y="%d" text-anchor="middle" style="fill:white;font-size:11px">%s</text>'%((x1+x2)/2,top+18,code))
            start=end+1
    for p in range(90,-1,-10):
        out.append('<line x1="%.2f" y1="284" x2="%.2f" y2="290" stroke="#607080"/>'%(x(p),x(p)))
        text(x(p),307,str(p),"tick","middle")
    text(left,330,"UAV1 scheduler allocation (Mbps) — a model budget, not measured traffic")
    plot_top,plot_bottom=355,495
    def y(v):return plot_bottom-v/5*(plot_bottom-plot_top)
    out.append('<rect x="%.2f" y="350" width="%.2f" height="145" fill="#f1f3f5"/>'%(x(20),right-x(20)))
    for value in (0,1.3,3.6,4.4,5):
        out.append('<line x1="%d" y1="%.2f" x2="%d" y2="%.2f" stroke="#e0e5ea"/>'%(left,y(value),right,y(value)))
        text(left-12,y(value)+4,str(value),"tick","end")
    for mode,color,dash in (("fixed","#182c40",""),("adaptive","#147e91","8 5")):
        points=[];previous=None
        for r in selected[mode]:
            px,py=x(r["battery_pct"]),y(r["uav1_allocated_mbps"])
            if previous is not None:points.append((px,previous))
            points.append((px,py));previous=py
        out.append('<polyline points="%s" fill="none" stroke="%s" stroke-width="3" stroke-dasharray="%s"/>'%(' '.join('%.3f,%.3f'%p for p in points),color,dash))
    for p in range(90,-1,-10):text(x(p),517,str(p),"tick","middle")
    text((left+right)/2,540,"UAV1 battery (%) — decreases from left to right",anchor="middle")
    out.append('<line x1="%.2f" y1="101" x2="%.2f" y2="495" stroke="#bb4450" stroke-width="1.5" stroke-dasharray="5 5"/>'%(x(20),x(20)))
    text(x(20)-8,99,"20% boundary","muted","end")
    text(36,565,"Allocation line: fixed = solid dark; adaptive = dashed blue. Orange bar underline = degraded video cap 3.6 Mbps.","muted")
    for i,mode in enumerate(WEIGHTS):
        summary=event_summary(selected[mode])
        def pct(key):
            value=summary[key]
            return "none" if value is None else str(value)+"%"
        text(36,590+22*i,mode.title()+": first video route change "+pct("first_video_route_change_pct")+
             "; first video leaves UAV1 "+pct("first_video_leaves_uav1_pct")+
             "; first downgrade "+pct("first_video_downgrade_pct")+".")
    for i,path in enumerate(routes):
        code,color=registry[path];py=640+24*i
        out.append('<rect x="36" y="%d" width="18" height="13" fill="%s"/>'%(py-11,color))
        text(66,py,code+": "+" -> ".join(path))
    text(36,height-14,"OFFLINE ONLY. 20% remains allowed; first excluded sample is 19%. No QoS, energy or recruiting benefit is established.","muted")
    out.append('</svg>')
    return '\n'.join(out)+'\n'


def save_outputs(report,folder):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=False)
    (folder/"scan.json").write_text(json.dumps(report,indent=2,allow_nan=False)+"\n")
    fields=("scenario","history","method","weights","battery_pct","voice_path","video_path","video_decision","voice_cost","video_cost","video_scheduler_mbps","video_meter_mbps","uav1_allocated_mbps","uav1_excluded","guard_blocks_feasible_voice")
    with (folder/"decisions.csv").open("w",newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=fields);writer.writeheader()
        for r in report["rows"]:
            writer.writerow({"scenario":r["scenario"],"history":r["history"],"method":r["method"],"weights":r["weights"],"battery_pct":r["battery_pct"],
                "voice_path":" -> ".join(r["voice"]["path"] or []),"video_path":" -> ".join(r["video"]["path"] or []),
                "video_decision":r["video"]["decision"],"voice_cost":r["voice"]["cost"],"video_cost":r["video"]["cost"],
                "video_scheduler_mbps":r["video"]["scheduler_budget_mbps"],"video_meter_mbps":r["video"]["meter_cap_mbps"],
                "uav1_allocated_mbps":r["uav1_allocated_mbps"],"uav1_excluded":"UAV1" in r["blocked_relays"],
                "guard_blocks_feasible_voice":r["guard_blocks_feasible_voice"]})
    with (folder/"transitions.csv").open("w",newline="") as handle:
        fields=("scenario","history","method","weights","previous_sample_pct","first_changed_sample_pct","changes","voice_path","video_path","video_decision","uav1_allocated_mbps")
        writer=csv.DictWriter(handle,fieldnames=fields);writer.writeheader()
        for s in report["summaries"]:
            for event in s["transitions"]:
                row={k:s[k] for k in ("scenario","history","method","weights")};row.update(event)
                for key in ("changes","voice_path","video_path"):row[key]=" -> ".join(row[key] or [])
                writer.writerow(row)
    registry=route_registry(report["rows"])
    figures=[]
    for scenario in ("A","B"):
        for history in HISTORIES:
            for method in METHODS:
                name="%s-%s-%s.svg"%(scenario,history,method)
                (folder/name).write_text(figure(report["rows"],scenario,history,method,registry))
                figures.append((scenario,history,method,name))
    lines=["# Offline planner decision map","",report["scope"],"",report["threshold_scope"],"",
        "Each pair compares fixed/adaptive weights with the SAME method and constraints. All six arms replan.",
        "The first point (90%) inherits a shared initial assignment. Single-step maps are independent counterfactuals, not discharge histories.",""]
    table=["| Scenario | History | Method | Weights | First video route change | First video leaves UAV1 | First downgrade | First exclusion |",
        "|---|---|---|---|---:|---:|---:|---:|"]
    for s in report["summaries"]:
        values=[s[k] for k in ("first_video_route_change_pct","first_video_leaves_uav1_pct","first_video_downgrade_pct","first_uav1_excluded_pct")]
        table.append("| %s | %s | %s | %s | %s |"%(s["scenario"],s["history"],s["method"],s["weights"]," | ".join("none" if x is None else str(x)+"%" for x in values)))
    lines+=table+["","Legacy parity checks: "+str(report["legacy_parity_checks"])+".","",
        "A smaller cost or earlier route move is not automatically better. Keep null results, adverse allocations and degradations.","",
        "Open index.html for all SVG figures. Full path/weight/guard data are in scan.json; numerical rows and transition brackets are in CSV."]
    (folder/"summary.md").write_text('\n'.join(lines)+'\n')
    html=['<!doctype html><html lang="en"><meta charset="utf-8"><title>Offline planner decision map</title>',
        '<style>body{font:16px system-ui,sans-serif;color:#172c40;max-width:1160px;margin:32px auto;padding:0 20px;background:#fafbfc}img{width:100%;height:auto;background:white;border:1px solid #dde4eb;margin:12px 0}summary{cursor:pointer;font-weight:bold;padding:14px;background:#e7eff4}p{line-height:1.55}a{color:#176b83}</style>',
        '<h1>Offline planner decision map</h1><p>'+escape(report["scope"])+'</p>',
        '<p>'+escape(report["threshold_scope"])+'</p>',
        '<p>All arms replan. Compare weights within the same method and scenario. Grey/shaded weak region does not mean a physical link was disabled.</p>',
        '<p><a href="summary.md">Summary table</a> · <a href="decisions.csv">All decisions</a> · <a href="transitions.csv">Transitions</a> · <a href="scan.json">Full data</a></p>']
    for scenario in ("A","B"):
        for history in HISTORIES:
            html.append('<details%s><summary>Scenario %s — %s</summary>'%(' open' if history=="sequential" else '',scenario,history.replace('_',' ')))
            for a,b,method,name in figures:
                if (a,b)==(scenario,history):html.append('<h2>'+escape(method.replace('_',' + '))+'</h2><a href="'+name+'"><img src="'+name+'" alt="'+escape(method+' '+scenario+' '+history)+'"></a>')
            html.append('</details>')
    html.append('<p>No measured QoS or energy benefit is inferred. Points are 1% samples; lines are visual guides. Costs at the inherited 90% point are not compared.</p></html>')
    (folder/"index.html").write_text('\n'.join(html)+'\n')


def main():
    report=scan()
    report["source_sha256"]={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
        ("core/model.py","core/lab_scenario.py","core/battery_policy.py","core/joint_battery_policy.py",
         "core/weight_comparison_policy.py","core/planner_map_policy.py","sim/run_planner_decision_map.py","config/params.py")}
    report["python_version"]=sys.version
    folder=ROOT/"results/planner-decision-maps"/(dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:12])
    save_outputs(report,folder)
    print("OFFLINE MAP: PASS | %d rows | %d existing-planner parity checks"%(len(report["rows"]),report["legacy_parity_checks"]))
    print("All six arms REPLAN. Main result: sequential 90..0% discharge, 1% samples.")
    print("Scenario method weights | first video route change / first downgrade / first UAV1 exclusion")
    for s in report["summaries"]:
        if s["history"]=="sequential":
            values=[s[k] for k in ("first_video_route_change_pct","first_video_downgrade_pct","first_uav1_excluded_pct")]
            print(s["scenario"],s["method"],s["weights"],"|"," / ".join("none" if x is None else str(x)+"%" for x in values))
    print("20% is allowed; first excluded sample is 19%. No traffic, QoS or energy claim.")
    print("Summary:",folder/"summary.md")
    print("Figures:",folder/"index.html")
    return 0


if __name__=="__main__":
    try:
        sys.exit(main())
    except (OSError,ValueError,KeyError,TypeError) as error:
        print("Offline map stopped:",error)
        sys.exit(1)
