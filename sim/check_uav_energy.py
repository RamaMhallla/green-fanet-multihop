"""Offline arithmetic and accounting checks; no network or state changes."""
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
from core.uav_energy_model import estimate_node, load_parameters, nominal_plan
from core.weight_comparison_policy import common_initial, plan_weight_comparison
from core.lab_scenario import STATES
from config import params as P


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parameters",type=Path,default=ROOT/"config/energy_model.example.json")
    parser.add_argument("--allow-illustrative",action="store_true")
    args=parser.parse_args(argv)
    parameters,sha=load_parameters(args.parameters,args.allow_illustrative)
    p=next(iter(parameters["uavs"].values()))
    idle=estimate_node(4,0,0,p)
    expected=4*(p["hover_w"]+p["platform_w"]+p["radio_idle_w"])
    if abs(idle["estimated_total_j"]-expected)>1e-9:
        raise ValueError("Idle/hover arithmetic failed")
    results={}
    for scenario in ("A","B"):
        estimates={}
        for mode in ("fixed","adaptive"):
            states=copy.deepcopy(STATES)
            states["UAV1"]["energy_fraction"]=.90
            plan=common_initial(P,states,scenario)
            for battery in (.30,.25):
                states["UAV1"]["energy_fraction"]=battery
                plan=plan_weight_comparison(P,states,scenario,plan,mode)
            estimates[mode]=nominal_plan(plan,parameters)
        results[scenario]=estimates
        print("\nSCENARIO",scenario,"| ASSUMED full delivery for the same 4 seconds")
        for mode,e in estimates.items():
            print("%s: all UAVs %.6f estimated J; UAV1 %.6f estimated J" %
                (mode,e["estimated_total_j"],e["per_uav"]["UAV1"]["estimated_total_j"]))
        print("Nominal adaptive minus fixed: %.9f J" %
            (estimates["adaptive"]["estimated_total_j"]-estimates["fixed"]["estimated_total_j"]))
    folder=ROOT/"results/energy-model-checks"/(dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    result={"status":"MODEL_CHECK_PASSED","model_only":True,"parameters":parameters,
        "parameter_sha256":sha,"scenarios":results,"qos_accepted":False,"energy_saving_established":False,
        "source_sha256":{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
            ("core/uav_energy_model.py","sim/check_uav_energy.py","core/weight_comparison_policy.py","config/params.py")}}
    (folder/"model-check.json").write_text(json.dumps(result,indent=2,allow_nan=False)+"\n")
    print("\nENERGY MODEL CHECK: PASS (arithmetic/model only)")
    print("Parameter status:",parameters["status"],"| No hardware, QoS or energy-saving claim.")
    print("Saved:",folder/"model-check.json")
    return 0


if __name__=="__main__":
    try:
        sys.exit(main())
    except (OSError,ValueError,KeyError,TypeError) as error:
        print("Model check stopped:",error)
        sys.exit(1)
