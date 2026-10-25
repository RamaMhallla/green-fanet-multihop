"""ONE existing weights trial with before/after read-only UAV link counters.

Same routes, traffic and source criteria; distinct instrumentation contract.
Do not mix a pair from this wrapper with an old non-instrumented trial.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import signal
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT),str(ROOT/"sim")]
from core.uav_energy_model import VERSION, digest, load_parameters, require


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario",choices=("A","B"),required=True)
    parser.add_argument("--weights",choices=("fixed","adaptive"),required=True)
    parser.add_argument("--pair",required=True)
    parser.add_argument("--parameters",type=Path,required=True)
    parser.add_argument("--allow-illustrative",action="store_true")
    args=parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}",args.pair):
        parser.error("Pair label must contain 1-40 letters, digits, underscores or hyphens")
    try:
        parameters,sha=load_parameters(args.parameters,args.allow_illustrative)
    except (OSError,ValueError,KeyError,TypeError) as error:
        print("Energy trial stopped before network setup:",error)
        return 1
    # Original runner owns preflight, trial lock, Ryu, queues, flow/meter cleanup.
    import run_weight_comparison as R
    from weight_comparison_capture import collect
    from weight_comparison_analysis import analyze
    from energy_counter_support import read_snapshot
    from report_uav_energy import build_report, write_report
    args.kind="udp"
    session=R.Trial(args)
    observation={"schema":1,"model":VERSION,"status":"starting","parameter_sha256":sha,
        "parameters":parameters,"instrumentation":"before/after ip -s -j link only; no in-traffic polling",
        "scope":"Per-node bracketed intervals enclose UDP collection, setup and capture tail; always-hovering/on are assumptions."}
    try:
        require(set(parameters["uavs"])==set(R.P.DRONES),"Configured UAV set differs from energy parameters")
        session.start()
        observation["instrumentation_version"]="weights-energy-observer-v1"
        session.report["energy_variant"]="weights-energy-observer-v1"
        contract=session.report["contract"]
        added=("core/uav_energy_model.py","sim/energy_counter_support.py","sim/run_weight_energy_trial.py","sim/report_uav_energy.py")
        for p in added:
            contract["source_sha256"][p]=hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
        contract["energy_instrumentation"]={"version":"weights-energy-observer-v1","model":VERSION,
            "parameter_sha256":sha,"parameter_status":parameters["status"],
            "snapshots":"two per UAV outside UDP collection; sequential and time-bracketed",
            "sleep_or_battery_feedback":False}
        session.report["source_sha256"]=dict(contract["source_sha256"])
        session.report["contract_sha256"]=digest(contract)
        observation["comparison_contract_sha256"]=session.report["contract_sha256"]
        session.write()
        observation["before"]=read_snapshot(R.P.DRONES)
        R.C.write_json(session.directory/"energy-counters.json",observation)
        print("Energy observer: all UAVs assumed hovering/on; model parameters:",parameters["status"],flush=True)
        collect(session)
        observation["after"]=read_snapshot(R.P.DRONES)
        session.finish_measurements()
        observation["status"]="collected"
    except (Exception,KeyboardInterrupt) as error:
        message=type(error).__name__+": "+str(error)
        session.report.update(status="failed",error=message)
        observation.update(status="failed",error=message)
        print("Energy trial stopped:",message,flush=True)
    finally:
        session.close()
        if session.report["status"]!="completed":
            observation["status"]="failed"
        if session.directory is not None:
            R.C.write_json(session.directory/"energy-counters.json",observation)
    if session.report["status"]!="completed":
        print("Evidence retained; cleanup:",session.report["cleanup_errors"])
        return 1
    try:
        traffic=analyze(session.directory)
        session.report["source_verdict"]=traffic["source_verdict"]
        session.write()
        observation["status"]="completed"
        observation["source_verdict_retained"]=traffic["source_verdict"]
        R.C.write_json(session.directory/"energy-counters.json",observation)
        report=build_report([session.directory],parameters,sha)
        write_report(report,session.directory/"energy-estimate")
    except (OSError,ValueError,RuntimeError,KeyError,TypeError) as error:
        session.report["energy_analysis_error"]=str(error)
        session.write()
        print("Energy analysis requires review; evidence retained:",error)
        return 1
    print("COMPLETED: instrumented",args.weights,"weights trial. Source/QoS verdicts unchanged; no energy-saving claim.")
    return 0


if __name__=="__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Termination requested")
    signal.signal(signal.SIGTERM,interrupted)
    sys.exit(main())
