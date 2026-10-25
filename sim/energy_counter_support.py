"""Read two virtual link counters per UAV, without changing network settings."""
import json
import subprocess
import time


def clock():
    return {"monotonic_ns":time.monotonic_ns(),"wall_ns":time.time_ns()}


def read_snapshot(names, run=subprocess.run):
    result={}
    for name in names:
        identity=run(["sudo","-n","docker","inspect","--format","{{.Id}} {{.State.Pid}} {{.State.Running}}","mn."+name.lower()],
            capture_output=True,text=True,timeout=10)
        fields=identity.stdout.strip().split()
        if identity.returncode or len(fields)!=3 or fields[2]!="true" or not fields[1].isdigit() or int(fields[1])<=1:
            raise RuntimeError("Cannot verify running container identity: "+name)
        begin=clock()
        answer=run(["sudo","-n","docker","exec","mn."+name.lower(),"ip","-s","-j","link","show"],
            capture_output=True,text=True,timeout=10)
        end=clock()
        if answer.returncode:
            raise RuntimeError("Cannot read link counters at "+name+": "+answer.stderr.strip())
        rows=json.loads(answer.stdout)
        interfaces={}
        for i in (0,1):
            interface=name.lower()+"-eth"+str(i)
            selected=[row for row in rows if row["ifname"]==interface]
            if len(selected)!=1 or "UP" not in selected[0].get("flags",[]):
                raise ValueError("Required interface is missing/down: "+interface)
            row=selected[0]
            counters=row.get("stats64",row.get("stats"))
            if not isinstance(counters,dict):
                raise ValueError("Missing link statistics: "+interface)
            values={"ifindex":row["ifindex"],"address":row["address"]}
            for direction in ("rx","tx"):
                for key in ("bytes","packets","dropped","errors"):
                    value=counters[direction][key]
                    if type(value) is not int or value<0:
                        raise ValueError("Invalid link statistic")
                    values[direction+"_"+key]=value
            interfaces[interface]=values
        result[name]={"begin":begin,"end":end,"interfaces":interfaces,
            "container_id":fields[0],"container_pid":int(fields[1])}
    return result
