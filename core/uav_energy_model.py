"""Assumption-based UAV energy accounting; no network or battery-state writes.

Hovering and electronics power remain present on unused, still airborne UAVs.
Per-bit coefficients are incremental ABOVE the always-on radio baseline.
Virtual interface bytes are workload proxies, not measured RF airtime.
"""
import copy
import hashlib
import json
import math
from pathlib import Path
import re

VERSION = "uav-energy-accounting-v1"
FIELDS = ("hover_w", "platform_w", "radio_idle_w", "tx_increment_j_per_bit", "rx_increment_j_per_bit")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value, label):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
            label+" must be finite and nonnegative")
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()


def validate_parameters(document, allow_illustrative=False):
    require(isinstance(document,dict),"Parameters must be a JSON object")
    require(document.get("schema") == 1, "Unsupported parameter schema")
    require(document.get("status") in ("ILLUSTRATIVE", "USER_ASSUMPTIONS"), "Unknown parameter status")
    require(document["status"] != "ILLUSTRATIVE" or allow_illustrative,
            "Illustrative numbers require --allow-illustrative; they are not hardware measurements")
    require(isinstance(document.get("provenance"),str) and document["provenance"].strip(), "Parameter provenance is required")
    require(document.get("model") == VERSION, "Wrong energy model")
    require(document.get("assumptions") == {
        "all_uavs_hovering": True, "all_radios_powered": True,
        "automatic_sleep": False, "battery_feedback": False}, "Explicit always-on/hovering assumptions required")
    nodes = document.get("uavs")
    require(isinstance(nodes,dict) and bool(nodes), "Per-UAV parameters required")
    for name, values in nodes.items():
        require(isinstance(name,str) and re.fullmatch(r"UAV[A-Za-z0-9_]+",name), "Invalid UAV name")
        require(isinstance(values,dict) and set(values) == set(FIELDS), name+": parameter names differ")
        for key in FIELDS:
            number(values[key],name+"."+key)
    return copy.deepcopy(document)


def load_parameters(path, allow_illustrative=False):
    path = Path(path)
    raw = path.read_bytes()
    doc = validate_parameters(json.loads(raw),allow_illustrative)
    return doc,hashlib.sha256(raw).hexdigest()


def estimate_node(duration_s, tx_bytes, rx_bytes, parameters):
    """All hardware remains on and hovering for the full stated duration."""
    number(duration_s,"duration_s")
    number(tx_bytes,"tx_bytes")
    number(rx_bytes,"rx_bytes")
    require(duration_s > 0, "Positive duration required")
    result = {"hover_j": parameters["hover_w"]*duration_s,
        "platform_j": parameters["platform_w"]*duration_s,
        "radio_idle_j": parameters["radio_idle_w"]*duration_s,
        "tx_increment_j": 8*tx_bytes*parameters["tx_increment_j_per_bit"],
        "rx_increment_j": 8*rx_bytes*parameters["rx_increment_j_per_bit"]}
    for key,value in result.items():
        number(value,key)
    result["estimated_total_j"] = sum(result.values())
    number(result["estimated_total_j"],"estimated_total_j")
    return result


def nominal_plan(plan, parameters, duration_s=4.0):
    """Equal-duration hypothetical full delivery; NOT reconstructed traffic.

Count UDP payload bytes only, in both receive and transmit directions at each
forward relay. No frame/PHY overhead or reverse/control traffic is invented.
This model workload is kept separate from interface/qdisc byte observations.
"""
    number(duration_s,"duration_s")
    require(duration_s>0,"Positive nominal duration required")
    nodes = parameters["uavs"]
    require(set(plan["states"]) == set(nodes), "Plan and parameter UAV sets differ")
    used = {name:0.0 for name in nodes}
    classes = plan["classes"]
    require(len(classes)==2 and {r["name"] for r in classes}=={"VOICE","VIDEO"}, "Two expected services required")
    delivered = 0.0
    for row in classes:
        require(row.get("admitted") is True and row.get("decision") in ("VOICE_ADMITTED","VIDEO_ADMITTED_FULL"),
                "Nominal full-delivery calculation refuses downgraded/rejected services")
        rate = number(row["requested_payload_mbps"],"requested_payload_mbps")
        require(rate>0,"Positive requested payload rate required")
        path = row["path"]
        require(len(path)>=3 and len(set(path))==len(path), "Expected a simple relay path")
        require(all(n in nodes for n in path[1:-1]), "Unknown intermediate relay")
        payload_bytes = rate*1e6*duration_s/8
        delivered += payload_bytes
        for name in path[1:-1]:
            used[name] += payload_bytes
    per_uav = {name:{"duration_s":duration_s,"assumed_tx_payload_bytes":b,
        "assumed_rx_payload_bytes":b, **estimate_node(duration_s,b,b,nodes[name])}
        for name,b in used.items()}
    total = sum(v["estimated_total_j"] for v in per_uav.values())
    return {"status":"HYPOTHETICAL_FULL_DELIVERY", "duration_s":duration_s,
        "byte_basis":"UDP payload-only; no PHY/MAC/header/control/retry overhead",
        "per_uav":per_uav,"estimated_total_j":total,
        "assumed_delivered_udp_mbit":delivered*8/1e6,
        "estimated_j_per_assumed_delivered_udp_mbit":total/(delivered*8/1e6),
        "scope":"Same 4s workload and always-hovering/on assumptions. Not measured consumption or proof of QoS."}


def root_counter(text):
    blocks = re.split(r"(?=^qdisc )",text,flags=re.M)
    roots = [b for b in blocks if re.match(r"qdisc htb 7e00: root\b",b)]
    require(len(roots)==1,"Expected exactly one owned HTB root; child counters must not be added")
    found = re.search(r"^\s*Sent (\d+) bytes (\d+) pkt \(dropped (\d+),",roots[0],re.M)
    require(found is not None,"Missing root byte/packet/drop counters")
    return dict(zip(("bytes","packets","drops"),map(int,found.groups())))


def old_tx_component(folder, parameters):
    """Only the TX incremental component can use the old qdisc snapshots."""
    folder=Path(folder)
    nodes={}
    for name,p in parameters["uavs"].items():
        interfaces={}
        for index in (0,1):
            interface=name.lower()+"-eth"+str(index)
            before=root_counter((folder/("queue-before-"+interface+".txt")).read_text())
            after=root_counter((folder/("queue-final-"+interface+".txt")).read_text())
            delta={k:after[k]-before[k] for k in before}
            require(all(v>=0 for v in delta.values()),"Counter reset at "+interface)
            interfaces[interface]=delta
        amount=sum(v["bytes"] for v in interfaces.values())
        nodes[name]={"interfaces":interfaces,"dequeued_bytes":amount,
            "estimated_tx_increment_only_j":8*amount*p["tx_increment_j_per_bit"]}
    return {"status":"PARTIAL_TX_COMPONENT_ONLY","per_uav":nodes,
        "estimated_tx_increment_only_j":sum(v["estimated_tx_increment_only_j"] for v in nodes.values()),
        "estimated_total_energy_j":None,
        "scope":"Both egress roots, counted once; includes control/reverse/header bytes as accounted by tc. RX and timed flight/electronics data are missing. No full energy total."}


def snapshot_energy(before, after, parameters):
    """Calculate per-node observation-interval estimates and timing brackets."""
    require(set(before)==set(after)==set(parameters["uavs"]),"Snapshot UAV sets differ")
    nodes={}
    for name,p in parameters["uavs"].items():
        left,right=before[name],after[name]
        require(left.get("container_id") and left.get("container_pid") and
                left["container_id"]==right.get("container_id") and left["container_pid"]==right.get("container_pid"),
                "Container replaced/restarted or identity missing: "+name)
        lb,le=left["begin"]["monotonic_ns"],left["end"]["monotonic_ns"]
        rb,re_=right["begin"]["monotonic_ns"],right["end"]["monotonic_ns"]
        require(all(type(t) is int and t>=0 for t in (lb,le,rb,re_)),"Invalid monotonic timestamps")
        require(lb<=le<rb<=re_,"Overlapping or reversed snapshot brackets")
        require(set(left["interfaces"])==set(right["interfaces"])=={name.lower()+"-eth0",name.lower()+"-eth1"},"Expected two UAV interfaces")
        totals={k:0 for k in ("rx_bytes","tx_bytes","rx_packets","tx_packets","rx_dropped","tx_dropped","rx_errors","tx_errors")}
        for interface,a in left["interfaces"].items():
            b=right["interfaces"][interface]
            require(a["ifindex"]==b["ifindex"] and a["address"]==b["address"],"Interface replaced: "+interface)
            for key in totals:
                require(type(a[key]) is int and type(b[key]) is int and a[key]>=0 and b[key]>=a[key],"Invalid/reset link counter: "+interface+"."+key)
                totals[key]+=b[key]-a[key]
        lower,upper=(rb-le)/1e9,(re_-lb)/1e9
        duration=(lower+upper)/2
        row={**totals,"duration_s":duration,"duration_bounds_s":[lower,upper],
            **estimate_node(duration,totals["tx_bytes"],totals["rx_bytes"],p)}
        row["energy_bounds_due_to_snapshot_timing_j"]=[
            estimate_node(t,totals["tx_bytes"],totals["rx_bytes"],p)["estimated_total_j"] for t in (lower,upper)]
        nodes[name]=row
    return {"status":"ESTIMATED_FROM_LINK_COUNTERS", "per_uav":nodes,
        "sum_per_node_interval_energy_j":sum(r["estimated_total_j"] for r in nodes.values()),
        "sum_timing_bounds_j":[sum(r["energy_bounds_due_to_snapshot_timing_j"][i] for r in nodes.values()) for i in (0,1)],
        "scope":"Sum over per-node, bracketed observation intervals including traffic setup and capture tail. Boundaries are not perfectly synchronized. Byte-based RF/processing work is an assumption, not a physical power measurement. No takeoff, landing, motion, PHY overhead or retransmission model."}
