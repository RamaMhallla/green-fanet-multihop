"""Private support for the separate battery-enforcement check.

Readiness reads the configured lab topology, without importing or running any
legacy trial script. The only process action is stopping the Ryu process
explicitly owned by the new runner. All commands have bounded timeouts.
"""
import json
import math
import re
import signal
import subprocess

from config import params as P

def command(arguments, timeout=10):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Command failed: %s\n%s" %
                           (" ".join(arguments), result.stderr.strip()))
    return result.stdout


def stop_controller(process):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def quantity(token, kind):
    """Decode iproute2's displayed time/rate, e.g. 10000us or 5Mbit."""
    if kind == "delay":
        match = re.fullmatch(r"([0-9.]+)(ns|us|ms|s)", token)
        factors = {"ns": 1e-6, "us": 1e-3, "ms": 1, "s": 1000}
    else:
        match = re.fullmatch(r"([0-9.]+)(bit|Kbit|Mbit|Gbit)", token)
        factors = {"bit": 1e-6, "Kbit": 1e-3, "Mbit": 1, "Gbit": 1000}
    if match is None:
        raise ValueError("Unrecognized tc %s value: %r" % (kind, token))
    return float(match[1]) * factors[match[2]]


def validate_tc(interface, destination, qdiscs, classes, filters):
    """Require our topology's installed queues and tc-wire action, read-only."""
    if not re.search(r"^qdisc htb 1: root\b[^\n]*\bdefault (?:0x)?10\b", qdiscs, re.M):
        raise ValueError("%s: HTB root/default class is not ready" % interface)
    netem = re.search(r"^qdisc netem 10: parent 1:10\b([^\n]*)", qdiscs, re.M)
    if netem is None:
        raise ValueError("%s: netem is not ready" % interface)
    delay = re.search(r"\bdelay (\S+)", netem[1])
    # tc omits the delay field for a configured zero delay.
    measured = quantity(delay[1], "delay") if delay else 0.0
    if not math.isclose(measured, float(P.UAV_DELAY_MS), rel_tol=1e-5, abs_tol=1e-5):
        raise ValueError("%s: netem delay does not match config" % interface)
    limit = re.search(r"\blimit (\d+)\b", netem[1])
    if limit is None or int(limit[1]) != 100:
        raise ValueError("%s: expected netem limit 100" % interface)
    selected = re.search(r"^class htb 1:10\b([^\n]*)", classes, re.M)
    if selected is None:
        raise ValueError("%s: HTB class is not ready" % interface)
    for name in ("rate", "ceil"):
        value = re.search(r"\b%s (\S+)" % name, selected[1])
        if value is None or not math.isclose(quantity(value[1], "rate"),
                                            float(P.UAV_BW_MBPS), rel_tol=1e-5):
            raise ValueError("%s: HTB %s does not match config" % (interface, name))
    if ("matchall" not in filters
            or not re.search(r"mirred \(Egress Redirect to device %s\)" %
                             re.escape(destination), filters)):
        raise ValueError("%s: ingress tc wire to %s is not ready" %
                         (interface, destination))


def topology_snapshot():
    """Read actual container settings, independently of Ryu's barrier."""
    evidence = {"uavs": {}, "endpoints": {}}
    for drone in P.DRONES:
        container = "mn." + drone.lower()
        prefix = ["sudo", "-n", "docker", "exec", container]
        addresses = json.loads(command(prefix + ["ip", "-j", "address", "show"], timeout=5))
        by_name = {entry["ifname"]: entry for entry in addresses}
        interfaces = {}
        for index in (0, 1):
            interface = drone.lower() + "-eth" + str(index)
            other = drone.lower() + "-eth" + str(1 - index)
            link = by_name.get(interface, {})
            if "UP" not in link.get("flags", []):
                raise ValueError("%s is not up" % interface)
            if any(addr.get("family") == "inet" for addr in link.get("addr_info", [])):
                raise ValueError("%s still has an IPv4 address" % interface)
            qdiscs = command(prefix + ["tc", "-s", "qdisc", "show", "dev", interface], timeout=5)
            classes = command(prefix + ["tc", "-s", "class", "show", "dev", interface], timeout=5)
            filters = command(prefix + ["tc", "-s", "filter", "show", "dev", interface, "ingress"], timeout=5)
            validate_tc(interface, other, qdiscs, classes, filters)
            interfaces[interface] = {"address": link, "qdiscs": qdiscs,
                                     "classes": classes, "ingress_filters": filters}
        evidence["uavs"][drone] = interfaces
    for host, peer in (("u1", "gs"), ("gs", "u1")):
        prefix = ["sudo", "-n", "docker", "exec", "mn." + host]
        addresses = json.loads(command(prefix + ["ip", "-j", "address", "show"], timeout=5))
        ip, mac = P.HOSTS[host]
        local_ip, prefix_length = ip.split("/")
        link = next((entry for entry in addresses if any(
            addr.get("family") == "inet" and addr.get("local") == local_ip
            and addr.get("prefixlen") == int(prefix_length)
            for addr in entry.get("addr_info", []))), None)
        if (link is None or "UP" not in link.get("flags", [])
                or link.get("address", "").lower() != mac.lower()):
            raise ValueError("%s: endpoint address/link is not ready" % host)
        neighbours = json.loads(command(prefix + ["ip", "-j", "neigh", "show"], timeout=5))
        peer_ip, peer_mac = P.HOSTS[peer]
        if not any(entry.get("dst") == peer_ip.split("/")[0]
                   and entry.get("lladdr", "").lower() == peer_mac.lower()
                   and entry.get("dev") == link["ifname"]
                   and "PERMANENT" in entry.get("state", []) for entry in neighbours):
            raise ValueError("%s: permanent neighbour for %s is not ready" % (host, peer))
        evidence["endpoints"][host] = {"address": link, "neighbours": neighbours}
    return evidence
