"""Constants and tc configuration for a separate, bounded functional check.

Configured HTB service and admission budgets are not measured QoS guarantees.
The video meter is an ingress policer; it does not adapt the media source.
"""

COOKIE = 0x7B00000000000000
COOKIE_MASK = 0xFF00000000000000
PRIORITY = 200
GUARD_PRIORITY = 190
METER_BASE = 180000
MAX_EPOCH = 30
BASE_VLANS = {0: 3000, 46: 3001, 34: 3002}
ROOT_HANDLE = "7e00:"
CLASS_MINOR = {"VOICE": "10", "VIDEO": "20", "CONTROL": "30"}


def vlan_id(dscp, epoch):
    if type(epoch) is not int or not 0 <= epoch <= MAX_EPOCH:
        raise ValueError("Protected VLAN epochs exhausted")
    return BASE_VLANS[dscp] + 32 * epoch


def meter_id(epoch):
    vlan_id(34, epoch)
    return METER_BASE + epoch


def queue_commands(interface, delay_ms):
    """Replace ONLY egress root; leave clsact/ingress redirect unchanged.

    Child rates sum to 5 Mbps. Video can borrow unused voice service up to
    4.4 Mbps. Admission forbids full video and voice sharing a forward relay.
    In the shared profile the video ingress meter caps it at 3.6 Mbps.
    Reverse traffic is classified but not admitted/reserved by the planner.
    """
    dev = ["tc"]
    commands = [dev + ["qdisc", "replace", "dev", interface, "root", "handle", ROOT_HANDLE,
                       "htb", "default", "30", "r2q", "100"],
                dev + ["class", "add", "dev", interface, "parent", ROOT_HANDLE,
                       "classid", "7e00:1", "htb", "rate", "5mbit", "ceil", "5mbit",
                       "burst", "16k", "cburst", "16k"]]
    for minor, rate, ceil, prio, handle in (
            ("10", "1.3mbit", "1.3mbit", "0", "7e10:"),
            ("20", "3.6mbit", "4.4mbit", "1", "7e20:"),
            ("30", "0.1mbit", "0.1mbit", "2", "7e30:")):
        commands.append(dev + ["class", "add", "dev", interface, "parent", "7e00:1",
                               "classid", "7e00:" + minor, "htb", "rate", rate,
                               "ceil", ceil, "prio", prio, "quantum", "1514",
                               "burst", "16k", "cburst", "16k"])
        commands.append(dev + ["qdisc", "add", "dev", interface, "parent", "7e00:" + minor,
                               "handle", handle, "netem", "delay", str(delay_ms) + "ms",
                               "limit", "100"])
    # Tagged packets are expected inside the UAV wires. The IP variant also
    # handles VLAN acceleration exposing the inner protocol to the classifier.
    for protocol, extra, offset in (("802.1Q", ["vlan_ethtype", "ipv4"], 0), ("ip", [], 100)):
        for pref, tos, minor in (("10", "0xb8/0xfc", "10"), ("20", "0x88/0xfc", "20")):
            commands.append(dev + ["filter", "add", "dev", interface, "parent", ROOT_HANDLE,
                                   "protocol", protocol, "pref", str(int(pref) + offset), "flower", "skip_hw"]
                            + extra + ["ip_tos", tos, "classid", "7e00:" + minor])
    return commands


def restore_commands(interface, delay_ms):
    # The runner accepts ONLY the unmodified topology layout before replacing
    # it. These restore that configuration, not historical counter values.
    return [
        ["tc", "qdisc", "replace", "dev", interface, "root", "handle", "1:",
         "htb", "default", "10", "r2q", "100"],
        ["tc", "class", "add", "dev", interface, "parent", "1:", "classid", "1:10",
         "htb", "rate", "5mbit", "ceil", "5mbit", "burst", "16k", "cburst", "16k"],
        ["tc", "qdisc", "add", "dev", interface, "parent", "1:10", "handle", "10:",
         "netem", "delay", str(delay_ms) + "ms", "limit", "100"],
    ]


def class_packets(text, minor):
    import re
    match = re.search(r"^class htb 7e00:" + re.escape(minor)
                      + r"\b[^\n]*\n\s*Sent \d+ bytes (\d+) pkt\b", text, re.M)
    if match is None:
        raise ValueError("Missing tc class packet counter: 7e00:" + minor)
    return int(match[1])
