import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from mininet.net import Containernet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import Link
from mininet.cli import CLI
from mininet.log import setLogLevel, info

from config import params as P


def checked(node, command):
    """Run a command in the node's network namespace and check its status."""
    output, error, status = node.pexec(command.split())
    if status != 0:
        raise RuntimeError(
            "%s: %s\n%s%s" % (node.name, command, output, error)
        )
    return output.strip()


def configure_wire(node):
    interfaces = [node.intfs[0].name, node.intfs[1].name]

    for interface in interfaces:
        checked(node, "ip -4 addr flush dev %s" % interface)
        checked(node, "ip link set dev %s up" % interface)
        checked(node, "ip link set dev %s promisc on" % interface)

        # Independent egress rate and delay in each direction.
        checked(node, "tc qdisc add dev %s root handle 1: htb default 10"
                " r2q 100" % interface)
        checked(node, "tc class add dev %s parent 1: classid 1:10 htb"
                " rate %smbit ceil %smbit burst 16k cburst 16k" %
                (interface, P.UAV_BW_MBPS, P.UAV_BW_MBPS))
        checked(node, "tc qdisc add dev %s parent 1:10 handle 10:"
                " netem delay %sms limit 100" %
                (interface, P.UAV_DELAY_MS))

        # Ingress redirection is separate from the egress queues above.
        checked(node, "tc qdisc add dev %s clsact" % interface)

    for source, destination in (
        (interfaces[0], interfaces[1]),
        (interfaces[1], interfaces[0]),
    ):
        checked(node, "tc filter add dev %s ingress protocol all pref 1"
                " matchall action mirred egress redirect dev %s" %
                (source, destination))

    info("*** %s: tc wire ready: %s <-> %s\n" %
         (node.name, interfaces[0], interfaces[1]))


def build(net):
    net.addController(
        "c0", controller=RemoteController,
        ip=P.CONTROLLER_IP, port=P.CONTROLLER_PORT,
    )
    switch = net.addSwitch(
        P.SWITCH_NAME,
        dpid="%016x" % P.SWITCH_DPID,
        protocols="OpenFlow13",
        failMode="secure",
    )

    ports = P.port_map()
    hosts = {}
    options = {
        "dimage": P.DOCKER_IMAGE,
        "network_mode": "none",
        "sysctls": {
            "net.ipv4.ip_forward": "0",
            "net.ipv6.conf.all.disable_ipv6": "1",
            "net.ipv6.conf.default.disable_ipv6": "1",
        },
    }

    for name, (ip, mac) in P.HOSTS.items():
        hosts[name] = net.addDocker(name, ip=ip, mac=mac, **options)
        net.addLink(hosts[name], switch, port1=0, port2=ports[name])

    for drone in P.DRONES:
        node = net.addDocker(drone.lower(), ip=None, **options)
        hosts[drone] = node
        net.addLink(
            node, switch, port1=0, port2=ports[(drone, "IN")],
            intfName1=node.name + "-eth0",
        )
        net.addLink(
            node, switch, port1=1, port2=ports[(drone, "OUT")],
            intfName1=node.name + "-eth1",
        )

    return hosts


def configure_hosts(hosts):
    for node in hosts.values():
        node.cmd("bind 'set enable-bracketed-paste off'")

    for drone in P.DRONES:
        configure_wire(hosts[drone])

    # Static neighbour entries for this first connectivity test.
    for source, destination in (("u1", "gs"), ("gs", "u1")):
        destination_ip, destination_mac = P.HOSTS[destination]
        interface = hosts[source].defaultIntf().name
        checked(hosts[source],
                "ip neigh replace %s lladdr %s nud permanent dev %s" %
                (destination_ip.split("/")[0], destination_mac, interface))


def main():
    setLogLevel("info")
    net = Containernet(controller=None, switch=OVSSwitch, link=Link)
    try:
        hosts = build(net)
        net.start()
        configure_hosts(hosts)
        info("*** Multi-hop topology ready; forwarding needs Ryu rules.\n")
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
