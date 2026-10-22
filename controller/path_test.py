import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3

from config import params as P


def path_port_pairs(path, ports):
    """OVS ingress/output pairs; containers connect their own IN/OUT ports."""
    forward_inputs = [ports["u1"]] + [ports[(d, "OUT")] for d in path]
    forward_outputs = [ports[(d, "IN")] for d in path] + [ports["gs"]]

    reverse_path = list(reversed(path))
    reverse_inputs = [ports["gs"]] + [ports[(d, "IN")] for d in reverse_path]
    reverse_outputs = [ports[(d, "OUT")] for d in reverse_path] + [ports["u1"]]

    return (
        list(zip(forward_inputs, forward_outputs)),
        list(zip(reverse_inputs, reverse_outputs)),
    )


class PathTest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PathTest, self).__init__(*args, **kwargs)
        self.path = list(P.TEST_PATH)
        if not self.path or len(self.path) != len(set(self.path)):
            raise ValueError("TEST_PATH must be nonempty and contain no repeats")
        if any(drone not in P.DRONES for drone in self.path):
            raise ValueError("TEST_PATH contains an unknown drone")
        self.pending = set()
        self.setup_errors = set()

    def add_flow(self, dp, priority, match, actions, cookie=0):
        parser = dp.ofproto_parser
        instructions = []
        if actions:
            instructions.append(parser.OFPInstructionActions(
                dp.ofproto.OFPIT_APPLY_ACTIONS, actions,
            ))
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=instructions, cookie=cookie,
        ))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, event):
        dp = event.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        if dp.id != P.SWITCH_DPID:
            self.logger.error("Unexpected switch DPID: %s", dp.id)
            return

        self.setup_errors.discard(dp.id)
        # Remove previous rules, then install default drop (no PacketIn).
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE,
            table_id=ofp.OFPTT_ALL,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch(),
        ))
        self.add_flow(dp, 0, parser.OFPMatch(), [])

        forward, reverse = path_port_pairs(self.path, P.port_map())
        user_ip = P.HOSTS["u1"][0].split("/")[0]
        gs_ip = P.HOSTS["gs"][0].split("/")[0]

        for direction, pairs, source, destination in (
            ("forward", forward, user_ip, gs_ip),
            ("reverse", reverse, gs_ip, user_ip),
        ):
            for in_port, out_port in pairs:
                match = parser.OFPMatch(
                    in_port=in_port, eth_type=0x0800,
                    ipv4_src=source, ipv4_dst=destination,
                )
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(dp, 100, match, actions, cookie=0x100)
                self.logger.info("[%s] port %s -> port %s",
                                 direction, in_port, out_port)

        barrier = parser.OFPBarrierRequest(dp)
        dp.set_xid(barrier)
        self.pending.add((dp.id, barrier.xid))
        dp.send_msg(barrier)

    @set_ev_cls(ofp_event.EventOFPBarrierReply,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def barrier_reply(self, event):
        key = (event.msg.datapath.id, event.msg.xid)
        if key in self.pending:
            self.pending.remove(key)
            if key[0] not in self.setup_errors:
                self.logger.info("Fixed path ready: u1 -> %s -> gs",
                                 " -> ".join(self.path))

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, event):
        msg = event.msg
        self.setup_errors.add(msg.datapath.id)
        self.logger.error("OpenFlow error: switch=%s type=%s code=%s",
                          msg.datapath.id, msg.type, msg.code)
