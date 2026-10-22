"""Startup DSCP path selection from the shared synthetic forward plan.

Reverse rules carry replies without reverse bandwidth admission. DSCP 0
uses a fixed diagnostic/control path with no bandwidth reservation.
This app does not implement dynamic rerouting or enforce per-class rates.
FANET_WEIGHT_MODE=fixed|adaptive selects the policy at process startup.
The fixed policy uses the comparison weights, not the earlier demo weights.
FANET_VLAN_TEST=1 enables a single-version VLAN transport smoke test.
This is not yet the two-version, consistent-update protocol.
"""

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
from core.lab_scenario import EXPERIMENT_FIXED_WEIGHTS, plan_forward

CLASS_VLANS = {0: 100, 46: 110, 34: 120}


def path_port_pairs(path, ports):
    """One rule per fabric traversal, in each direction."""
    forward = list(zip(
        [ports["u1"]] + [ports[(d, "OUT")] for d in path],
        [ports[(d, "IN")] for d in path] + [ports["gs"]],
    ))
    reverse_path = list(reversed(path))
    reverse = list(zip(
        [ports["gs"]] + [ports[(d, "IN")] for d in reverse_path],
        [ports[(d, "OUT")] for d in reverse_path] + [ports["u1"]],
    ))
    return forward, reverse


def validate_path(path):
    if not path or len(path) != len(set(path)):
        raise ValueError("Path must be nonempty and contain no repeats")
    if any(drone not in P.DRONES for drone in path):
        raise ValueError("Path contains an unknown drone")
    allowed = {frozenset(link) for link in P.LOGICAL_LINKS}
    whole = ["u1"] + list(path) + ["gs"]
    if any(frozenset((a, b)) not in allowed
           for a, b in zip(whole, whole[1:])):
        raise ValueError("Path uses a forbidden logical link")


class CostPaths(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CostPaths, self).__init__(*args, **kwargs)
        self.weight_mode = os.environ.get("FANET_WEIGHT_MODE", "fixed").strip().lower()
        if self.weight_mode not in ("fixed", "adaptive"):
            raise ValueError("FANET_WEIGHT_MODE must be 'fixed' or 'adaptive'")
        vlan_flag = os.environ.get("FANET_VLAN_TEST", "0")
        if vlan_flag not in ("0", "1"):
            raise ValueError("FANET_VLAN_TEST must be '0' or '1'")
        self.vlan_test = vlan_flag == "1"
        self.plan = plan_forward(
            P, weight_mode=self.weight_mode,
            fixed_weights=EXPERIMENT_FIXED_WEIGHTS,
        )
        self.control_path = list(P.TEST_PATH)
        validate_path(self.control_path)
        for record in self.plan["classes"]:
            if record["admitted"]:
                validate_path(record["path"][1:-1])
        self.pending = {}
        self.setup_errors = set()

    def add_flow(self, dp, priority, match, actions, cookie=0):
        instructions = []
        if actions:
            instructions.append(dp.ofproto_parser.OFPInstructionActions(
                dp.ofproto.OFPIT_APPLY_ACTIONS, actions,
            ))
        dp.send_msg(dp.ofproto_parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=instructions, cookie=cookie,
        ))

    def install_path(self, dp, relays, dscp, cookie):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        forward, reverse = path_port_pairs(relays, P.port_map())
        user_ip = P.HOSTS["u1"][0].split("/")[0]
        gs_ip = P.HOSTS["gs"][0].split("/")[0]
        for pairs, source, destination in (
            (forward, user_ip, gs_ip), (reverse, gs_ip, user_ip),
        ):
            for index, (in_port, out_port) in enumerate(pairs):
                actions = []
                if self.vlan_test:
                    vid = CLASS_VLANS[dscp]
                    tagged_vid = ofp.OFPVID_PRESENT | vid
                    if index == 0:
                        # Classify only untagged endpoint packets, then label.
                        match = parser.OFPMatch(
                            in_port=in_port, eth_type=0x0800,
                            ipv4_src=source, ipv4_dst=destination,
                            ip_dscp=dscp, vlan_vid=ofp.OFPVID_NONE,
                        )
                        actions.extend([
                            parser.OFPActionPushVlan(ethertype=0x8100),
                            parser.OFPActionSetField(vlan_vid=tagged_vid),
                        ])
                    else:
                        match = parser.OFPMatch(
                            in_port=in_port, vlan_vid=tagged_vid,
                        )
                        if index == len(pairs) - 1:
                            # End hosts receive ordinary, untagged frames.
                            actions.append(parser.OFPActionPopVlan())
                else:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=0x0800,
                        ipv4_src=source, ipv4_dst=destination, ip_dscp=dscp,
                    )
                actions.append(parser.OFPActionOutput(out_port))
                self.add_flow(dp, 100, match, actions, cookie)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, event):
        dp = event.msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        if dp.id != P.SWITCH_DPID:
            self.logger.error("Unexpected switch DPID: %s", dp.id)
            return
        self.pending.pop(dp.id, None)
        self.setup_errors.discard(dp.id)
        self.logger.info("Weight mode: %s (startup snapshot)",
                         self.weight_mode.upper())
        self.logger.info("VLAN test: %s", "ENABLED" if self.vlan_test else "DISABLED")
        if self.vlan_test:
            self.logger.info("Internal VLAN IDs: CONTROL=100 VOICE=110 VIDEO=120; "
                             "single version, no live updates")
        if self.weight_mode == "fixed":
            self.logger.info("Fixed comparison weights: %s",
                             EXPERIMENT_FIXED_WEIGHTS)
        else:
            self.logger.info("Adaptive design: threshold=0.20 steepness=15 "
                             "delay/carbon split=70/30")
        for drone in P.DRONES:
            alpha, beta, gamma = self.plan["relay_weights"][drone]
            self.logger.info("WEIGHTS %s alpha=%.3f beta=%.3f gamma=%.3f",
                             drone, alpha, beta, gamma)
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE,
            table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY, match=parser.OFPMatch(),
        ))
        self.add_flow(dp, 0, parser.OFPMatch(), [])
        self.install_path(dp, self.control_path, dscp=0, cookie=0x100)
        for index, record in enumerate(self.plan["classes"], start=1):
            if not record["admitted"]:
                self.logger.warning("%s REJECTED: %s", record["name"],
                                    record["reason"])
                continue
            self.install_path(dp, record["path"][1:-1], record["dscp"],
                              cookie=0x200 + index)
            self.logger.info(
                "%s DSCP=%s cost=%.3f delay=%.1f/%.1f ms path=%s",
                record["name"], record["dscp"], record["cost"],
                record["delay_ms"], record["budget_ms"],
                " -> ".join(record["path"]),
            )
        self.logger.info("Synthetic states; forward admission only. "
                         "Reverse rules have no bandwidth reservation.")
        self.logger.info("DSCP=0 diagnostic path: u1 -> %s -> gs",
                         " -> ".join(self.control_path))
        barrier = parser.OFPBarrierRequest(dp)
        dp.set_xid(barrier)
        self.pending[dp.id] = (dp, barrier.xid)
        dp.send_msg(barrier)

    @set_ev_cls(ofp_event.EventOFPBarrierReply,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def barrier_reply(self, event):
        dp = event.msg.datapath
        if self.pending.get(dp.id) == (dp, event.msg.xid):
            del self.pending[dp.id]
            if dp.id not in self.setup_errors:
                admitted = " ".join(
                    "%s=%s" % (record["name"], record["dscp"])
                    for record in self.plan["classes"] if record["admitted"]
                )
                self.logger.info("Class paths ready: %s CONTROL=0", admitted)

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, event):
        msg = event.msg
        self.setup_errors.add(msg.datapath.id)
        self.logger.error("OpenFlow error: switch=%s type=%s code=%s",
                          msg.datapath.id, msg.type, msg.code)
