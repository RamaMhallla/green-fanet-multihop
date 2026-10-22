"""Live synthetic-state routing with two-phase, VLAN-versioned path updates.

The switch first installs all internal rules for a fresh version and confirms
them with a barrier. Only then are endpoint classifiers changed to the new
version. Old internal rules are retained; version IDs are never reused within
a connection. This avoids relying on an unmeasured queue-drain timeout.

Scope: one OVS switch, endpoint IPv4/DSCP classification, existing tc wires.
Per-packet version isolation does not make ingress changes atomic across
classes/directions, guarantee QoS, or reserve capacity for both versions during
transition. Admission remains forward-only and states are synthetic.

At most 125 versions fit this lab's VLAN allocation. If labels are exhausted,
stop traffic and restart the controller between experiments. Reconnection
clears/rebuilds the lab switch and is not covered by the live-update guarantee.
"""

import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls,
)
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

from config import params as P
from core.lab_scenario import EXPERIMENT_FIXED_WEIGHTS, plan_forward
from core.state_store import load_state

BASE_VLANS = {0: 100, 46: 110, 34: 120}
VLAN_STRIDE = 32
MAX_EPOCH = (4094 - max(BASE_VLANS.values())) // VLAN_STRIDE
COOKIE_PREFIX = 0x6A00000000000000
POLL_SECONDS = 1.0
BARRIER_TIMEOUT = 10.0


def vlan_id(dscp, epoch):
    if type(epoch) is not int or not 0 <= epoch <= MAX_EPOCH:
        raise ValueError("VLAN version limit reached")
    return BASE_VLANS[dscp] + VLAN_STRIDE * epoch


def port_pairs(relays):
    ports = P.port_map()
    forward = list(zip(
        [ports["u1"]] + [ports[(d, "OUT")] for d in relays],
        [ports[(d, "IN")] for d in relays] + [ports["gs"]],
    ))
    backward = list(reversed(relays))
    reverse = list(zip(
        [ports["gs"]] + [ports[(d, "IN")] for d in backward],
        [ports[(d, "OUT")] for d in backward] + [ports["u1"]],
    ))
    return forward, reverse


def validate_relays(relays):
    if not relays or len(relays) != len(set(relays)):
        raise ValueError("Relay path must be nonempty without repeats")
    if any(drone not in P.DRONES for drone in relays):
        raise ValueError("Unknown relay in path")
    whole = ["u1"] + list(relays) + ["gs"]
    allowed = {frozenset(link) for link in P.LOGICAL_LINKS}
    if any(frozenset((a, b)) not in allowed
           for a, b in zip(whole, whole[1:])):
        raise ValueError("Path uses a forbidden logical link")


def path_signature(plan):
    return tuple((record["dscp"], tuple(record["path"]) if record["admitted"] else None)
                 for record in plan["classes"])


class LivePaths(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LivePaths, self).__init__(*args, **kwargs)
        self.mode = os.environ.get("FANET_WEIGHT_MODE", "fixed").strip().lower()
        if self.mode not in ("fixed", "adaptive"):
            raise ValueError("FANET_WEIGHT_MODE must be fixed or adaptive")
        self.state_file = os.environ.get(
            "FANET_STATE_FILE", os.path.join(PROJECT_ROOT, "config", "runtime_state.json"),
        )
        # Fail clearly at startup if init has not created a valid state file.
        load_state(self.state_file, P.DRONES)
        self.control_path = list(P.TEST_PATH)
        validate_relays(self.control_path)
        self.dp = None
        self.txn = None
        self.applied_document = None
        self.applied_plan = None
        self.active_epoch = None
        self.next_epoch = 0
        self.last_attempted_revision = -1
        self.halted = False
        self.last_read_error = None
        self.worker = hub.spawn(self._poll)

    def _plan(self, document):
        plan = plan_forward(P, states=document["states"], weight_mode=self.mode,
                            fixed_weights=EXPERIMENT_FIXED_WEIGHTS)
        for record in plan["classes"]:
            if record["admitted"]:
                validate_relays(record["path"][1:-1])
        return plan

    def _send(self, tx, message):
        if self.txn is not tx or self.dp is not tx["dp"]:
            raise RuntimeError("Datapath/transaction changed during update")
        tx["dp"].set_xid(message)
        tx["xids"].add(message.xid)
        tx["dp"].send_msg(message)

    def _flow(self, tx, match, actions, cookie):
        dp = tx["dp"]
        instructions = []
        if actions:
            instructions = [dp.ofproto_parser.OFPInstructionActions(
                dp.ofproto.OFPIT_APPLY_ACTIONS, actions,
            )]
        self._send(tx, dp.ofproto_parser.OFPFlowMod(
            datapath=dp, priority=100, match=match,
            instructions=instructions, cookie=cookie,
        ))

    def _barrier(self, tx):
        request = tx["dp"].ofproto_parser.OFPBarrierRequest(tx["dp"])
        # Register the expected xid before sending, including on fast replies.
        tx["dp"].set_xid(request)
        tx["xids"].add(request.xid)
        tx["barrier_xid"] = request.xid
        tx["deadline"] = time.monotonic() + BARRIER_TIMEOUT
        tx["dp"].send_msg(request)

    def _classes(self, plan):
        return [{"name": "CONTROL", "dscp": 0, "admitted": True,
                 "path": ["u1"] + self.control_path + ["gs"]}] + plan["classes"]

    def _prepare(self, tx):
        dp, epoch = tx["dp"], tx["epoch"]
        parser, ofp = dp.ofproto_parser, dp.ofproto
        if tx["bootstrap"]:
            self._send(tx, parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE,
                table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY, match=parser.OFPMatch(),
            ))
            self._send(tx, parser.OFPFlowMod(
                datapath=dp, priority=0, match=parser.OFPMatch(),
                instructions=[], cookie=COOKIE_PREFIX,
            ))
        for index, record in enumerate(self._classes(tx["plan"])):
            if not record["admitted"]:
                continue
            tagged = ofp.OFPVID_PRESENT | vlan_id(record["dscp"], epoch)
            cookie = COOKIE_PREFIX | (epoch << 8) | index
            for pairs in port_pairs(record["path"][1:-1]):
                # Only internal rules. Endpoint classifiers stay unchanged.
                for hop, (in_port, out_port) in enumerate(pairs[1:], start=1):
                    actions = []
                    if hop == len(pairs) - 1:
                        actions.append(parser.OFPActionPopVlan())
                    actions.append(parser.OFPActionOutput(out_port))
                    self._flow(tx, parser.OFPMatch(in_port=in_port, vlan_vid=tagged),
                               actions, cookie)
        self._barrier(tx)

    def _flip(self, tx):
        dp, epoch = tx["dp"], tx["epoch"]
        parser, ofp = dp.ofproto_parser, dp.ofproto
        ports = P.port_map()
        user_ip = P.HOSTS["u1"][0].split("/")[0]
        gs_ip = P.HOSTS["gs"][0].split("/")[0]
        for index, record in enumerate(self._classes(tx["plan"])):
            pairs_by_direction = (port_pairs(record["path"][1:-1])
                                  if record["admitted"] else (None, None))
            for pairs, in_port, source, destination in (
                (pairs_by_direction[0], ports["u1"], user_ip, gs_ip),
                (pairs_by_direction[1], ports["gs"], gs_ip, user_ip),
            ):
                actions = []
                if record["admitted"]:
                    actions = [parser.OFPActionPushVlan(ethertype=0x8100),
                               parser.OFPActionSetField(
                                   vlan_vid=ofp.OFPVID_PRESENT | vlan_id(record["dscp"], epoch)),
                               parser.OFPActionOutput(pairs[0][1])]
                # A rejected aggregate gets an explicit drop classifier.
                match = parser.OFPMatch(
                    in_port=in_port, eth_type=0x0800, ipv4_src=source,
                    ipv4_dst=destination, ip_dscp=record["dscp"],
                    vlan_vid=ofp.OFPVID_NONE,
                )
                self._flow(tx, match, actions, COOKIE_PREFIX | (epoch << 8) | index)
        self._barrier(tx)

    def _begin(self, document, plan, bootstrap=False):
        self.last_attempted_revision = document["revision"]
        if not bootstrap and path_signature(plan) == path_signature(self.applied_plan):
            self.applied_document, self.applied_plan = document, plan
            self.logger.info("STATE revision=%s: paths unchanged; no rule update",
                             document["revision"])
            self._log_plan(document, plan, self.active_epoch)
            return
        if self.next_epoch > MAX_EPOCH:
            self.halted = True
            self.logger.error("VLAN labels exhausted. Stop traffic and restart "
                              "the live controller between experiments.")
            return
        epoch = self.next_epoch
        self.next_epoch += 1  # Never reuse an allocated version, even on error.
        tx = {"dp": self.dp, "epoch": epoch, "document": document, "plan": plan,
              "bootstrap": bootstrap, "phase": "prepare", "xids": set(),
              "barrier_xid": None, "failed": False,
              "deadline": time.monotonic() + BARRIER_TIMEOUT}
        self.txn = tx
        self.logger.info("PREPARE revision=%s epoch=%s", document["revision"], epoch)
        try:
            self._prepare(tx)
        except Exception as error:
            self._fail(tx, str(error))

    def _fail(self, tx, reason):
        if self.txn is not tx:
            return
        self.txn = None
        if tx["phase"] == "ingress":
            # Some classifiers may have changed. Do not claim rollback/success.
            self.halted = True
            self.logger.error("Ingress update incomplete; automatic updates halted. "
                              "Retained versions remain installed. Restart between "
                              "experiments after checking errors. Reason: %s", reason)
        else:
            self.logger.error("Prepare failed; new ingress was not enabled. "
                              "Fix the problem and write a newer state revision. "
                              "Reason: %s", reason)

    def _log_plan(self, document, plan, epoch):
        self.logger.info("STATE revision=%s UAV1=%.1f%% mode=%s epoch=%s",
                         document["revision"],
                         100 * document["states"]["UAV1"]["energy_fraction"],
                         self.mode.upper(), epoch)
        for record in plan["classes"]:
            if not record["admitted"]:
                self.logger.warning("%s REJECTED: %s", record["name"], record["reason"])
                continue
            self.logger.info("%s DSCP=%s VLAN=%s cost=%.3f path=%s",
                             record["name"], record["dscp"],
                             vlan_id(record["dscp"], epoch), record["cost"],
                             " -> ".join(record["path"]))

    def _poll_once(self):
        if self.dp is None or self.halted:
            return
        if self.txn is not None:
            if time.monotonic() > self.txn["deadline"]:
                self._fail(self.txn, "Barrier timeout")
            return
        try:
            document = load_state(self.state_file, P.DRONES)
        except (OSError, ValueError) as error:
            reason = str(error)
            if reason != self.last_read_error:
                self.logger.warning("State file rejected; active rules retained: %s", reason)
                self.last_read_error = reason
            return
        self.last_read_error = None
        if document["revision"] <= self.last_attempted_revision:
            return
        try:
            plan = self._plan(document)
        except ValueError as error:
            self.last_attempted_revision = document["revision"]
            self.logger.error("Planning failed; active rules retained: %s", error)
            return
        self._begin(document, plan, bootstrap=self.applied_plan is None)

    def _poll(self):
        while True:
            hub.sleep(POLL_SECONDS)
            try:
                self._poll_once()
            except Exception:
                self.logger.exception("Live poll failed; check the controller log")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, event):
        dp = event.msg.datapath
        if dp.id != P.SWITCH_DPID:
            self.logger.error("Unexpected DPID: %s", dp.id)
            return
        self.dp, self.txn = dp, None
        self.applied_document = self.applied_plan = None
        self.active_epoch, self.next_epoch = None, 0
        self.last_attempted_revision = -1
        self.halted = False
        self.logger.info("LIVE controller mode=%s; polling %s every %.1fs",
                         self.mode.upper(), self.state_file, POLL_SECONDS)
        self.logger.info("Old internal versions retained; max=%s versions; "
                         "forward-only admission, synthetic state, no GBR policing",
                         MAX_EPOCH + 1)
        self._poll_once()

    @set_ev_cls(ofp_event.EventOFPBarrierReply,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def barrier_reply(self, event):
        tx = self.txn
        if (tx is None or event.msg.datapath is not tx["dp"]
                or event.msg.xid != tx["barrier_xid"]):
            return
        if tx["failed"]:
            self._fail(tx, "OpenFlow error during " + tx["phase"])
            return
        if tx["phase"] == "prepare":
            tx["phase"] = "ingress"
            tx["deadline"] = time.monotonic() + BARRIER_TIMEOUT
            self.logger.info("FLIP revision=%s epoch=%s",
                             tx["document"]["revision"], tx["epoch"])
            try:
                self._flip(tx)
            except Exception as error:
                self._fail(tx, str(error))
        else:
            self.applied_document, self.applied_plan = tx["document"], tx["plan"]
            self.active_epoch, self.txn = tx["epoch"], None
            self._log_plan(self.applied_document, self.applied_plan, self.active_epoch)
            self.logger.info("LIVE READY revision=%s epoch=%s; old versions retained",
                             self.applied_document["revision"], self.active_epoch)

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, event):
        msg = event.msg
        tx = self.txn
        if tx is not None and msg.datapath is tx["dp"] and msg.xid in tx["xids"]:
            tx["failed"] = True
        self.logger.error("OpenFlow error: DPID=%s xid=%s type=%s code=%s",
                          msg.datapath.id, msg.xid, msg.type, msg.code)

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def disconnected(self, event):
        if event.datapath is self.dp:
            self.dp, self.txn = None, None
            self.logger.warning("Switch disconnected; live updates paused")
