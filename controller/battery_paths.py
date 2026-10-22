"""Separate battery-protection controller for the owned functional smoke check.

Requires the runner-installed queues. A barrier confirms OpenFlow processing,
not packet delivery or queue drain. No QoS, atomic multi-class transition or
energy-saving claim follows. Old versions are retained for in-flight packets.
FIXED freezes the common initial protected plan and profile. CONTROL uses a
constant healthy UAV2--UAV4 path so test control survives the UAV1 failure.
"""

import copy
import json
from pathlib import Path
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
from core.battery_policy import plan_protected, plan_signature, scenario_links
from core.battery_enforcement import (
    BASE_VLANS, MAX_EPOCH, COOKIE, PRIORITY, GUARD_PRIORITY, vlan_id, meter_id,
)
from core.state_store import load_state

COOKIE_PREFIX = COOKIE
POLL_SECONDS = 0.2
BARRIER_TIMEOUT = 10.0


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


def validate_relays(relays, scenario):
    if not relays or len(relays) != len(set(relays)):
        raise ValueError("Relay path must be nonempty without repeats")
    if any(drone not in P.DRONES for drone in relays):
        raise ValueError("Unknown relay in path")
    whole = ["u1"] + list(relays) + ["gs"]
    allowed = {frozenset(link) for link in scenario_links(P, scenario)[0]}
    if any(frozenset((a, b)) not in allowed
           for a, b in zip(whole, whole[1:])):
        raise ValueError("Path uses a forbidden logical link")


class BatteryPaths(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BatteryPaths, self).__init__(*args, **kwargs)
        self.mode = os.environ.get("FANET_WEIGHT_MODE", "fixed").strip().lower()
        if self.mode not in ("fixed", "adaptive"):
            raise ValueError("FANET_WEIGHT_MODE must be fixed or adaptive")
        self.state_file = os.environ.get(
            "FANET_STATE_FILE", os.path.join(PROJECT_ROOT, "config", "runtime_state.json"),
        )
        # Fail clearly at startup if init has not created a valid state file.
        load_state(self.state_file, P.DRONES)
        if not os.environ.get("FANET_SMOKE_TOKEN"):
            raise ValueError("Start this controller only with check_battery_enforcement.py")
        self.scenario = os.environ["FANET_SCENARIO"]
        self.status_file = Path(os.environ["FANET_APPLIED_FILE"])
        self.control_path = ["UAV2", "UAV4"]
        validate_relays(self.control_path, self.scenario)
        self.initial_plan = None
        self.connected_once = False
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

    def _timing(self, event, tx=None, **fields):
        stamp = time.monotonic_ns()
        row = {"event": event, "monotonic_ns": stamp}
        if tx is not None:
            row.update(revision=tx["document"]["revision"], epoch=tx["epoch"])
        row.update(fields)
        self.logger.info("TIMING %s", json.dumps(row, sort_keys=True))

    def _plan(self, document):
        if self.initial_plan is None:
            if document["states"]["UAV1"]["energy_fraction"] != .90:
                raise ValueError("The common initial plan requires UAV1 at 90%")
            self.initial_plan = plan_protected(P, document["states"], self.scenario)
        plan = (copy.deepcopy(self.initial_plan) if self.mode == "fixed" else
                plan_protected(P, document["states"], self.scenario))
        for row in plan["classes"]:
            if row["admitted"]:
                validate_relays(row["path"][1:-1], self.scenario)
        return plan

    def _publish(self, document, plan, epoch):
        payload = {"revision": document["revision"], "epoch": epoch,
                   "mode": self.mode, "scenario": self.scenario, "plan": plan,
                   "video_meter_id": meter_id(epoch),
                   "observed_monotonic_ns": time.monotonic_ns(),
                   "scope": "Barrier-confirmed configuration; packet probes are separate"}
        temporary = self.status_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self.status_file)

    def _send(self, tx, message):
        if self.txn is not tx or self.dp is not tx["dp"]:
            raise RuntimeError("Datapath/transaction changed during update")
        tx["dp"].set_xid(message)
        tx["xids"].add(message.xid)
        tx["dp"].send_msg(message)

    def _flow(self, tx, match, actions, cookie, video_meter=None):
        dp = tx["dp"]
        instructions = []
        if actions:
            instructions = [dp.ofproto_parser.OFPInstructionActions(
                dp.ofproto.OFPIT_APPLY_ACTIONS, actions,
            )]
        if video_meter is not None:
            instructions.insert(0, dp.ofproto_parser.OFPInstructionMeter(video_meter))
        self._send(tx, dp.ofproto_parser.OFPFlowMod(
            datapath=dp, priority=PRIORITY, match=match,
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
            # Overlay the old idle trial rules; do not delete them. The runner
            # rejects existing flows at or above these reserved priorities.
            self._send(tx, parser.OFPFlowMod(
                datapath=dp, priority=GUARD_PRIORITY, match=parser.OFPMatch(),
                instructions=[], cookie=COOKIE_PREFIX,
            ))
        video = next(row for row in tx["plan"]["classes"] if row["name"] == "VIDEO")
        if video["admitted"]:
            rate = int(round(video["meter_cap_mbps"] * 1000))
            self._send(tx, parser.OFPMeterMod(
                datapath=dp, command=ofp.OFPMC_ADD,
                flags=ofp.OFPMF_KBPS | ofp.OFPMF_STATS,
                meter_id=meter_id(epoch),
                bands=[parser.OFPMeterBandDrop(rate=rate, burst_size=0)],
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

    def _flip(self, tx, names):
        dp, epoch = tx["dp"], tx["epoch"]
        parser, ofp = dp.ofproto_parser, dp.ofproto
        ports = P.port_map()
        user_ip = P.HOSTS["u1"][0].split("/")[0]
        gs_ip = P.HOSTS["gs"][0].split("/")[0]
        for index, record in enumerate(self._classes(tx["plan"])):
            if record["name"] not in names:
                continue
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
                send_start_ns = time.monotonic_ns()
                video_meter = (meter_id(epoch) if record["name"] == "VIDEO"
                               and record["admitted"] and source == user_ip else None)
                self._flow(tx, match, actions, COOKIE_PREFIX | (epoch << 8) | index,
                           video_meter=video_meter)
                self._timing("INGRESS_FLOW_SUBMITTED", tx,
                             traffic_class=record["name"],
                             direction="forward" if source == user_ip else "reverse",
                             send_start_monotonic_ns=send_start_ns)
        self._barrier(tx)

    def _begin(self, document, plan, bootstrap=False):
        self.last_attempted_revision = document["revision"]
        if not bootstrap and plan_signature(plan) == plan_signature(self.applied_plan):
            self._timing("STATE_UNCHANGED", revision=document["revision"],
                         epoch=self.active_epoch)
            self.applied_document, self.applied_plan = document, plan
            self.logger.info("STATE revision=%s: paths unchanged; no rule update",
                             document["revision"])
            self._log_plan(document, plan, self.active_epoch)
            self._publish(document, plan, self.active_epoch)
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
        self._timing("PREPARE_BEGIN", tx)
        self.logger.info("PREPARE revision=%s epoch=%s", document["revision"], epoch)
        try:
            self._prepare(tx)
        except Exception as error:
            self._fail(tx, str(error))

    def _fail(self, tx, reason):
        if self.txn is not tx:
            return
        self.txn = None
        self.halted = True
        self.logger.error("ENFORCEMENT FAILED phase=%s; automatic updates halted; "
                          "no rollback or success claimed: %s", tx["phase"], reason)

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
            self.logger.info("APPLIED %s decision=%s resource=%s budget=%.2f meter=%s",
                             record["name"], record["decision"], record["resource_type"],
                             record["scheduler_budget_mbps"], record["meter_cap_mbps"])

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
        if self.connected_once:
            self.halted = True
            self.logger.error("ENFORCEMENT FAILED: reconnect is outside this smoke protocol")
            return
        self.connected_once = True
        self.dp = dp
        self.logger.info("BATTERY controller mode=%s scenario=%s; owned overlay only",
                         self.mode.upper(), self.scenario)
        self.logger.info("Requires verified HTB voice/video queues at ALL UAV egresses; "
                         "CONTROL fixed on UAV2--UAV4; forward-only admission")
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
        try:
            if tx["phase"] == "prepare":
                self._timing("INTERNAL_BARRIER_REPLY", tx)
                tx["phase"] = "video"
                self._timing("VIDEO_UPDATE_BEGIN", tx)
                self._flip(tx, {"VIDEO"})
            elif tx["phase"] == "video":
                self._timing("VIDEO_BARRIER_REPLY", tx)
                tx["phase"] = "voice_control"
                self._timing("VOICE_UPDATE_BEGIN", tx)
                self._flip(tx, {"VOICE", "CONTROL"})
            else:
                self._timing("INGRESS_BARRIER_REPLY", tx)
                self.applied_document, self.applied_plan = tx["document"], tx["plan"]
                self.active_epoch, self.txn = tx["epoch"], None
                self._log_plan(self.applied_document, self.applied_plan, self.active_epoch)
                self._publish(self.applied_document, self.applied_plan, self.active_epoch)
                self.logger.info("BATTERY READY revision=%s epoch=%s",
                                 self.applied_document["revision"], self.active_epoch)
        except Exception as error:
            # Keep transaction ownership until status publication succeeds.
            self.txn = tx
            self._fail(tx, str(error))

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
            self.halted = True
            self.dp, self.txn = None, None
            self.logger.error("ENFORCEMENT FAILED: switch disconnected")
