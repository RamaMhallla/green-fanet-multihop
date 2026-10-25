"""One concurrent UDP source diagnostic on mn.u1 loopback; no OVS/UAV traffic.

Separate protocol: the receiver moves into the source container, and loopback
uses its existing noqueue instead of the external source interface's fq. This
is not a single-variable equivalent of the full-path experiment. No network
configuration, controller, battery state or old source criteria are changed.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "sim")]
import battery_calibration_support as C

DURATION = 40
CONTAINER = "mn.u1"
ADDRESS = "127.0.0.1"
PROTOCOL = "source-loopback-isolation-v1"
EXPECTED_POLICY = {
    "mean_rate_tolerance_fraction": .05,
    "interior_one_second_rate_tolerance_fraction": .10,
    "maximum_interior_captured_gap_ms": 100.0,
    "interior_trim_s": 5,
}
SCOPE = ("Loopback interface observations and sender reports only. No external "
         "path calibration, application continuity, one-way delay, energy or "
         "host/VM root-cause proof. No automatic retry or comparison batch.")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inside(*arguments):
    return ["sudo", "-n", "docker", "exec", "-e", "LC_ALL=C", CONTAINER, *arguments]


def identity():
    rows = json.loads(C.command(["sudo", "-n", "docker", "inspect", CONTAINER]))
    row = rows[0]
    require(row["State"]["Running"] and row["State"]["Pid"] > 1,
            "mn.u1 is not running; keep the accepted topology open")
    return {"id": row["Id"], "pid": row["State"]["Pid"],
            "resources": {key: row["HostConfig"].get(key) for key in
                          ("CpuQuota", "CpuPeriod", "NanoCpus", "CpusetCpus", "Memory")}}


def listener(port):
    return C.command(inside("ss", "-H", "-ltn", "sport = :%d" % port)).strip()


def loopback_snapshot():
    result = {
        "route": json.loads(C.command(inside("ip", "-j", "route", "get", ADDRESS))),
        "address": json.loads(C.command(inside("ip", "-j", "address", "show", "dev", "lo"))),
        "qdisc": json.loads(C.command(inside("tc", "-j", "-s", "qdisc", "show", "dev", "lo"))),
        "source_egress_qdisc": json.loads(C.command(inside(
            "tc", "-j", "-s", "qdisc", "show", "dev", "u1-eth0"))),
    }
    require(result["route"] and result["route"][0].get("dev") == "lo",
            "127.0.0.1 route is not loopback")
    require(result["address"] and "UP" in result["address"][0].get("flags", []),
            "Loopback is not up; this diagnostic does not change interfaces")
    roots = [row for row in result["qdisc"] if row.get("root") is True]
    require(len(roots) == 1 and roots[0].get("kind") == "noqueue",
            "Loopback must already have noqueue; existing settings left untouched")
    return result


# Read the private PID file, then capture PID start time and full command line.
# Before signalling, match all of them to prevent signalling a reused PID.
PROCESS_IDENTITY = r'''
import json, os, pathlib, signal, sys
pid = int(pathlib.Path(sys.argv[1]).read_text().strip())
if pid <= 1: raise ValueError("Invalid owned PID")
proc = pathlib.Path("/proc") / str(pid)
try:
    raw = (proc / "stat").read_text()
    now = {"pid": pid, "start": raw[raw.rfind(")") + 2:].split()[19],
           "cmdline": (proc / "cmdline").read_bytes().hex()}
except FileNotFoundError:
    if len(sys.argv) > 2: sys.exit(0)
    raise
if len(sys.argv) > 2:
    if now != json.loads(sys.argv[2]): raise ValueError("Owned PID identity changed")
    os.kill(pid, signal.SIGINT)
else:
    if b"timeout" not in bytes.fromhex(now["cmdline"]):
        raise ValueError("Expected bounded timeout process")
    print(json.dumps(now))
'''


class OwnedJob(C.Job):
    process_identity = None

    def confirm_identity(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Job exited during startup: " + self.name)
            try:
                self.process_identity = json.loads(C.command(
                    inside("python3", "-c", PROCESS_IDENTITY, self.pidfile), timeout=3))
                return
            except RuntimeError:
                time.sleep(.05)
        raise RuntimeError("Owned process identity not confirmed: " + self.name)

    def stop(self):
        error = None
        try:
            if getattr(self, "process", None) is not None and self.process.poll() is None:
                require(self.process_identity is not None,
                        "No verified remote identity; bounded job left to timeout: " + self.name)
                C.command(inside("python3", "-c", PROCESS_IDENTITY, self.pidfile,
                                 json.dumps(self.process_identity)), timeout=4)
                self.process.wait(timeout=5)
        except Exception as caught:
            error = caught
            if getattr(self, "process", None) is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
        finally:
            try:
                if getattr(self, "pump", None) is not None:
                    self.pump.drain()
            finally:
                self.handle.close()
        if error is not None:
            raise error
        C.command(inside("rm", "-f", "--", self.pidfile), timeout=3)


def summarize(directory, data):
    """Keep the existing source criteria; capture defects never become PASS."""
    for key, value in EXPECTED_POLICY.items():
        require(C.CALIBRATION_POLICY[key] == value, "Existing source criteria changed: " + key)
    capture_count, captured = C.read_capture(directory / "loopback.pcap", ADDRESS, ADDRESS)
    quality = C.tcpdump_stats(C.read_log(directory / "loopback-tcpdump.log"))
    issues = []
    if quality["kernel_dropped"]:
        issues.append("Loopback capture reported kernel drops")
    if quality["captured"] != capture_count:
        issues.append("tcpdump count differs from parsed pcap record count")
    if data.get("status") != "completed" or data.get("cleanup_errors"):
        issues.append("Collection or owned-job cleanup did not complete")
    streams = {}
    for profile in C.PROFILES:
        name = profile["name"]
        client = C.read_log(directory / (name.lower() + "-client.log"))
        server = C.read_log(directory / (name.lower() + "-server.log"))
        senders = [r for r in C.udp_records(client) if r["role"] == "sender"]
        require(len(senders) == 1, "Expected one sender summary: " + name)
        sender = senders[0]
        row = C.assess_source(captured[profile["port"]], sender, DURATION, profile["rate_mbps"])
        row["evidence_issues"].extend(issues)
        if row["evidence_issues"]:
            row["verdict"] = "INCONCLUSIVE"
        receiver = C.receiver_summary(server)
        row.update(sender=sender, receiver_summary=receiver,
                   receiver_counter_screen=("MATCHES_SENDER_COUNT" if
                       receiver["total_packets"] == sender["total_packets"] and
                       receiver["lost_packets"] == 0 else "REVIEW_RECEIVER_COUNTERS"))
        streams[name] = row
    verdicts = [row["verdict"] for row in streams.values()]
    verdict = "INCONCLUSIVE" if "INCONCLUSIVE" in verdicts else "FAIL" if "FAIL" in verdicts else "PASS"
    result = {"schema": 1, "protocol": PROTOCOL, "source_verdict": verdict,
              "policy": C.CALIBRATION_POLICY, "capture_quality": quality,
              "streams": streams, "evidence_issues": issues, "scope": SCOPE,
              "limitations": [
                  "Both servers and clients share mn.u1; receiver CPU placement differs from full-path runs",
                  "Loopback uses existing noqueue; source u1-eth0 fq and all external queues are bypassed",
                  "One loopback capture is not separate source/GS packet-set evidence",
                  "No host/VM root cause is inferred; no full-path calibration is issued"],
              "full_path_accepted": False, "qos_accepted": False}
    C.write_json(directory / "loopback-report.json", result)
    print("\nLOOPBACK SOURCE CRITERIA:", verdict, flush=True)
    print("Same thresholds: mean +/-5%; interior 1s bins +/-10%; interior gap <=100ms; trim 5s.")
    for name, row in streams.items():
        stats = row["source_statistics"]
        print("%s: captured %d; generated %.3f Mbps; interior gap %.3f ms; %s" %
              (name, stats["unique_packets"], row["generated_payload_mbps"],
               stats["maximum_interior_captured_gap_ms"], row["verdict"]))
        for issue in row["failed_criteria"] + row["evidence_issues"]:
            print("  " + issue)
    print("Capture quality:", quality)
    print("Separate loopback protocol; no external-path/QoS acceptance or root-cause proof.")
    print("Saved:", directory / "loopback-report.json")
    return result


def collect(directory):
    jobs, captures = [], []
    token = uuid.uuid4().hex[:12]
    data = {"schema": 1, "protocol": PROTOCOL, "status": "starting", "duration_s": DURATION,
            "container": CONTAINER, "source_ip": ADDRESS, "destination_ip": ADDRESS,
            "interface": "lo", "profiles": C.PROFILES, "payload_bytes": 1200,
            "socket_pacing_cap_enabled": False, "cleanup_errors": [],
            "policy": C.CALIBRATION_POLICY, "timing_marks": {"begin": C.clock_mark()},
            "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (Path(__file__).resolve(), ROOT / "sim/battery_calibration_support.py",
                          ROOT / "core/battery_live_support.py", ROOT / "config/params.py")},
            "scope": SCOPE}
    try:
        for executable in ("nsenter", "tcpdump", "timeout"):
            require(shutil.which(executable), "Missing executable: " + executable)
        data["container_before"] = identity()
        processes = C.command(["sudo", "-n", "docker", "top", CONTAINER, "-eo", "pid,args"])
        require(not re.search(r"\b(?:iperf3|tcpdump|ping)\b", processes),
                "Existing source traffic/capture; stop its owning trial first")
        version = C.command(inside("iperf3", "--version"))
        require(re.match(r"iperf 3\.9(?:\s|$)", version), "Decoder requires iperf3 3.9")
        help_text = C.command(inside("iperf3", "--help"))
        require("--fq-rate" in help_text and "--forceflush" in help_text,
                "Required iperf options missing")
        data["iperf_version"] = version
        data["loopback_before"] = loopback_snapshot()
        for profile in C.PROFILES:
            require(not listener(profile["port"]), "Loopback TCP port already in use")
        packet_filter = "ip and host 127.0.0.1 and (udp or tcp) and (port 5201 or port 5202)"
        observer = C.Capture(directory, "loopback", data["container_before"]["pid"], "lo", packet_filter)
        captures.append(observer)
        observer.ready()
        print("Loopback capture ready. No Ryu, OVS rules, UAV queues or battery events are changed.", flush=True)
        servers, clients = {}, {}

        def launch(profile, role, arguments):
            job = OwnedJob(directory, token, CONTAINER, profile["name"].lower() + "-" + role,
                           arguments, DURATION + 50)
            jobs.append(job)
            job.confirm_identity()
            return job

        for profile in C.PROFILES:
            servers[profile["name"]] = launch(profile, "server", [
                "iperf3", "-s", "-1", "-B", ADDRESS, "-p", str(profile["port"]),
                "-i", "1", "--forceflush"])
        deadline = time.monotonic() + 10
        while not all(listener(p["port"]) for p in C.PROFILES):
            require(time.monotonic() < deadline and all(j.process.poll() is None for j in jobs),
                    "Loopback servers failed to become ready")
            time.sleep(.1)
        print("Concurrent VOICE 1.2 / VIDEO 4.2 Mbps; 1200 bytes; 40s; --fq-rate 0.", flush=True)
        for profile in C.PROFILES:
            clients[profile["name"]] = launch(profile, "client", [
                "iperf3", "-c", ADDRESS, "-p", str(profile["port"]), "-u", "-b",
                "%gM" % profile["rate_mbps"], "--fq-rate", "0", "-l", "1200", "-t", str(DURATION),
                "-i", "1", "-S", str(profile["tos"]), "--forceflush"])
            data["timing_marks"][profile["name"].lower() + "_client_launch"] = clients[profile["name"]].launch_mark
        data["job_commands"] = {job.name: job.argv for job in jobs}
        C.write_json(directory / "manifest.json", data)
        deadline = time.monotonic() + DURATION + 55
        while any(job.process.poll() is None for job in clients.values()):
            require(observer.process.poll() is None, "Packet capture stopped during traffic")
            require(all(job.process.poll() in (None, 0) for job in jobs), "A traffic job failed")
            require(time.monotonic() < deadline, "Bounded loopback collection deadline exceeded")
            time.sleep(.1)
        for job in jobs:
            job.process.wait(timeout=10)
            job.pump.drain()
            require(job.process.returncode == 0, "Traffic job did not exit normally: " + job.name)
        data["timing_marks"]["traffic_finished"] = C.clock_mark()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            require(observer.process.poll() is None, "Capture stopped before tail completed")
            time.sleep(.1)
        observer.stop()
        data["container_after"] = identity()
        require(data["container_before"] == data["container_after"], "Source container/resources changed")
        data["loopback_after"] = loopback_snapshot()
        data["status"] = "completed"
    except (Exception, KeyboardInterrupt) as error:
        data.update(status="failed", error=type(error).__name__ + ": " + str(error))
        print("Loopback collection stopped:", data["error"], flush=True)
    finally:
        for capture in reversed(captures):
            if capture.process.poll() is None:
                try:
                    capture.stop()
                except Exception as error:
                    data["cleanup_errors"].append("capture: " + str(error))
        for job in reversed(jobs):
            try:
                job.stop()
            except Exception as error:
                data["cleanup_errors"].append(job.name + ": " + str(error))
        if data["cleanup_errors"]:
            data["status"] = "cleanup_failed"
        data["timing_marks"]["end"] = C.clock_mark()
        C.write_json(directory / "manifest.json", data)
    return data


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    require(os.geteuid() != 0, "Run normally after sudo -v, not with sudo python3")
    for key, value in EXPECTED_POLICY.items():
        require(C.CALIBRATION_POLICY[key] == value, "Existing source criteria changed: " + key)
    with (ROOT / "config/runtime_state.trial.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        directory = ROOT / "results/source-loopback-checks" / (stamp + "-" + uuid.uuid4().hex[:12])
        directory.mkdir(parents=True)
        print("Results:", directory, flush=True)
        data = collect(directory)
        if data["status"] != "completed":
            print("Evidence retained; cleanup errors:", data["cleanup_errors"])
            return 1
        try:
            summarize(directory, data)
        except Exception as error:
            data["analysis_error"] = type(error).__name__ + ": " + str(error)
            C.write_json(directory / "manifest.json", data)
            print("Collection retained; analysis requires review:", data["analysis_error"])
            return 1
    return 0


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Termination requested")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print("Loopback check stopped:", type(error).__name__ + ": " + str(error))
        sys.exit(1)
