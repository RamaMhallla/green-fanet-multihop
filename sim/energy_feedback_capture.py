"""UDP capture for feedback; separate from the manual 90/30/25% protocol."""
import os
import shutil
import subprocess
import time
import uuid

import battery_calibration_support as C
from core.energy_feedback import PROTOCOL, DURATION_S


def collect(session):
    folder = session.directory
    jobs, captures, clients, servers = [], [], {}, {}
    monitor = pump = handle = None
    fq_attempted = False
    token = uuid.uuid4().hex[:12]
    data = {"schema": 1, "protocol": PROTOCOL, "status": "starting", "duration_s": DURATION_S,
        "weights": session.args.weights, "scenario": session.args.scenario,
        "profiles": C.PROFILES, "policy": C.CALIBRATION_POLICY, "payload_bytes": 1200,
        "cleanup_errors": [], "socket_pacing_cap_enabled": False,
        "link_failure_enabled": False, "scheduled_battery_events": False,
        "timing_marks": {"begin": C.clock_mark()}}
    error = None
    try:
        for executable in ("tcpdump", "nsenter", "timeout", "vmstat"):
            if not shutil.which(executable):
                raise RuntimeError("Required executable missing: " + executable)
        for name in ("u1", "gs"):
            prefix = ["sudo", "-n", "docker", "exec", "mn." + name, "iperf3"]
            version, help_text = C.command(prefix + ["--version"]), C.command(prefix + ["--help"])
            if not version.startswith("iperf 3.9") or any(x not in help_text for x in ("--forceflush", "--fq-rate")):
                raise RuntimeError("Protocol requires iperf3 3.9 with --forceflush and --fq-rate")
            data[name + "_iperf_version"] = version
        if any(C.listener(p["port"]) for p in C.PROFILES):
            raise RuntimeError("Existing GS listener on a traffic port; stop its owning trial first")
        original = C.capture(folder, "source-qdisc-original.json",
            C.source_tc("-j", "-s", "qdisc", "show", "dev", C.SOURCE_INTERFACE))
        if C.root_qdisc(original).get("kind") != "noqueue":
            raise RuntimeError("Source root must start as noqueue")
        fq_attempted = True
        C.command(C.source_tc("qdisc", "add", "dev", C.SOURCE_INTERFACE, "root",
            "handle", C.SOURCE_HANDLE, "fq", *C.SOURCE_FQ_OPTIONS))
        source_before = C.source_snapshot(folder, "before")
        queues_before = C.queue_snapshot(folder, "before")
        data.update(source_ip=C.P.HOSTS["u1"][0].split("/")[0], destination_ip=C.P.HOSTS["gs"][0].split("/")[0])
        packet_filter = ("ip and host %s and host %s and (udp or tcp) and (port 5201 or port 5202)" %
                         (data["source_ip"], data["destination_ip"]))
        data["capture_settings"] = {"filter": packet_filter, "snaplen": 128, "post_jobs_observation_s": 8}
        for name in ("u1", "gs"):
            observer = C.Capture(folder, name, C.container_pid("mn." + name), name + "-eth0", packet_filter)
            captures.append(observer)
            observer.ready()
        session.begin_feedback()
        print("Both captures ready. Battery feedback from RX/TX counters; NO scheduled battery jumps or link failure.", flush=True)
        bound = DURATION_S + 65
        for profile in C.PROFILES:
            job = C.Job(folder, token, "mn.gs", profile["name"].lower() + "-server",
                ["iperf3", "-s", "-1", "-p", str(profile["port"]), "-i", "1", "--forceflush"], bound)
            jobs.append(job)
            servers[profile["name"]] = job
        deadline = time.monotonic() + 10
        while not all(C.listener(p["port"]) for p in C.PROFILES):
            session.alive()
            if any(j.process.poll() is not None for j in servers.values()) or time.monotonic() > deadline:
                raise RuntimeError("Both UDP servers did not become ready")
            time.sleep(.1)
        handle = (folder / "vmstat.log").open("w", encoding="utf-8")
        monitor = subprocess.Popen(["vmstat", "-t", "1"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1, env=dict(os.environ, LC_ALL="C"))
        pump = C.OutputPump(monitor, handle, folder / "vmstat.timing.jsonl")
        data["timing_marks"]["client_launch_origin"] = C.clock_mark()
        for profile in C.PROFILES:
            job = C.Job(folder, token, "mn.u1", profile["name"].lower() + "-client",
                ["iperf3", "-c", data["destination_ip"], "-p", str(profile["port"]), "-u",
                 "-b", "%gM" % profile["rate_mbps"], "--fq-rate", "0", "-l", "1200",
                 "-t", str(DURATION_S), "-i", "1", "-S", str(profile["tos"]), "--forceflush"], bound)
            jobs.append(job)
            clients[profile["name"]] = job
            data["timing_marks"][profile["name"].lower() + "_client_launch"] = job.launch_mark
        data["job_commands"] = {j.name: j.argv for j in jobs}
        C.write_json(folder / "energy-feedback-traffic.json", data)
        deadline = time.monotonic() + 15
        while True:
            session.alive()
            if any(j.process.poll() is not None for j in jobs):
                raise RuntimeError("Traffic job exited before both streams were confirmed")
            if all(any(r["role"] == "interval" and r["total_packets"] > r["lost_packets"]
                       for r in C.udp_records(C.read_log(j.path))) for j in servers.values()):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Both receive streams were not confirmed")
            session.tick()
            time.sleep(.1)
        data["timing_marks"]["both_streams_observed"] = C.clock_mark()
        print("Both streams observed. 40s UDP; feedback sampling overhead is included and recorded.", flush=True)
        deadline = time.monotonic() + bound
        while any(j.process.poll() is None for j in clients.values()):
            session.alive()
            if (monitor.poll() is not None or any(c.process.poll() is not None for c in captures)
                    or any(j.process.poll() not in (None, 0) for j in clients.values())):
                raise RuntimeError("Client, capture or monitor failed")
            if time.monotonic() > deadline:
                raise RuntimeError("UDP collection exceeded its bound")
            session.tick()
            time.sleep(.1)
        data["timing_marks"]["clients_exited_observed"] = C.clock_mark()
        for job in jobs:
            job.process.wait(timeout=10)
            job.pump.drain()
            job.handle.flush()
            if job.process.returncode:
                raise RuntimeError("Traffic job failed: " + job.name)
        data["timing_marks"]["traffic_finished"] = C.clock_mark()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            session.alive()
            if any(c.process.poll() is not None for c in captures):
                raise RuntimeError("Capture exited before tail completed")
            session.tick()
            time.sleep(.1)
        session.tick(finished=True)
        data["timing_marks"]["model_observation_finished"] = C.clock_mark()
        for observer in captures:
            observer.stop()
        source_after = C.source_snapshot(folder, "final")
        queues_after = C.queue_snapshot(folder, "final")
        drops = {n: queues_after[n] - v for n, v in queues_before.items()}
        if any(v < 0 for v in drops.values()) or source_after["drops"] < source_before["drops"]:
            raise RuntimeError("Counters reset during collection")
        data["queue_root_drop_deltas"] = drops
        data["source_pacing"] = {"dropped_packets_delta": source_after["drops"] - source_before["drops"],
            "final_queued_packets": source_after["qlen"], "final_backlog_bytes": source_after["backlog"]}
        data["udp"] = {}
        for profile in C.PROFILES:
            name = profile["name"]
            sender = [r for r in C.udp_records(C.read_log(clients[name].path)) if r["role"] == "sender"]
            if not sender:
                raise RuntimeError("Missing sender summary for " + name)
            data["udp"][name] = {"sender": sender[-1], "receiver": C.receiver_summary(C.read_log(servers[name].path))}
        data["status"] = "completed"
    except BaseException as caught:
        error = caught
        data.update(status="failed", error=type(caught).__name__ + ": " + str(caught))
    finally:
        def clean(label, action):
            try:
                action()
            except Exception as caught:
                data["cleanup_errors"].append(label + ": " + str(caught))
        for observer in reversed(captures):
            clean("capture " + observer.name, observer.stop)
        for job in reversed(jobs):
            clean(job.name, job.stop)
        if monitor is not None:
            def stop_monitor():
                if monitor.poll() is None:
                    monitor.terminate()
                    try:
                        monitor.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        monitor.kill()
                        monitor.wait(timeout=3)
            clean("vmstat", stop_monitor)
        if pump is not None:
            clean("vmstat log pump", pump.drain)
        if handle is not None:
            clean("vmstat handle", handle.close)
        if fq_attempted:
            before = len(data["cleanup_errors"])
            clean("source fq", lambda: C.restore_source_qdisc(folder))
            data.setdefault("source_pacing", {})["noqueue_restored"] = len(data["cleanup_errors"]) == before
        if data["cleanup_errors"]:
            data["status"] = "failed"
        data["timing_marks"]["end"] = C.clock_mark()
        C.write_json(folder / "energy-feedback-traffic.json", data)
    if error is not None:
        raise error
    if data["status"] != "completed":
        raise RuntimeError("Collection cleanup failed; retain evidence")
    return data
