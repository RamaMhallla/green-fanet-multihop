"""Candidate buffer diagnostic. No source-calibration criteria are relaxed."""
from battery_calibration_support import *
from core.battery_enforcement import queue_commands as original_queue_commands
from run_battery_source_calibration import verify_owned_queues, require

PROTOCOL = "battery-voice-buffer-diagnostic-v1"
BUFFER_PROFILE = {
    "only_queue_setting_change": "VOICE netem packet limit on eight UAV egress interfaces",
    "voice_limit_packets": 128, "old_voice_limit_packets": 100,
    "video_and_control_limit_packets": 100,
    "voice_rate_and_ceil_mbps": 1.3, "relay_rate_and_ceil_mbps": 5.0,
    "source_settings_unchanged": True, "capture_separation_screen_ms": 100.0,
    "screen_scope": "Captured delivery and paired capture timestamp separation, not application latency/QoS",
}


def queue_commands(interface, delay_ms):
    commands = original_queue_commands(interface, delay_ms)
    changed = 0
    for row in commands:
        if "netem" in row and "7e10:" in row:
            index = row.index("limit") + 1
            require(row[index] == "100", "Unexpected old VOICE netem limit")
            row[index] = "128"
            changed += 1
    require(changed == 1, "Expected exactly one VOICE queue command")
    return commands


def verify_buffer_queues():
    snapshot = verify_owned_queues()
    for interface, row in snapshot.items():
        for handle, expected in (("7e10:", 128), ("7e20:", 100), ("7e30:", 100)):
            match = re.search(r"^qdisc netem " + re.escape(handle) + r" [^\n]*", row["qdiscs"], re.M)
            require(match is not None, interface + ": missing " + handle)
            limit = re.search(r"\blimit (\d+)\b", match[0])
            require(limit is not None and int(limit[1]) == expected,
                    interface + ": incorrect packet limit for " + handle)
    return snapshot


def leaf_voice_drops(text):
    block = re.search(r"^qdisc netem 7e10: [^\n]*\n(.*?)(?=^qdisc |\Z)", text, re.M | re.S)
    if not block:
        raise ValueError("Missing VOICE netem statistics")
    match = re.search(r"\bdropped (\d+)\b", block[1])
    if not match:
        raise ValueError("Missing VOICE dropped counter")
    return int(match[1])


def capture_time_summary(source, destination, clock_usable):
    """Matched SOFTWARE capture-time separations; not application acknowledgements."""
    matched = sorted(set(source) & set(destination))
    values = sorted((destination[seq] - source[seq]) / 1e6 for seq in matched)
    if not values:
        return {"status": "INCONCLUSIVE", "matched_packets": 0}
    result = {"status": "DESCRIPTIVE" if clock_usable and values[0] >= 0 else "INCONCLUSIVE",
              "matched_packets": len(values), "minimum_ms": values[0],
              "median_ms": values[(len(values)-1)//2],
              "p99_ms": values[max(0, math.ceil(.99*len(values))-1)],
              "maximum_ms": values[-1], "above_100ms": sum(v > 100 for v in values),
              "scope": "GS pcap wall timestamp minus matching source pcap wall timestamp; not application delay or a QoS guarantee. Sparse clock checks are limited."}
    return result


def collect_voice_buffer(applied, directory, duration, controller):
    """Collect one unchanged initial plan. No state publication or link action."""
    token = uuid.uuid4().hex[:12]
    jobs, observers, clients, servers = [], [], {}, {}
    monitor = pump = monitor_handle = None
    fq_attempted = False
    data = {"schema": 1, "protocol": "battery-voice-buffer-diagnostic-v1", "status": "starting",
            "scenario": "A", "mode": "fixed", "duration_s": duration, "payload_bytes": 1200,
            "profiles": PROFILES, "policy": CALIBRATION_POLICY, "battery_event_enabled": False,
            "link_failure_enabled": False, "socket_pacing_cap_enabled": False,
            "source_fq_options": SOURCE_FQ_OPTIONS, "epoch": applied["epoch"],
            "voice_buffer_profile": BUFFER_PROFILE,
            "cleanup_errors": [], "timing_marks": {"begin": clock_mark()},
            "scope": "One instrumented voice-buffer diagnostic on protected queues; not QoS or energy proof"}

    def require_alive():
        if controller.poll() is not None:
            raise RuntimeError("Protected controller exited during calibration")

    def ofctl(operation, *args):
        return command(["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", operation, P.SWITCH_NAME] + list(args))

    error = None
    try:
        for executable in ("tcpdump", "nsenter", "timeout", "vmstat"):
            if not shutil.which(executable):
                raise RuntimeError("Required executable missing: " + executable)
        for node in ("u1", "gs"):
            prefix = ["sudo", "-n", "docker", "exec", "mn." + node, "iperf3"]
            version = command(prefix + ["--version"])
            help_text = command(prefix + ["--help"])
            if not version.startswith("iperf 3.9") or "--forceflush" not in help_text or "--fq-rate" not in help_text:
                raise RuntimeError("This calibration requires iperf3 3.9 with --forceflush/--fq-rate")
            data[node + "_iperf_version"] = version
        for profile in PROFILES:
            if listener(profile["port"]):
                raise RuntimeError("Existing listener on GS port " + str(profile["port"]) + "; left untouched")
        original = capture(directory, "source-qdisc-original.json",
                           source_tc("-j", "-s", "qdisc", "show", "dev", SOURCE_INTERFACE))
        if root_qdisc(original).get("kind") != "noqueue":
            raise RuntimeError("Source root must be noqueue before calibration; left untouched")
        fq_attempted = True
        command(source_tc("qdisc", "add", "dev", SOURCE_INTERFACE, "root", "handle", SOURCE_HANDLE,
                          "fq", *SOURCE_FQ_OPTIONS))
        source_before = source_snapshot(directory, "before")
        before = queue_snapshot(directory, "before")
        mid = applied["video_meter_id"]
        meter_before = ofctl("meter-stats", "meter=" + str(mid))
        (directory / "video-meter-before.txt").write_text(meter_before)
        source_ip = P.HOSTS["u1"][0].split("/")[0]
        destination = P.HOSTS["gs"][0].split("/")[0]
        data.update(source_ip=source_ip, destination_ip=destination)
        packet_filter = ("ip and host %s and host %s and (udp or tcp) and (port 5201 or port 5202)"
                         % (source_ip, destination))
        data["capture_settings"] = {"filter": packet_filter, "snaplen": 128,
            "post_jobs_observation_s": 8, "clock": "pcap wall clock; not controller monotonic timestamps"}
        for name in ("u1", "gs"):
            observer = Capture(directory, name, container_pid("mn." + name), name + "-eth0", packet_filter)
            observers.append(observer)
            observer.ready()
        print("Both captures ready; private UAV1=90%; NO battery event or link failure; VOICE buffer candidate 128.", flush=True)
        bound = duration + 50
        for profile in PROFILES:
            job = Job(directory, token, "mn.gs", profile["name"].lower() + "-server",
                      ["iperf3", "-s", "-1", "-p", str(profile["port"]), "-i", "1", "--forceflush"], bound)
            jobs.append(job)
            servers[profile["name"]] = job
        deadline = time.monotonic() + 10
        while not all(listener(profile["port"]) for profile in PROFILES):
            require_alive()
            if any(job.process.poll() is not None for job in servers.values()) or time.monotonic() > deadline:
                raise RuntimeError("Both UDP servers did not become ready")
            time.sleep(.1)
        monitor_handle = (directory / "vmstat.log").open("w", encoding="utf-8")
        monitor = subprocess.Popen(["vmstat", "-t", "1"], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1,
            env=dict(os.environ, LC_ALL="C"))
        pump = OutputPump(monitor, monitor_handle, directory / "vmstat.timing.jsonl")
        data["timing_marks"]["client_launch_origin"] = clock_mark()
        print("Concurrent UDP: VOICE 1.2 Mbps, VIDEO 4.2 Mbps, 1200-byte payload; --fq-rate 0.", flush=True)
        for profile in PROFILES:
            job = Job(directory, token, "mn.u1", profile["name"].lower() + "-client",
                      ["iperf3", "-c", destination, "-p", str(profile["port"]), "-u",
                       "-b", "%gM" % profile["rate_mbps"], "--fq-rate", "0", "-l", "1200",
                       "-t", str(duration), "-i", "1", "-S", str(profile["tos"]), "--forceflush"], bound)
            jobs.append(job)
            clients[profile["name"]] = job
            data["timing_marks"][profile["name"].lower() + "_client_launch"] = job.launch_mark
        data["job_commands"] = {job.name: job.argv for job in jobs}
        write_json(directory / "voice-buffer-data.json", data)
        deadline = time.monotonic() + 15
        while True:
            require_alive()
            if any(job.process.poll() is not None for job in jobs):
                raise RuntimeError("A traffic job exited before both receive streams were confirmed")
            if all(any(row["role"] == "interval" and row["total_packets"] > row["lost_packets"]
                       for row in udp_records(read_log(job.path))) for job in servers.values()):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Both UDP receive streams were not confirmed within 15s")
            time.sleep(.1)
        data["timing_marks"]["both_streams_observed"] = clock_mark()
        print("Both UDP streams observed; collecting one fixed baseline for %ds." % duration, flush=True)
        deadline = time.monotonic() + bound
        while any(job.process.poll() is None for job in clients.values()):
            require_alive()
            if monitor.poll() is not None or any(job.process.poll() not in (None, 0) for job in clients.values()):
                raise RuntimeError("A client or vmstat monitor failed during calibration")
            if time.monotonic() > deadline:
                raise RuntimeError("UDP clients exceeded the bounded run time")
            time.sleep(.1)
        for job in jobs:
            job.process.wait(timeout=10)
            job.pump.drain()
            job.handle.flush()
            if job.process.returncode != 0:
                raise RuntimeError("Traffic job failed: " + job.name)
        data["timing_marks"]["traffic_finished"] = clock_mark()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            require_alive()
            if any(observer.process.poll() is not None for observer in observers):
                raise RuntimeError("Capture exited before tail observation completed")
            time.sleep(.1)
        for observer in observers:
            observer.stop()
        source_after = source_snapshot(directory, "final")
        after = queue_snapshot(directory, "final")
        drops = {name: after[name] - count for name, count in before.items()}
        if any(count < 0 for count in drops.values()) or source_after["drops"] < source_before["drops"]:
            raise RuntimeError("Queue counters reset during calibration")
        data["queue_root_drop_deltas"] = drops
        data["source_pacing"] = {"dropped_packets_delta": source_after["drops"] - source_before["drops"],
            "final_queued_packets": source_after["qlen"], "final_backlog_bytes": source_after["backlog"]}
        meter_after = ofctl("meter-stats", "meter=" + str(mid))
        (directory / "video-meter-final.txt").write_text(meter_after)
        mb, ma = meter_counts(meter_before), meter_counts(meter_after)
        data["video_meter_deltas"] = {name: ma[name] - mb[name] for name in ma}
        if any(value < 0 for value in data["video_meter_deltas"].values()):
            raise RuntimeError("Video meter counters reset during calibration")
        data["udp"] = {}
        for profile in PROFILES:
            name = profile["name"]
            receiver = receiver_summary(read_log(servers[name].path))
            senders = [row for row in udp_records(read_log(clients[name].path)) if row["role"] == "sender"]
            if not senders or senders[-1]["end_s"] - senders[-1]["start_s"] < duration - 1:
                raise RuntimeError("No complete planned-duration sender summary for " + name)
            data["udp"][name] = {"receiver": receiver, "sender": senders[-1]}
            print("%s receiver: %.3f Mbps; missing %d/%d; displayed jitter %.3f ms" %
                  (name, receiver["bitrate_mbps"], receiver["lost_packets"], receiver["total_packets"],
                   receiver["jitter_ms"]), flush=True)
        data["status"] = "completed"
    except BaseException as caught:
        error = caught
        data["status"] = "failed"
        data["error"] = type(caught).__name__ + ": " + str(caught)
    finally:
        def cleanup(label, action):
            try:
                action()
            except Exception as caught:
                data["cleanup_errors"].append(label + ": " + str(caught))
        for observer in reversed(observers):
            cleanup("capture " + observer.name, observer.stop)
        for job in reversed(jobs):
            cleanup(job.name, job.stop)
        if monitor is not None:
            def stop_monitor():
                if monitor.poll() is None:
                    monitor.terminate()
                    try:
                        monitor.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        monitor.kill(); monitor.wait(timeout=3)
            cleanup("vmstat process", stop_monitor)
        if pump is not None:
            cleanup("vmstat observer", pump.drain)
        if monitor_handle is not None:
            cleanup("vmstat log", monitor_handle.close)
        if fq_attempted:
            before_cleanup = len(data["cleanup_errors"])
            cleanup("source fq", lambda: restore_source_qdisc(directory))
            data.setdefault("source_pacing", {})["noqueue_restored"] = len(data["cleanup_errors"]) == before_cleanup
        if data["cleanup_errors"]:
            data["status"] = "failed"
        data["timing_marks"]["end"] = clock_mark()
        write_json(directory / "voice-buffer-data.json", data)
    if error is not None:
        raise error
    if data["status"] != "completed":
        raise RuntimeError("Traffic/capture/source cleanup failed; inspect voice-buffer-data.json")
    return {"collection_status": "completed", "duration_s": duration,
            "battery_event_enabled": False, "link_failure_enabled": False,
            "data_file": "voice-buffer-data.json"}

def report_voice_buffer(directory):
    directory = Path(directory)
    outer = json.loads((directory / "manifest.json").read_text())
    data = json.loads((directory / "voice-buffer-data.json").read_text())
    for doc in (outer, data):
        if (doc.get("status") != "completed" or doc.get("cleanup_errors")
                or doc.get("protocol") != PROTOCOL or doc.get("voice_buffer_profile") != BUFFER_PROFILE
                or doc.get("battery_event_enabled") is not False
                or doc.get("link_failure_enabled") is not False
                or doc.get("mode") != "fixed" or doc.get("scenario") != "A"
                or doc.get("duration_s") != 40):
            raise ValueError("Completed, restored 40s FIXED/A buffer diagnostic required")
    if (data.get("policy") != CALIBRATION_POLICY or data.get("profiles") != list(PROFILES)
            or data.get("socket_pacing_cap_enabled") is not False or data.get("payload_bytes") != 1200):
        raise ValueError("Source criteria or traffic profile changed")
    captures, quality, issues = {}, {}, []
    for node in ("u1", "gs"):
        count, captures[node] = read_capture(directory / (node + ".pcap"), data["source_ip"], data["destination_ip"])
        quality[node] = tcpdump_stats((directory / (node + "-tcpdump.log")).read_text())
        if count != quality[node]["captured"] or quality[node]["kernel_dropped"]:
            issues.append(node + ": capture count mismatch or capture drops")
    pacing = data["source_pacing"]
    if (pacing.get("noqueue_restored") is not True or pacing.get("dropped_packets_delta")
            or pacing.get("final_queued_packets") or pacing.get("final_backlog_bytes")):
        issues.append("Source fq drops/backlog or unverified restoration")
    offsets = [m["wall_ns"]-m["monotonic_ns"] for m in data["timing_marks"].values()
               if isinstance(m, dict) and "wall_ns" in m and "monotonic_ns" in m]
    spread = (max(offsets)-min(offsets))/1e6 if len(offsets) >= 2 else None
    clock_usable = spread is not None and spread <= 5
    streams = {}
    for profile in PROFILES:
        name, port = profile["name"], profile["port"]
        src, dst = captures["u1"][port], captures["gs"][port]
        row = assess_source(src, data["udp"][name]["sender"], 40, profile["rate_mbps"])
        first, second = set(src["ids"]), set(dst["ids"])
        row.update(source_unique_packets=len(first), gs_unique_packets=len(second),
                   source_ids_not_observed_at_gs=sorted(first-second),
                   gs_ids_not_observed_at_source=sorted(second-first),
                   gs_duplicate_observations=dst["datagrams"]-len(second),
                   paired_capture_time=capture_time_summary(src["ids"], dst["ids"], clock_usable))
        streams[name] = row
    leaf_drops = {}
    for drone in P.DRONES:
        for index in (0, 1):
            interface = drone.lower() + "-eth" + str(index)
            before = leaf_voice_drops((directory / ("queue-before-"+interface+".txt")).read_text())
            final = leaf_voice_drops((directory / ("queue-final-"+interface+".txt")).read_text())
            if final < before:
                raise ValueError("VOICE queue counter reset")
            leaf_drops[interface] = final-before
    voice = streams["VOICE"]
    ambiguous = (issues or voice["evidence_issues"] or voice["gs_ids_not_observed_at_source"]
                 or voice["gs_duplicate_observations"] or not voice["source_unique_packets"])
    zero = not voice["source_ids_not_observed_at_gs"] and not any(leaf_drops.values())
    delivery = "INCONCLUSIVE" if ambiguous else "ZERO_OBSERVED_MISSING" if zero else "NONZERO_MISSING_OR_QUEUE_DROPS"
    separation = voice["paired_capture_time"]
    time_screen = ("INCONCLUSIVE" if ambiguous or separation["status"] != "DESCRIPTIVE"
                   else "EXCEEDS_100MS" if separation["maximum_ms"] > 100 else "WITHIN_100MS")
    source_verdicts = [row["verdict"] for row in streams.values()]
    source_verdict = ("INCONCLUSIVE" if any(issue.startswith("u1:") for issue in issues) or "INCONCLUSIVE" in source_verdicts
                      else "FAIL" if "FAIL" in source_verdicts else "PASS")
    result = {"protocol": PROTOCOL, "voice_buffer_profile": BUFFER_PROFILE,
              "source_verdict": source_verdict, "voice_delivery_screen": delivery,
              "voice_capture_time_screen": time_screen, "streams": streams,
              "capture_quality": quality, "evidence_issues": issues,
              "wall_minus_monotonic_spread_ms": spread,
              "voice_leaf_drop_deltas": leaf_drops, "source_pacing": pacing,
              "video_meter_deltas": data["video_meter_deltas"],
              "queue_root_drop_deltas": data["queue_root_drop_deltas"],
              "performance_comparison_supported": False,
              "scope": "Single no-event diagnostic. Original source FAIL remains FAIL. Zero observed missing only refers to captured source IDs within a finite capture. No QoS, latency, repeatability or energy guarantee."}
    write_json(directory / "voice-buffer-report.json", result)
    print("\nSOURCE CRITERIA (unchanged):", source_verdict)
    for name, row in streams.items():
        print("%s: source %d; GS %d; absent %d; source gap %.3f ms; %s" %
              (name, row["source_unique_packets"], row["gs_unique_packets"], len(row["source_ids_not_observed_at_gs"]),
               row["source_statistics"]["maximum_interior_captured_gap_ms"], row["verdict"]))
    print("VOICE DELIVERY SCREEN:", delivery)
    print("VOICE leaf drop deltas:", leaf_drops)
    print("VOICE CAPTURE-TIME SCREEN:", time_screen)
    print("VOICE paired capture-time statistics:", separation)
    print("Capture quality:", quality)
    print("Evidence issues:", issues)
    print("VIDEO meter:", data["video_meter_deltas"])
    print("UAV root drop deltas:", data["queue_root_drop_deltas"])
    print("No QoS PASS is issued. Keep this protocol separate; review before any repeat or event test.")
    print("Saved:", directory / "voice-buffer-report.json")
    return result
