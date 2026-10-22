"""One A/adaptive UDP event diagnostic; original calibration is unchanged.
Reuses source-guarded capture/owned-job helpers and the original source criteria.
No automatic retries or comparison loop. No claim that source timing is fixed.
"""
from battery_calibration_support import *

def collect_event_load(applied, directory, duration, controller, event_tick):
    """One diagnostic; event_tick runs in this loop, never in a background thread."""
    token = uuid.uuid4().hex[:12]
    jobs, observers, clients, servers = [], [], {}, {}
    monitor = pump = monitor_handle = None
    fq_attempted = False
    data = {"schema": 1, "protocol": "battery-udp-event-diagnostic-v1", "status": "starting",
            "scenario": "A", "mode": "adaptive", "duration_s": duration, "payload_bytes": 1200,
            "profiles": PROFILES, "policy": CALIBRATION_POLICY, "battery_event_enabled": True,
            "link_failure_enabled": True, "socket_pacing_cap_enabled": False,
            "source_fq_options": SOURCE_FQ_OPTIONS, "initial_epoch": applied["epoch"],
            "cleanup_errors": [], "timing_marks": {"begin": clock_mark()},
            "scope": "One event diagnostic with source irregularity retained; not a calibrated QoS comparison"}

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
        print("Both captures ready; private state; weak event at +8s and UAV1 failure at +20s after both streams observed.", flush=True)
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
        write_json(directory / "diagnostic-data.json", data)
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
        print("Both streams observed; event diagnostic started (source acceptance is assessed separately).", flush=True)
        deadline = time.monotonic() + bound
        while any(job.process.poll() is None for job in clients.values()):
            require_alive()
            event_tick(data, False)
            if monitor.poll() is not None or any(job.process.poll() not in (None, 0) for job in clients.values()):
                raise RuntimeError("A client or vmstat monitor failed during calibration")
            if time.monotonic() > deadline:
                raise RuntimeError("UDP clients exceeded the bounded run time")
            time.sleep(.1)
        event_tick(data, True)
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
        data["initial_video_meter_deltas"] = {name: ma[name] - mb[name] for name in ma}
        if any(value < 0 for value in data["initial_video_meter_deltas"].values()):
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
        write_json(directory / "diagnostic-data.json", data)
    if error is not None:
        raise error
    if data["status"] != "completed":
        raise RuntimeError("Traffic/capture/source cleanup failed; inspect diagnostic-data.json")
    return {"collection_status": "completed", "duration_s": duration,
            "battery_event_enabled": True, "link_failure_enabled": True,
            "data_file": "diagnostic-data.json"}

def report_diagnostic(directory):
    """Captured sequence audit plus unchanged source criteria, without a QoS pass."""
    directory = Path(directory)
    outer = json.loads((directory / "manifest.json").read_text())
    data = json.loads((directory / "diagnostic-data.json").read_text())
    if (outer.get("protocol") != "battery-udp-event-diagnostic-v1"
            or outer.get("status") != "completed" or outer.get("cleanup_errors")
            or data.get("status") != "completed" or data.get("cleanup_errors")):
        raise ValueError("A completed diagnostic with verified cleanup is required")
    if (data.get("protocol") != "battery-udp-event-diagnostic-v1"
            or data.get("battery_event_enabled") is not True or data.get("link_failure_enabled") is not True
            or data.get("socket_pacing_cap_enabled") is not False
            or data.get("policy") != CALIBRATION_POLICY or data.get("profiles") != list(PROFILES)
            or data.get("payload_bytes") != 1200 or data.get("duration_s") != 40
            or data.get("mode") != "adaptive" or data.get("scenario") != "A"
            or set(outer.get("stages", {})) != {"initial", "weak", "failed"}):
        raise ValueError("Diagnostic profile, stage set or source criteria differs")
    captures, quality, issues = {}, {}, []
    for endpoint in ("u1", "gs"):
        count, captures[endpoint] = read_capture(directory / (endpoint + ".pcap"),
                                                data["source_ip"], data["destination_ip"])
        quality[endpoint] = tcpdump_stats((directory / (endpoint + "-tcpdump.log")).read_text())
        if count != quality[endpoint]["captured"] or quality[endpoint]["kernel_dropped"]:
            issues.append(endpoint + ": capture count mismatch or capture drops")
    result = {"schema": 1, "protocol": "battery-udp-event-diagnostic-v1",
              "capture_quality": quality, "evidence_issues": issues, "streams": {},
              "source_policy": CALIBRATION_POLICY, "performance_comparison_supported": False,
              "video_meter_totals_by_epoch": outer.get("video_meter_totals"),
              "queue_root_drop_deltas": data["queue_root_drop_deltas"],
              "source_pacing": data["source_pacing"],
              "scope": "One descriptive event diagnostic; source criteria are unchanged. No causal loss attribution, QoS, energy or repeatability claim."}
    anchors = {"before_weak": data["timing_marks"]["both_streams_observed"],
               "after_weak": outer["stages"]["weak"]["confirmation_observed"],
               "after_link_down": outer["stages"]["failed"]["link_down_confirmed"]}
    offsets = [(mark["wall_ns"] - mark["monotonic_ns"]) for mark in anchors.values()]
    offset_spread_ms = (max(offsets) - min(offsets)) / 1e6
    window_valid = offset_spread_ms <= 5 and not issues
    result["window_clock_check"] = {"wall_minus_monotonic_spread_ms": offset_spread_ms,
         "usable": window_valid,
         "caveat": "Windows are +2 to +6 seconds after host observations, using pcap wall time. Sparse clock checks cannot exclude every clock adjustment. Not exact packet-level switch times or one-way delay."}
    for profile in PROFILES:
        name, port = profile["name"], profile["port"]
        src, dst = captures["u1"][port], captures["gs"][port]
        row = assess_source(src, data["udp"][name]["sender"], 40, profile["rate_mbps"])
        first, second = set(src["ids"]), set(dst["ids"])
        missing, extra = sorted(first-second), sorted(second-first)
        ambiguous = (issues or row["evidence_issues"] or extra
                     or dst["datagrams"] != len(second)
                     or data["source_pacing"]["final_queued_packets"]
                     or data["source_pacing"]["final_backlog_bytes"])
        windows, omitted_windows = {}, {}
        if window_valid:
            for label, mark in anchors.items():
                lower, upper = mark["wall_ns"] + 2_000_000_000, mark["wall_ns"] + 6_000_000_000
                end_limit = (outer["stages"]["weak"]["publish_start"]["wall_ns"] if label == "before_weak" else
                             outer["stages"]["failed"]["link_down_begin"]["wall_ns"] if label == "after_weak" else
                             data["timing_marks"]["traffic_finished"]["wall_ns"])
                if upper > end_limit:
                    omitted_windows[label] = "Window overlaps the next event or extends past traffic completion"
                    continue
                cohort = {seq for seq, stamp in src["ids"].items() if lower <= stamp < upper}
                observed = sum(lower <= stamp < upper for stamp in dst["ids"].values())
                windows[label] = {"window_wall_ns": [lower, upper], "source_packets": len(cohort),
                    "gs_arrival_packets_in_window": observed,
                    "source_cohort_ids_absent_at_gs_by_capture_end": sorted(cohort - second),
                    "source_payload_mbps": len(cohort) * 1200 * 8 / 4e6,
                    "gs_arrival_payload_mbps": observed * 1200 * 8 / 4e6}
        row.update(source_unique_packets=len(first), gs_unique_packets=len(second),
                   source_ids_not_observed_at_gs=missing, gs_ids_not_observed_at_source=extra,
                   missing_observed_packet_percent=100 * len(missing) / len(first) if first else None,
                   packet_set_audit="INCONCLUSIVE" if ambiguous else "COMPLETE_CAPTURE_AUDIT",
                   receiver_report=data["udp"][name]["receiver"],
                   gs_statistics=stream_statistics(dst, 40) if len(second) >= 2 else None,
                   descriptive_windows=windows, omitted_windows=omitted_windows)
        result["streams"][name] = row
    verdicts = [row["verdict"] for row in result["streams"].values()]
    source_issues = any(issue.startswith("u1:") for issue in issues)
    result["source_verdict"] = ("INCONCLUSIVE" if source_issues or "INCONCLUSIVE" in verdicts
                                 else "FAIL" if "FAIL" in verdicts else "PASS")
    write_json(directory / "diagnostic-report.json", result)
    print("\nSOURCE CRITERIA (unchanged):", result["source_verdict"])
    for name, row in result["streams"].items():
        print("%s: source %d; GS %d; source IDs absent at GS %d; source interior gap %.3f ms; %s" %
              (name, row["source_unique_packets"], row["gs_unique_packets"],
               len(row["source_ids_not_observed_at_gs"]),
               row["source_statistics"]["maximum_interior_captured_gap_ms"], row["verdict"]))
        for label, window in row["descriptive_windows"].items():
            print("  %s: source %.3f Mbps; GS arrivals %.3f Mbps; source-cohort IDs absent at GS %d" %
                  (label, window["source_payload_mbps"], window["gs_arrival_payload_mbps"],
                   len(window["source_cohort_ids_absent_at_gs_by_capture_end"])))
    print("VIDEO meter totals by epoch:", result["video_meter_totals_by_epoch"])
    print("UAV root drop deltas:", result["queue_root_drop_deltas"])
    print("Diagnostic only. Source failures remain failures; these data do not establish a calibrated QoS comparison.")
    print("Saved:", directory / "diagnostic-report.json")
    return result
