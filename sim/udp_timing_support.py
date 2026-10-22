"""Host-side log observation times, NOT packet arrival/measurement times."""
import json
import threading
import time


def clock_mark():
    # Bracket the wall-clock sample; monotonic_ns is shared by host processes.
    before = time.monotonic_ns()
    wall = time.time_ns()
    after = time.monotonic_ns()
    return {"monotonic_ns": before, "wall_ns": wall,
            "wall_sample_bracket_end_ns": after}


class OutputPump:
    """Preserve raw stdout and separately timestamp each observed complete line.

    A line can be delayed by iperf, docker, pipes, and host scheduling. Never
    reinterpret observed_monotonic_ns as the receiver interval's exact end.
    """
    def __init__(self, process, raw_handle, timing_path):
        self.process = process
        self.raw_handle = raw_handle
        self.timing_path = timing_path
        self.error = None
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        try:
            with self.timing_path.open("x", encoding="utf-8") as timing:
                for number, line in enumerate(self.process.stdout, 1):
                    observed = time.monotonic_ns()
                    self.raw_handle.write(line)
                    self.raw_handle.flush()
                    timing.write(json.dumps({"line_number": number,
                        "observed_monotonic_ns": observed,
                        "text": line.rstrip("\r\n")}, ensure_ascii=True) + "\n")
                    timing.flush()
        except Exception as error:
            self.error = error
        finally:
            self.process.stdout.close()

    def drain(self):
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("Log observer did not finish: %s" % self.timing_path)
        if self.error is not None:
            raise RuntimeError("Log observer failed: %s" % self.error)
