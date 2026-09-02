"""Launches the real `routing` binary and streams its stdout into a RunState.

Never edits or writes into the ns-3 tree — only invokes the pre-built binary
that already exists there, exactly the way E1_results/e1_driver_v2.py,
Task9_Evidence/multiseed_comparison.py and Task9_5_Evidence/ablation_driver.py
already do (all read-only referenced here, none modified).
"""
import os
import subprocess
import threading
import time
import uuid

from log_parser import RunState

NS3ROOT = os.path.expanduser("~/ns-allinone-3.35/ns-3.35-g62build")
BINARY = os.path.join(NS3ROOT, "build", "scratch", "routing")

# Verified this session: N_Vehicles=20/simTime=15 completed in ~111s wall-clock
# with real, non-degenerate MCC output. Anything larger is unverified in this
# session and the GUI must warn before requesting it.
SAFE_MAX_N_VEHICLES = 20
SAFE_MAX_SIM_TIME = 15
HARD_TIMEOUT_S = 600

ATTACK_FLAGS = {
    "S1": ["--attack_number=1"],
    "S2": ["--attack_number=2", "--intermittent_period=2"],
    "S3": ["--attack_number=3", "--grey_hole_target_flow=0"],
    "S4": ["--enable_cp_attack=1", "--cp_attack_number=4"],
    "S5": ["--enable_cp_attack=1", "--cp_attack_number=5"],
    "S6": ["--enable_cp_attack=1", "--cp_attack_number=6"],
}


def _clamp(value, default, maximum):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(value, maximum))


def build_args(attack, preset, ai_on, n_vehicles=None, sim_time=None):
    n = _clamp(n_vehicles, 20, SAFE_MAX_N_VEHICLES)
    t = _clamp(sim_time, 15, SAFE_MAX_SIM_TIME)
    args = [
        "--routing_test=true",
        f"--N_Vehicles={n}",
        f"--simTime={t}",
        "--routing_algorithm=4",
        "--architecture=0",
        "--maxspeed=80",
        "--detection_mode=lightweight",
        "--drop_rate=60",
        "--attack_percentage=40",
    ]
    args += ATTACK_FLAGS.get(attack, ATTACK_FLAGS["S1"])
    if ai_on:
        args.append("--enable_full_mode_ai=1")
    return args


class Run:
    def __init__(self, run_id, args):
        self.run_id = run_id
        self.args = args
        self.state = RunState()
        self.proc = None
        self.done = False
        self.exit_code = None
        self.error = None
        self.started_at = time.time()
        self._lock = threading.Lock()

    def _reader_thread(self):
        try:
            env = dict(os.environ)
            env["LD_LIBRARY_PATH"] = (
                os.path.join(NS3ROOT, "build", "lib") + ":" + env.get("LD_LIBRARY_PATH", "")
            )
            for v in ("GRB_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS",
                      "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
                env[v] = "1"
            self.proc = subprocess.Popen(
                [BINARY] + self.args,
                cwd=NS3ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in self.proc.stdout:
                with self._lock:
                    self.state.feed_line(line)
            self.proc.wait(timeout=HARD_TIMEOUT_S)
            self.exit_code = self.proc.returncode
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.error = f"timed out after {HARD_TIMEOUT_S}s"
        except FileNotFoundError:
            self.error = f"routing binary not found at {BINARY} — build it first"
        except Exception as exc:  # noqa: BLE001 — surfaced to the GUI, not swallowed
            self.error = str(exc)
        finally:
            with self._lock:
                self.done = True

    def start(self):
        threading.Thread(target=self._reader_thread, daemon=True).start()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def status(self):
        with self._lock:
            payload = self.state.to_status()
        payload.update({
            "run_id": self.run_id,
            "args": self.args,
            "running": not self.done,
            "done": self.done,
            "exit_code": self.exit_code,
            "error": self.error,
            "elapsed_s": round(time.time() - self.started_at, 1),
        })
        return payload


class RunManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._current = None

    def start_run(self, attack, preset, ai_on, n_vehicles=None, sim_time=None):
        with self._lock:
            if self._current is not None and not self._current.done:
                return None, "a run is already active — stop it before starting another"
            args = build_args(attack, preset, ai_on, n_vehicles, sim_time)
            run = Run(str(uuid.uuid4()), args)
            self._current = run
            run.start()
            return run, None

    def get(self, run_id):
        if self._current is not None and self._current.run_id == run_id:
            return self._current
        return None

    def stop(self, run_id):
        run = self.get(run_id)
        if run is None:
            return False
        run.stop()
        return True


manager = RunManager()
