#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NETWATCH MTR (EN) — route watch + loss diagnostics for ISP escalation (Xfinity-friendly).

What this script does (high level):
- Every second it runs `mtr -r -w -n -c 1 -i 1 <target>` and prints the block to console
  and to the current epoch log.
- In parallel it pings:
    * the main target (stateful: detects UP/DOWN),
    * every discovered hop IP (simple continuous ping with timestamps),
    * each user-provided “extra IP” (stateful: detects UP/DOWN).
- It counts intermediate-hop loss **only when the final target is DOWN** in that second.
- Hops shown as `???` in the very first snapshot of an epoch are baseline-excluded until
  a debounced route change starts a new epoch.
- All outputs are written to a dedicated run folder with per-second CSV summaries.

Why you saw the gawk error before:
- The previous version piped `ping | gawk '...'` via `/bin/bash -lc` with escaped quotes,
  which produced backslashes inside the awk program. Now we spawn `ping` and `gawk`
  **as two processes** connected by a pipe using `subprocess`, so no shell quoting is needed.

System tools only:
- Uses system `mtr` and `ping` (Ubuntu/macOS). `gawk` is optional; if present, it stamps
  each line. If `gawk` is missing, Python adds timestamps itself.

If `mtr` needs privileges:
- The script re-execs itself via `sudo` (you’ll be prompted for your password).
"""

from __future__ import annotations
import os, re, sys, time, signal, shutil, threading, subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------- SETTINGS ----------------------------
SNAPSHOT_PERIOD_SEC = 1.0                   # mtr cadence (1 probe/hop/sec)
ROUTE_CHANGE_STABLE_SNAPSHOTS = 3           # debounce: signature must persist ≥3 snapshots
ROTATION_MIN_GAP_SEC = 60                   # minimal time between "epochs"
MAX_HOP_PINGERS = 32                        # cap concurrent hop pingers (safety)
TARGET_LOSS_THRESHOLD_SEC = 2.0             # for route-flap notes when target is DOWN
AGG_FLUSH_EVERY_SEC = 10                    # write agg csv every N seconds

# ---------------------------- HELPERS ----------------------------
def ts_human() -> str: return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def ts_file()  -> str: return datetime.now().strftime("%Y%m%d_%H%M%S")
def ts_br()    -> str: return "[" + ts_human() + "]"
def have(cmd: str) -> bool: return shutil.which(cmd) is not None
def on_linux() -> bool: return sys.platform.startswith("linux")
def on_macos() -> bool: return sys.platform == "darwin"

# ----------------- mtr sanity + sudo re-exec if required -----------------
def try_mtr_once(target: str) -> Tuple[bool, str]:
    """Call mtr once to see whether it runs without root privileges."""
    try:
        out = subprocess.check_output(
            ["mtr", "-r", "-w", "-n", "-c", "1", "-i", "1", target],
            text=True, stderr=subprocess.STDOUT
        )
        return True, out
    except subprocess.CalledProcessError as e:
        return False, e.output or ""
    except FileNotFoundError:
        return False, "mtr not found"

def ensure_mtr_or_reexec_with_sudo(target: str) -> None:
    """If mtr demands raw-socket privileges, restart via sudo."""
    if not have("mtr"):
        print("Error: 'mtr' not found. Please install it.")
        sys.exit(1)
    ok, out = try_mtr_once(target)
    if ok:
        return
    need_root = ("mtr-packet" in out or "Operation not permitted" in out
                 or "Permission denied" in out or "raw socket" in out)
    if need_root and os.geteuid() != 0 and have("sudo"):
        print("⚠️  mtr needs privileges. Re-executing via sudo — enter your password.")
        os.execvp("sudo", ["sudo", sys.executable, os.path.abspath(__file__), *sys.argv[1:]])
    else:
        print("mtr failed to start. Output:\n" + (out.strip() or "(empty)"))
        print("Hint: macOS — set suid on mtr-packet or run via sudo; Linux — sudo.")
        sys.exit(1)

# ----------------------------- mtr parsing -----------------------------
@dataclass
class Hop:
    """Parsed row from mtr report."""
    idx:int; host:str; loss:float; snt:int; last:float; avg:float; best:float; wrst:float; stdev:float

# Regex matches typical mtr "-r -w -n" table rows.
_MTR_LINE_RE = re.compile(
    r"""^\s*(?P<idx>\d+)\.\|\-\-\s+
        (?P<host>\S+)\s+
        (?P<loss>\d+\.\d)\%\s+
        (?P<snt>\d+)\s+
        (?P<last>[\d\.]+)\s+
        (?P<avg>[\d\.]+)\s+
        (?P<best>[\d\.]+)\s+
        (?P<wrst>[\d\.]+)\s+
        (?P<stdev>[\d\.]+)""", re.X)

def parse_mtr_report(raw: str) -> List[Hop]:
    """Parse mtr raw text into Hop objects."""
    hops: List[Hop] = []
    for line in raw.splitlines():
        m = _MTR_LINE_RE.match(line)
        if m:
            hops.append(Hop(
                idx=int(m.group("idx")), host=m.group("host"),
                loss=float(m.group("loss")), snt=int(m.group("snt")),
                last=float(m.group("last")), avg=float(m.group("avg")),
                best=float(m.group("best")), wrst=float(m.group("wrst")),
                stdev=float(m.group("stdev")),
            ))
    return hops

def normalized_signature(hops: List[Hop], excluded_idxs: set[int]) -> str:
    """
    Build a normalized "route signature" used for debounced route-change detection.
    At excluded indices we force host to '???' so transient reveals don't flip signatures.
    """
    parts=[]
    for h in hops:
        host = "???" if h.idx in excluded_idxs else h.host
        parts.append(f"{h.idx}:{host}")
    return "|".join(parts)

# ----------------------- OS ping threads -----------------------
class PingThread(threading.Thread):
    """
    Continuous OS ping of a single IP with timestamps.
    - If gawk is present: we run two processes connected by a pipe:
          ping ...  |  gawk '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0; fflush(); }'
      so timestamps are added outside Python (zero quoting issues).
    - If gawk is absent: we read ping stdout in Python and prefix timestamps.
    - Output is appended to `outfile`.
    """
    def __init__(self, ip: str, outfile: Path):
        super().__init__(daemon=True)
        self.ip = ip
        self.outfile = outfile
        self.proc: Optional[subprocess.Popen] = None      # main process we monitor (gawk if used, else ping)
        self.proc_ping: Optional[subprocess.Popen] = None # underlying ping when gawk is used
        self.stop_evt = threading.Event()
        self.have_gawk = have("gawk")

    def _cmd(self) -> List[str]:
        # Linux: -O prints "no answer yet" on lost replies; macOS doesn't support it.
        if on_linux(): return ["ping", "-n", "-O", "-i", "1", self.ip]
        else:          return ["ping", "-n", "-i", "1", self.ip]

    def run(self) -> None:
        self.outfile.parent.mkdir(parents=True, exist_ok=True)
        with self.outfile.open("a", encoding="utf-8") as f:
            f.write(f"{ts_br()} [START ping {self.ip}]\n"); f.flush()

            if self.have_gawk:
                # Start ping -> stdout pipe
                self.proc_ping = subprocess.Popen(
                    self._cmd(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                # Start gawk reading from ping's stdout and writing directly into our file
                awk_program = '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0; fflush(); }'
                self.proc = subprocess.Popen(
                    ["gawk", awk_program],
                    stdin=self.proc_ping.stdout, stdout=f, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                # Keep the pipe open while both run
                while not self.stop_evt.is_set() and self.proc.poll() is None:
                    time.sleep(0.2)
            else:
                # No gawk: timestamp in Python
                self.proc = subprocess.Popen(
                    self._cmd(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                for line in self.proc.stdout:
                    if self.stop_evt.is_set():
                        break
                    f.write(f"{ts_br()} {line.rstrip()}\n"); f.flush()

            f.write(f"{ts_br()} [STOP  ping {self.ip}]\n"); f.flush()

    def stop(self) -> None:
        """Signal the thread to stop and terminate child processes."""
        self.stop_evt.set()
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
        except Exception:
            pass
        try:
            if self.proc_ping and self.proc_ping.poll() is None:
                self.proc_ping.terminate()
        except Exception:
            pass

class StatefulPingThread(PingThread):
    """
    Like PingThread, but we also classify lines into UP/DOWN to expose a loss state.
    We read the final stream (gawk-stamped or Python-stamped) and maintain a flag.
    """
    _TS_PREFIX_RE = re.compile(r"^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\]\s*")

    def __init__(self, ip: str, outfile: Path):
        super().__init__(ip, outfile)
        self.lock = threading.Lock()
        self.down_active: bool = False
        self.down_start: Optional[datetime] = None

    def _classify(self, line: str) -> Optional[bool]:
        """
        Return True for a successful reply, False for a lost/timeout/unreachable hint,
        None for unrecognized lines. Works across Linux/macOS wordings.
        """
        s = line.strip()
        if not s:
            return None
        # Remove leading "[YYYY-mm-dd HH:MM:SS]" if present (gawk/Python prefix)
        s = self._TS_PREFIX_RE.sub("", s)
        if "bytes from" in s or "time=" in s:
            return True
        if "Request timeout" in s or "no answer yet" in s:
            return False
        if "Destination Host Unreachable" in s or "Destination Net Unreachable" in s:
            return False
        if "100% packet loss" in s:
            return False
        return None

    def run(self) -> None:
        self.outfile.parent.mkdir(parents=True, exist_ok=True)
        with self.outfile.open("a", encoding="utf-8") as f:
            f.write(f"{ts_br()} [START ping {self.ip}]\n"); f.flush()

            # Start the pipeline (gawk if available)
            if self.have_gawk:
                self.proc_ping = subprocess.Popen(
                    self._cmd(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                awk_program = '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0; fflush(); }'
                self.proc = subprocess.Popen(
                    ["gawk", awk_program],
                    stdin=self.proc_ping.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                stream = self.proc.stdout
            else:
                self.proc = subprocess.Popen(
                    self._cmd(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                stream = self.proc.stdout

            try:
                for line in stream:
                    if self.stop_evt.is_set():
                        break
                    # Write the stamped line
                    if self.have_gawk:
                        f.write(line.rstrip() + "\n")
                    else:
                        f.write(f"{ts_br()} {line.rstrip()}\n")
                    f.flush()

                    # Update state machine
                    kind = self._classify(line)
                    now = datetime.now()
                    with self.lock:
                        if kind is True:
                            self.down_active = False
                            self.down_start = None
                        elif kind is False:
                            if not self.down_active:
                                self.down_active = True
                                self.down_start = now
            finally:
                f.write(f"{ts_br()} [STOP  ping {self.ip}]\n"); f.flush()

    def loss_state(self) -> Tuple[bool, float, Optional[datetime]]:
        """Expose (is_down_now, seconds_since_down_started, down_since_timestamp)."""
        with self.lock:
            if self.down_active and self.down_start:
                return True, (datetime.now() - self.down_start).total_seconds(), self.down_start
            return False, 0.0, None

# ------------------------------- Monitor -------------------------------
class NetwatchMTR:
    """Main controller: runs mtr snapshots, manages pingers, and writes CSV/logs."""
    def __init__(self, target: str, extras: List[str]):
        self.target = target
        self.extras = [ip.strip() for ip in extras if ip.strip()]
        self.root = Path(f"netwatch_run_{self.target}_{ts_file()}"); self.root.mkdir(parents=True, exist_ok=True)

        # Files/folders
        self.events_log   = self.root / "mtr_events_lost.log"
        self.flaps_log    = self.root / "mtr_route_flaps.log"
        self.summary_csv  = self.root / "summary.csv"
        self.extras_csv   = self.root / "extras_status.csv"
        self.agg_csv      = self.root / "agg_per_hop.csv"
        self.episodes_csv = self.root / "loss_episodes.csv"
        self.routechg_csv = self.root / "route_changes.csv"
        self.index_md     = self.root / "INDEX.md"
        self.hops_dir     = self.root / "hop_pings";   self.hops_dir.mkdir(exist_ok=True)
        self.extras_dir   = self.root / "extra_pings"; self.extras_dir.mkdir(exist_ok=True)
        self.target_ping_file = self.root / "target_ping.log"

        # Epoch / route-change state
        self.epoch_id = 0
        self.full_log = self._new_epoch_full_log()
        self.pingers: Dict[str, PingThread] = {}
        self.prev_norm_sig: Optional[str] = None
        self.excluded_idxs: set[int] = set()
        self.baseline_set = False
        self.pending_sig: Optional[str] = None
        self.pending_count = 0
        self.last_rotation_at = datetime.min

        # Stateful ping for target
        self.target_pinger = StatefulPingThread(self.target, self.target_ping_file); self.target_pinger.start()
        # Stateful ping for user extras
        self.extra_threads: Dict[str, StatefulPingThread] = {}
        for ip in self.extras:
            th = StatefulPingThread(ip, self.extras_dir / f"{ip}.log")
            th.start()
            self.extra_threads[ip] = th

        # Episode tracking
        self.target_down_prev = False
        self.current_episode_start: Optional[datetime] = None
        self.current_episode_first_fault: Optional[Tuple[int, str, str]] = None
        self.current_episode_route_changes = 0
        self.norm_sig_at_episode_start = ""
        self.norm_sig_at_episode_end   = ""
        self.extras_snapshot_start_up:   List[str] = []
        self.extras_snapshot_start_down: List[str] = []

        # Per-hop aggregates
        self.hop_stats: Dict[str, Dict[str, int]] = {}
        self.first_fault_current_ip: Optional[str] = None
        self.first_fault_active = False
        self.last_agg_flush = time.time()

        # CSV headers
        if not self.summary_csv.exists():
            with self.summary_csv.open("w", encoding="utf-8") as f:
                f.write("timestamp,epoch,target_down,loss_hops_unfiltered,loss_hops_if_target_down,route_changed,route_signature\n")
        if not self.extras_csv.exists():
            with self.extras_csv.open("w", encoding="utf-8") as f:
                cols = ",".join(self.extras)
                f.write("timestamp,target_down" + ("," + cols if cols else "") + "\n")
        if not self.agg_csv.exists():
            with self.agg_csv.open("w", encoding="utf-8") as f:
                f.write("ip,loss_seconds_when_target_down,first_fault_events\n")
        if not self.episodes_csv.exists():
            with self.episodes_csv.open("w", encoding="utf-8") as f:
                f.write("start,end,duration_s,first_fault_idx,first_fault_ip,prev_ip_before_fault,route_changes_in_episode,norm_sig_start,norm_sig_end,extras_up_at_start,extras_down_at_start\n")
        if not self.routechg_csv.exists():
            with self.routechg_csv.open("w", encoding="utf-8") as f:
                f.write("timestamp,epoch_before,epoch_after,old_norm_sig,new_norm_sig\n")
        with self.index_md.open("w", encoding="utf-8") as f:
            f.write(f"# NETWATCH run for {self.target}\n\n- Start: {ts_human()}\n- Folder: {self.root}\n")
            if self.extras: f.write(f"- Extra IPs to ping: {', '.join(self.extras)}\n")

    def _new_epoch_full_log(self) -> Path:
        """Start a new 'epoch' file after a debounced route change."""
        self.epoch_id += 1
        p = self.root / f"mtr_full_epoch_{self.epoch_id}.log"
        with p.open("a", encoding="utf-8") as f:
            f.write(f"{ts_br()} New epoch #{self.epoch_id}\n")
        self.last_rotation_at = datetime.now()
        return p

    def _snapshot_mtr(self) -> Tuple[str, List[Hop]]:
        """Run mtr once (1 probe per hop) and parse the result."""
        try:
            raw = subprocess.check_output(
                ["mtr", "-r", "-w", "-n", "-c", "1", "-i", "1", self.target],
                text=True, stderr=subprocess.STDOUT
            )
        except subprocess.CalledProcessError as e:
            raw = e.output or ""
        return raw, parse_mtr_report(raw)

    def _ensure_hop_pingers(self, hops: List[Hop]) -> None:
        """Start/stop simple pingers for each visible hop IP (except target and '???')."""
        ips_now = [h.host for h in hops if h.host != "???" and h.host != self.target]
        if MAX_HOP_PINGERS > 0:
            ips_now = ips_now[:MAX_HOP_PINGERS]
        # Start new
        for ip in ips_now:
            if ip not in self.pingers:
                th = PingThread(ip, self.hops_dir / f"{ip}.txt")
                th.start()
                self.pingers[ip] = th
        # Stop vanished
        for ip in list(self.pingers.keys()):
            if ip not in ips_now:
                self.pingers[ip].stop()
                self.pingers[ip].join(timeout=2)
                del self.pingers[ip]

    def _update_baseline_exclusions(self, hops: List[Hop]) -> None:
        """During the first snapshot of an epoch, mark '???' indices as baseline exclusions."""
        if self.baseline_set:
            return
        self.excluded_idxs = {h.idx for h in hops if h.host == "???"}
        self.baseline_set = True

    def _maybe_rotate_epoch(self, norm_sig: str) -> bool:
        """
        Debounce route changes: require the new normalized signature to persist for
        ROUTE_CHANGE_STABLE_SNAPSHOTS snapshots and ensure a minimal time since last rotation.
        """
        changed = (self.prev_norm_sig is not None and norm_sig != self.prev_norm_sig)
        if self.prev_norm_sig is None:
            self.prev_norm_sig = norm_sig
            return False
        if not changed:
            self.pending_sig = None
            self.pending_count = 0
            return False
        # Signature changed
        if self.pending_sig != norm_sig:
            self.pending_sig = norm_sig
            self.pending_count = 1
        else:
            self.pending_count += 1
        enough = self.pending_count >= ROUTE_CHANGE_STABLE_SNAPSHOTS
        gap_ok = (datetime.now() - self.last_rotation_at).total_seconds() >= ROTATION_MIN_GAP_SEC
        if enough and gap_ok:
            old = self.prev_norm_sig
            self.prev_norm_sig = norm_sig
            old_epoch = self.epoch_id
            self.full_log = self._new_epoch_full_log()
            with self.routechg_csv.open("a", encoding="utf-8") as f:
                f.write(f"{ts_human()},{old_epoch},{self.epoch_id},\"{old}\",\"{norm_sig}\"\n")
            self.pending_sig = None
            self.pending_count = 0
            return True
        return True

    def _append_summary(self, hops: List[Hop], target_down: bool, route_changed: bool, norm_sig: str) -> None:
        """Per-second CSV snapshot for high-level analysis."""
        loss_unf  = [f"{h.idx}:{h.host}" for h in hops if h.loss > 0.0]
        loss_cond = [f"{h.idx}:{h.host}" for h in hops if h.loss > 0.0 and h.idx not in self.excluded_idxs] if target_down else []
        with self.summary_csv.open("a", encoding="utf-8") as f:
            f.write(",".join([
                ts_human(), str(self.epoch_id), "1" if target_down else "0",
                '"' + ";".join(loss_unf)  + '"',
                '"' + ";".join(loss_cond) + '"',
                "1" if route_changed else "0",
                '"' + norm_sig + '"'
            ]) + "\n")

    def _append_extras_snapshot(self, target_down: bool) -> None:
        """Record per-second UP/DOWN of user extras to correlate local vs remote reachability."""
        if not self.extras:
            return
        states = []
        for ip, th in self.extra_threads.items():
            down, _, _ = th.loss_state()
            states.append(("DOWN" if down else "UP"))
        with self.extras_csv.open("a", encoding="utf-8") as f:
            row = [ts_human(), "1" if target_down else "0"] + states
            f.write(",".join(row) + "\n")

    def _flush_agg_csv(self) -> None:
        """Flush per-hop aggregates: total loss seconds & first-fault counters."""
        if (time.time() - self.last_agg_flush) < AGG_FLUSH_EVERY_SEC:
            return
        self.last_agg_flush = time.time()
        with self.agg_csv.open("w", encoding="utf-8") as f:
            f.write("ip,loss_seconds_when_target_down,first_fault_events\n")
            for ip, st in sorted(self.hop_stats.items()):
                f.write(f"{ip},{st.get('loss_sec',0)},{st.get('first_fault_events',0)}\n")

    def _detect_first_fault(self, hops: List[Hop]) -> Optional[Tuple[int, str, str]]:
        """During a target-down second: pick the lowest-index hop where loss>0 or host=='???' (not excluded)."""
        prev_ip = None
        for h in hops:
            if h.idx in self.excluded_idxs:
                prev_ip = h.host if h.host != "???" else prev_ip
                continue
            problematic = (h.loss > 0.0) or (h.host == "???")
            if problematic:
                return (h.idx, h.host, prev_ip or "")
            prev_ip = h.host if h.host != "???" else prev_ip
        return None

    def _update_per_hop_counters(self, hops: List[Hop], target_down: bool,
                                 first_fault: Optional[Tuple[int, str, str]]) -> None:
        """Update aggregates only while the final target is DOWN."""
        if not target_down:
            self.first_fault_active = False
            self.first_fault_current_ip = None
            return
        for h in hops:
            if h.idx in self.excluded_idxs:
                continue
            if h.loss > 0.0:
                st = self.hop_stats.setdefault(h.host, {"loss_sec": 0, "first_fault_events": 0})
                st["loss_sec"] += 1
        if first_fault:
            _, ip, _ = first_fault
            if ip != self.first_fault_current_ip or not self.first_fault_active:
                st = self.hop_stats.setdefault(ip, {"loss_sec": 0, "first_fault_events": 0})
                st["first_fault_events"] += 1
                self.first_fault_current_ip = ip
                self.first_fault_active = True
        else:
            self.first_fault_active = False
            self.first_fault_current_ip = None

    # ------------------------------ main loop ------------------------------
    def loop(self) -> None:
        while True:
            t0 = time.time()

            # 1) Take an mtr snapshot
            raw, hops = self._snapshot_mtr()
            header = f"===== {ts_human()} target={self.target} =====\n"
            block  = header + raw + "\n"
            sys.stdout.write(block); sys.stdout.flush()
            with self.full_log.open("a", encoding="utf-8") as f:
                f.write(block)

            # 2) Maintain hop pingers and baseline exclusions
            self._ensure_hop_pingers(hops)
            self._update_baseline_exclusions(hops)

            # 3) Route signature / epoch rotation
            norm_sig = normalized_signature(hops, self.excluded_idxs)
            route_changed = self._maybe_rotate_epoch(norm_sig)

            # 4) Target state + "first fault" detection
            target_down, dur, since = self.target_pinger.loss_state()
            first_fault = self._detect_first_fault(hops) if target_down else None

            # Route changed while target was down for a while — note the flap
            if route_changed and target_down and dur > TARGET_LOSS_THRESHOLD_SEC:
                with self.flaps_log.open("a", encoding="utf-8") as f:
                    info = f"since {since.strftime('%H:%M:%S')}" if since else "since n/a"
                    f.write(f"{ts_br()} ROUTE CHANGE while TARGET DOWN >{int(TARGET_LOSS_THRESHOLD_SEC)}s ({info})\n")

            # 5) Loss events: write full block only when loss detected on non-excluded hops
            loss_now = any((h.loss > 0.0) and (h.idx not in self.excluded_idxs) for h in hops)
            if loss_now:
                with self.events_log.open("a", encoding="utf-8") as f:
                    f.write(block)

            # 6) CSV snapshots
            self._append_summary(hops, target_down, route_changed, norm_sig)
            self._append_extras_snapshot(target_down)

            # 7) Aggregates
            self._update_per_hop_counters(hops, target_down, first_fault)

            # 8) Target-down episode tracking
            if target_down and not self.target_down_prev:
                # Opening a new episode
                self.current_episode_start = datetime.now()
                self.current_episode_first_fault = first_fault
                self.current_episode_route_changes = 1 if route_changed else 0
                self.norm_sig_at_episode_start = norm_sig
                ups, downs = [], []
                for ip, th in self.extra_threads.items():
                    d, _, _ = th.loss_state()
                    (downs if d else ups).append(ip)
                self.extras_snapshot_start_up = ups
                self.extras_snapshot_start_down = downs
            elif target_down and self.target_down_prev:
                if route_changed:
                    self.current_episode_route_changes += 1
            elif (not target_down) and self.target_down_prev:
                # Close episode
                end   = datetime.now()
                start = self.current_episode_start or end
                dur_s = int((end - start).total_seconds())
                ff_idx, ff_ip, prev_ip = (-1, "", "")
                if self.current_episode_first_fault:
                    ff_idx, ff_ip, prev_ip = self.current_episode_first_fault
                self.norm_sig_at_episode_end = norm_sig
                with self.episodes_csv.open("a", encoding="utf-8") as f:
                    f.write(",".join([
                        start.strftime("%Y-%m-%d %H:%M:%S"),
                        end.strftime("%Y-%m-%d %H:%M:%S"),
                        str(dur_s), str(ff_idx), f"\"{ff_ip}\"", f"\"{prev_ip}\"",
                        str(self.current_episode_route_changes),
                        f"\"{self.norm_sig_at_episode_start}\"",
                        f"\"{self.norm_sig_at_episode_end}\"",
                        f"\"{';'.join(self.extras_snapshot_start_up)}\"",
                        f"\"{';'.join(self.extras_snapshot_start_down)}\"",
                    ]) + "\n")
                # Reset
                self.current_episode_start = None
                self.current_episode_first_fault = None
                self.current_episode_route_changes = 0
                self.norm_sig_at_episode_start = ""
                self.norm_sig_at_episode_end = ""
                self.extras_snapshot_start_up = []
                self.extras_snapshot_start_down = []

            self.target_down_prev = target_down
            self._flush_agg_csv()

            # 9) Pace to 1 second
            elapsed = time.time() - t0
            if elapsed < SNAPSHOT_PERIOD_SEC:
                time.sleep(max(0.0, SNAPSHOT_PERIOD_SEC - elapsed))

# -------------------------------- Entry --------------------------------
def main() -> None:
    # Ask for target & extras if not provided as CLI args
    if len(sys.argv) >= 2:
        target = sys.argv[1].strip()
    else:
        target = input("Main target to ping (e.g., 8.8.8.8)? ").strip()
    if not target:
        print("Target not provided."); sys.exit(1)

    if len(sys.argv) >= 3:
        extras_csv = sys.argv[2]
    else:
        extras_csv = input("Extra IPs (comma-separated; e.g., 10.0.0.1,203.0.113.10,203.0.113.1,75.75.75.75,75.75.76.76): ").strip()
    extras = [x.strip() for x in (extras_csv.split(",") if extras_csv else []) if x.strip()]

    ensure_mtr_or_reexec_with_sudo(target)

    mon = NetwatchMTR(target, extras)

    def on_sigint(signum, frame):
        print(f"\n{ts_br()} Shutting down...")
        for th in mon.pingers.values():
            th.stop()
        for th in mon.pingers.values():
            th.join(timeout=2)
        for th in mon.extra_threads.values():
            th.stop()
        for th in mon.extra_threads.values():
            th.join(timeout=2)
        if mon.target_pinger:
            mon.target_pinger.stop()
            mon.target_pinger.join(timeout=2)
        mon._flush_agg_csv()
        print(f"{ts_br()} Done. Folder: {mon.root}")
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)
    mon.loop()

if __name__ == "__main__":
    main()
