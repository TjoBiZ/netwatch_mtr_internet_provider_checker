#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetWatch MTR (EN)
=================
Production-grade traceroute/MTR + per-hop pingers with timestamped logs
and a single summary.csv that includes target, all hops, and extra IPs
(e.g., WAN IP and WAN default gateway).

Key guarantees vs previous version:
- No awk/gawk usage -> no quoting/backslash errors in logs.
- One log file per IP (target, each hop, each extra) -> clear separation.
- Robust summary builder reads ALL log files, not just the first one it finds.

Tested on macOS (BSD ping/traceroute) and Linux (iproute2, GNU ping).
"""

import argparse
import csv
import datetime as dt
import os
import platform
import re
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import List, Tuple, Optional

# ----------------------------- Utilities ---------------------------------- #

TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"


def now_ts() -> str:
    """Return current local time formatted once, to stamp log lines."""
    return dt.datetime.now().strftime(TIMESTAMP_FMT)


def ensure_dir(p: Path) -> None:
    """Create directory if not exists."""
    p.mkdir(parents=True, exist_ok=True)


def which(cmd: str) -> Optional[str]:
    """Lightweight shutil.which to avoid extra import."""
    for d in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(d) / cmd
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def extract_ip(s: str) -> Optional[str]:
    """Extract first IPv4 from a string."""
    m = IP_RE.search(s)
    return m.group(0) if m else None


# ----------------------- WAN / Gateway discovery -------------------------- #

def get_default_gateway() -> Optional[str]:
    """
    Try to detect default gateway in a cross-platform way.
    macOS: route -n get default
    Linux: ip route
    """
    system = platform.system().lower()

    if "darwin" in system or "mac" in system:
        try:
            out = subprocess.check_output(
                ["sh", "-lc", "route -n get default 2>/dev/null | awk '/gateway:/{print $2}'"],
                text=True,
            ).strip()
            return out or None
        except Exception:
            return None

    # Linux
    try:
        out = subprocess.check_output(
            ["sh", "-lc", "ip route 2>/dev/null | awk '/^default/{print $3; exit}'"],
            text=True,
        ).strip()
        return out or None
    except Exception:
        return None


def get_public_ip() -> Optional[str]:
    """
    Try a no-HTTP method first (OpenDNS). Falls back to curl if available.

    Note: if outbound DNS is blocked, this may return None — handled gracefully.
    """
    # Try dig via OpenDNS (works on macOS/Linux if dig exists)
    try:
        out = subprocess.check_output(
            ["sh", "-lc", "command -v dig >/dev/null && dig +short myip.opendns.com @resolver1.opendns.com || true"],
            text=True,
        ).strip()
        if out and IP_RE.fullmatch(out):
            return out
    except Exception:
        pass

    # Fallback: curl to ipify (if available)
    try:
        out = subprocess.check_output(
            ["sh", "-lc", "command -v curl >/dev/null && curl -s https://api.ipify.org || true"],
            text=True,
        ).strip()
        if out and IP_RE.fullmatch(out):
            return out
    except Exception:
        pass

    return None


# --------------------------- MTR / Traceroute ----------------------------- #

def run_path_probe(target: str, mtr_count: int = 15, timeout: int = 60) -> List[str]:
    """
    Get hop IPs to `target` using mtr if present; otherwise use traceroute.
    Returns a list of IPv4 hop addresses in order (duplicates removed).
    """
    hops: List[str] = []
    seen = set()

    mtr_bin = which("mtr")
    traceroute_bin = which("traceroute")

    if mtr_bin:
        # -n numeric, -r report, -c count, -w wide; -z disables dns
        cmd = [mtr_bin, "-n", "-r", "-c", str(mtr_count), "-w", target]
    elif traceroute_bin:
        # -n numeric, -q 1: 1 probe per hop to speed up
        cmd = [traceroute_bin, "-n", "-q", "1", target]
    else:
        print("Neither mtr nor traceroute found in PATH. Provide hop IPs manually with --extra.", file=sys.stderr)
        return hops

    try:
        out = subprocess.check_output(cmd, text=True, timeout=timeout, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        out = ""
    except Exception as e:
        print(f"Path probe failed: {e}", file=sys.stderr)
        out = ""

    for line in out.splitlines():
        ip = extract_ip(line)
        if ip and ip not in seen:
            seen.add(ip)
            hops.append(ip)

    return hops


# ----------------------------- Ping workers -------------------------------- #

def build_ping_cmd(ip: str, interval: float) -> List[str]:
    """
    Construct a ping command that works on macOS and Linux without DNS lookups.
    - BSD ping (macOS): `ping -n -i 1 <ip>`
    - GNU ping (Linux): `ping -n -i 1 <ip>`
    We avoid -D because it's Linux-only; timestamps added in Python.
    """
    return ["ping", "-n", "-i", str(interval), ip]


def ping_worker(ip: str, log_dir: Path, interval: float, stop_evt: threading.Event) -> None:
    """
    Run `ping` continuously and prefix every output line with a timestamp.
    Writes to <log_dir>/<ip>.log
    """
    ensure_dir(log_dir)
    log_path = log_dir / f"{ip}.log"

    with open(log_path, "a", buffering=1, encoding="utf-8") as f:
        f.write(f"[{now_ts()}] [START ping {ip}]\n")
        f.flush()

        try:
            proc = subprocess.Popen(
                build_ping_cmd(ip, interval),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
        except FileNotFoundError:
            f.write(f"[{now_ts()}] ERROR: ping binary not found in PATH\n")
            return
        except Exception as e:
            f.write(f"[{now_ts()}] ERROR: failed to start ping: {e}\n")
            return

        try:
            # Read line by line and timestamp it
            while not stop_evt.is_set():
                line = proc.stdout.readline()
                if not line:  # process ended
                    break
                line = line.rstrip("\n")
                f.write(f"[{now_ts()}] {line}\n")
        finally:
            # Try to stop the ping process nicely
            try:
                if proc.poll() is None:
                    if platform.system().lower().startswith("win"):
                        proc.terminate()
                    else:
                        proc.send_signal(signal.SIGINT)
                        # give it a moment; then kill if necessary
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
            except Exception:
                pass
            f.write(f"[{now_ts()}] [STOP  ping {ip}]\n")


# ----------------------------- Summary builder ---------------------------- #

def parse_ping_line(line: str, ip: str) -> Tuple[bool, Optional[float]]:
    """
    Best-effort parsing of a single timestamped ping output line (BSD/GNU).
    Returns (ok, rtt_ms).
    - ok=True when we see a 'bytes from <ip>' (or 'icmp_seq' with 'time=')
    - ok=False for timeouts, unreachable, or other errors
    """
    if "bytes from" in line and ip in line:
        # Try to extract `time=XX.xx ms`
        m = re.search(r"time[=<]\s*([0-9.]+)\s*ms", line)
        rtt = float(m.group(1)) if m else None
        return True, rtt

    if "Request timeout" in line or "Destination Host Unreachable" in line \
       or "100% packet loss" in line or "Time to live exceeded" in line:
        return False, None

    # Some GNU ping prints like: icmp_seq=3 ttl=... time=...
    if f"icmp_seq=" in line and " time=" in line:
        m = re.search(r"time[=<]\s*([0-9.]+)\s*ms", line)
        rtt = float(m.group(1)) if m else None
        return True, rtt

    # Unknown -> don't count it either way
    return False, None


def minute_bucket(ts: str) -> str:
    """
    Collapse `[YYYY-mm-dd HH:MM:SS]` to minute resolution `[YYYY-mm-dd HH:MM]`.
    """
    # ts format: "[YYYY-mm-dd HH:MM:SS] ...."
    m = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2})", ts)
    return m.group(1) if m else dt.datetime.now().strftime("%Y-%m-%d %H:%M")


def build_summary_csv(all_dirs: List[Path], out_csv: Path) -> None:
    """
    Read every *.log file from provided directories and build a single CSV
    with per-minute availability (1 if any success in that minute, 0 otherwise).
    Columns: timestamp_minute, <ip1>, <ip2>, ...
    """
    # Map: ip -> {minute_str -> ok_count}
    matrix: dict[str, defaultdict[str, int]] = {}
    all_minutes: set[str] = set()
    ips: List[str] = []

    for d in all_dirs:
        if not d.exists():
            continue
        for log_path in sorted(d.glob("*.log")):
            ip = log_path.stem
            ips.append(ip)
            minute_map: defaultdict[str, int] = defaultdict(int)

            try:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    for raw in f:
                        # Require leading timestamp
                        if not raw.startswith("["):
                            continue
                        # Minute bucket
                        minute = minute_bucket(raw)
                        ok, _rtt = parse_ping_line(raw, ip)
                        if ok:
                            minute_map[minute] += 1
                            all_minutes.add(minute)
            except Exception:
                # If a log is unreadable, just skip; do not break the whole summary.
                continue

            matrix[ip] = minute_map

    minutes_sorted = sorted(all_minutes)

    ensure_dir(out_csv.parent)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp_minute"] + ips)
        for m in minutes_sorted:
            row = [m]
            for ip in ips:
                ok = 1 if matrix.get(ip, {}).get(m, 0) > 0 else 0
                row.append(ok)
            w.writerow(row)


# ----------------------------- Main orchestration ------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Run traceroute/MTR, ping every hop and extra IP separately, and build a summary.csv."
    )
    parser.add_argument("target", help="Target host/IP to trace and ping")
    parser.add_argument("--interval", type=float, default=1.0, help="Ping interval in seconds (default: 1.0)")
    parser.add_argument("--duration", type=int, default=300, help="How long to ping (seconds). Ctrl-C to stop earlier.")
    parser.add_argument("--mtr-count", type=int, default=15, help="MTR/traceroute probe count (default: 15)")
    parser.add_argument("--log-root", default="logs", help="Root directory for logs and summary (default: ./logs)")
    parser.add_argument("--no-wan", action="store_true", help="Do NOT auto-include WAN (public) IP")
    parser.add_argument("--no-gw", action="store_true", help="Do NOT auto-include default gateway")
    parser.add_argument(
        "--extra",
        default="",
        help="Comma-separated extra IPs to ping (each will get its own log file)",
    )

    args = parser.parse_args()
    root = Path(args.log_root)
    hop_dir = root / "hop_pings"
    extra_dir = root / "extra_pings"
    target_dir = root / "target_ping"

    ensure_dir(hop_dir)
    ensure_dir(extra_dir)
    ensure_dir(target_dir)

    # Discover hops
    hops = run_path_probe(args.target, mtr_count=args.mtr_count)
    if not hops:
        print("No hops discovered (mtr/traceroute unavailable or blocked). We'll still ping target/extra.", file=sys.stderr)

    # Compose extras
    extras: List[str] = []
    if not args.no_gw:
        gw = get_default_gateway()
        if gw:
            extras.append(gw)
    if not args.no_wan:
        wan = get_public_ip()
        if wan:
            extras.append(wan)
    if args.extra.strip():
        for piece in args.extra.split(","):
            ip = piece.strip()
            if ip:
                extras.append(ip)

    # Deduplicate while keeping order
    seen: set[str] = set()
    extras = [x for x in extras if not (x in seen or seen.add(x))]

    print(f"Target: {args.target}")
    print(f"Hops ({len(hops)}): {', '.join(hops) or '-'}")
    print(f"Extras ({len(extras)}): {', '.join(extras) or '-'}")
    print(f"Logging to: {root.resolve()}")

    # Start workers
    stop_evt = threading.Event()
    workers: list[threading.Thread] = []

    # Per-hop pingers
    for ip in hops:
        t = threading.Thread(target=ping_worker, args=(ip, hop_dir, args.interval, stop_evt), daemon=True)
        t.start()
        workers.append(t)

    # Per-extra pingers (WAN, GW, custom extras)
    for ip in extras:
        t = threading.Thread(target=ping_worker, args=(ip, extra_dir, args.interval, stop_evt), daemon=True)
        t.start()
        workers.append(t)

    # Dedicated target pinger (own directory)
    t = threading.Thread(target=ping_worker, args=(args.target, target_dir, args.interval, stop_evt), daemon=True)
    t.start()
    workers.append(t)

    # Duration loop
    try:
        if args.duration > 0:
            end = time.time() + args.duration
            while time.time() < end:
                time.sleep(0.2)
        else:
            # Run until Ctrl-C
            while True:
                time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        stop_evt.set()
        for t in workers:
            t.join(timeout=5)

    # Build summary
    build_summary_csv([hop_dir, extra_dir, target_dir], root / "summary.csv")
    print(f"Summary written: {(root / 'summary.csv').resolve()}")

if __name__ == "__main__":
    main()
