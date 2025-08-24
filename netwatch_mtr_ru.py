#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetWatch MTR (RU)
=================
Трассировка/MTR + отдельные пинги для КАЖДОГО хопа и для “extra” IP
(WAN-IP и WAN-шлюз по умолчанию), с таймстемпами в логах без awk/gawk.
Формируется общий summary.csv, куда попадают все IP: цель, хопы, extra.

Главные изменения:
- Полный отказ от awk/gawk — временные метки проставляет Python.
- По одному файлу лога на IP (в своих папках).
- Итоговая сводка строится по всем логам сразу (раньше у вас попадала только 10.0.0.1).
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

# ----------------------------- Утилиты ------------------------------------ #

TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"


def now_ts() -> str:
    """Текущие дата/время в едином формате для префикса логов."""
    return dt.datetime.now().strftime(TIMESTAMP_FMT)


def ensure_dir(p: Path) -> None:
    """Создать каталог, если его нет."""
    p.mkdir(parents=True, exist_ok=True)


def which(cmd: str) -> Optional[str]:
    """Мини-аналог shutil.which (без лишних импортов)."""
    for d in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(d) / cmd
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def extract_ip(s: str) -> Optional[str]:
    """Вытащить первый IPv4 из строки."""
    m = IP_RE.search(s)
    return m.group(0) if m else None


# ----------------------- WAN и шлюз по умолчанию -------------------------- #

def get_default_gateway() -> Optional[str]:
    """
    Кроссплатформенное определение дефолтного шлюза.
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
    WAN (публичный IP). Сначала пробуем OpenDNS (dig), затем curl -> ipify.
    Если внешние запросы запрещены — вернём None (это ок).
    """
    try:
        out = subprocess.check_output(
            ["sh", "-lc", "command -v dig >/dev/null && dig +short myip.opendns.com @resolver1.opendns.com || true"],
            text=True,
        ).strip()
        if out and IP_RE.fullmatch(out):
            return out
    except Exception:
        pass

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
    Получить список IP хопов до `target` (через mtr, если есть; иначе traceroute).
    Возвращает список IPv4 в порядке следования (без повторов).
    """
    hops: List[str] = []
    seen = set()

    mtr_bin = which("mtr")
    traceroute_bin = which("traceroute")

    if mtr_bin:
        cmd = [mtr_bin, "-n", "-r", "-c", str(mtr_count), "-w", target]
    elif traceroute_bin:
        cmd = [traceroute_bin, "-n", "-q", "1", target]
    else:
        print("В PATH нет ни mtr, ни traceroute. Укажите хопы вручную через --extra.", file=sys.stderr)
        return hops

    try:
        out = subprocess.check_output(cmd, text=True, timeout=timeout, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        out = ""
    except Exception as e:
        print(f"Не удалось выполнить трассировку: {e}", file=sys.stderr)
        out = ""

    for line in out.splitlines():
        ip = extract_ip(line)
        if ip and ip not in seen:
            seen.add(ip)
            hops.append(ip)

    return hops


# ----------------------------- Пинг-потоки -------------------------------- #

def build_ping_cmd(ip: str, interval: float) -> List[str]:
    """
    Собираем команду ping, одинаковую для macOS и Linux (без обратного DNS).
    BSD и GNU ping понимают: `ping -n -i 1 <ip>`
    """
    return ["ping", "-n", "-i", str(interval), ip]


def ping_worker(ip: str, log_dir: Path, interval: float, stop_evt: threading.Event) -> None:
    """
    Запускает непрерывный ping и префиксует КАЖДУЮ строку временной меткой.
    Пишет в файл <log_dir>/<ip>.log
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
            f.write(f"[{now_ts()}] ОШИБКА: ping не найден в PATH\n")
            return
        except Exception as e:
            f.write(f"[{now_ts()}] ОШИБКА запуска ping: {e}\n")
            return

        try:
            while not stop_evt.is_set():
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.rstrip("\n")
                f.write(f"[{now_ts()}] {line}\n")
        finally:
            try:
                if proc.poll() is None:
                    if platform.system().lower().startswith("win"):
                        proc.terminate()
                    else:
                        proc.send_signal(signal.SIGINT)
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
            except Exception:
                pass
            f.write(f"[{now_ts()}] [STOP  ping {ip}]\n")


# ----------------------------- Сбор сводки -------------------------------- #

def parse_ping_line(line: str, ip: str) -> Tuple[bool, Optional[float]]:
    """
    Разбор одной строки пинга (BSD/GNU).
    Возвращает (ok, rtt_ms). ok=True, если есть ответ (bytes from / icmp_seq+time).
    """
    if "bytes from" in line and ip in line:
        m = re.search(r"time[=<]\s*([0-9.]+)\s*ms", line)
        rtt = float(m.group(1)) if m else None
        return True, rtt

    if "Request timeout" in line or "Destination Host Unreachable" in line \
       or "100% packet loss" in line or "Time to live exceeded" in line:
        return False, None

    if f"icmp_seq=" in line and " time=" in line:
        m = re.search(r"time[=<]\s*([0-9.]+)\s*ms", line)
        rtt = float(m.group(1)) if m else None
        return True, rtt

    return False, None


def minute_bucket(ts: str) -> str:
    """Схлопываем точность до минут: из `[YYYY-mm-dd HH:MM:SS]` делаем `[YYYY-mm-dd HH:MM]`."""
    m = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2})", ts)
    return m.group(1) if m else dt.datetime.now().strftime("%Y-%m-%d %H:%M")


def build_summary_csv(all_dirs: List[Path], out_csv: Path) -> None:
    """
    Читает ВСЕ *.log из папок и собирает единую таблицу по минутам.
    1 — был ответ от IP в данную минуту (хотя бы один пакет), 0 — нет.
    Формат: timestamp_minute, <ip1>, <ip2>, ...
    """
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
                        if not raw.startswith("["):
                            continue
                        minute = minute_bucket(raw)
                        ok, _rtt = parse_ping_line(raw, ip)
                        if ok:
                            minute_map[minute] += 1
                            all_minutes.add(minute)
            except Exception:
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


# ----------------------------- Точка входа -------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Трассировка/MTR → отдельные пинги по каждому хопу и extra IP + summary.csv."
    )
    parser.add_argument("target", help="Целевой хост/IP")
    parser.add_argument("--interval", type=float, default=1.0, help="Интервал ping в секундах (по умолчанию 1.0)")
    parser.add_argument("--duration", type=int, default=300, help="Сколько пинговать (сек). Ctrl-C — остановка.")
    parser.add_argument("--mtr-count", type=int, default=15, help="Сколько попыток в mtr/traceroute (по умолчанию 15)")
    parser.add_argument("--log-root", default="logs", help="Корень для логов и сводки (по умолчанию ./logs)")
    parser.add_argument("--no-wan", action="store_true", help="Не добавлять автоматически WAN (публичный IP)")
    parser.add_argument("--no-gw", action="store_true", help="Не добавлять автоматически WAN-шлюз по умолчанию")
    parser.add_argument(
        "--extra",
        default="",
        help="Доп. IP через запятую; каждый получит свой файл лога",
    )

    args = parser.parse_args()
    root = Path(args.log_root)
    hop_dir = root / "hop_pings"
    extra_dir = root / "extra_pings"
    target_dir = root / "target_ping"

    ensure_dir(hop_dir)
    ensure_dir(extra_dir)
    ensure_dir(target_dir)

    # Хопы
    hops = run_path_probe(args.target, mtr_count=args.mtr_count)
    if not hops:
        print("Хопы не обнаружены (mtr/traceroute недоступны). Всё равно пингуем цель/extra.", file=sys.stderr)

    # Дополнительно: шлюз и WAN + то, что передано руками
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

    # Дедуп с сохранением порядка
    seen: set[str] = set()
    extras = [x for x in extras if not (x in seen or seen.add(x))]

    print(f"Цель: {args.target}")
    print(f"Хопы ({len(hops)}): {', '.join(hops) or '-'}")
    print(f"Доп. IP ({len(extras)}): {', '.join(extras) or '-'}")
    print(f"Логи: {root.resolve()}")

    # Запуск потоков
    stop_evt = threading.Event()
    workers: list[threading.Thread] = []

    for ip in hops:
        t = threading.Thread(target=ping_worker, args=(ip, hop_dir, args.interval, stop_evt), daemon=True)
        t.start()
        workers.append(t)

    for ip in extras:
        t = threading.Thread(target=ping_worker, args=(ip, extra_dir, args.interval, stop_evt), daemon=True)
        t.start()
        workers.append(t)

    t = threading.Thread(target=ping_worker, args=(args.target, target_dir, args.interval, stop_evt), daemon=True)
    t.start()
    workers.append(t)

    try:
        if args.duration > 0:
            end = time.time() + args.duration
            while time.time() < end:
                time.sleep(0.2)
        else:
            while True:
                time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nОстанавливаем…")
    finally:
        stop_evt.set()
        for t in workers:
            t.join(timeout=5)

    build_summary_csv([hop_dir, extra_dir, target_dir], root / "summary.csv")
    print(f"Сводка готова: {(root / 'summary.csv').resolve()}")

if __name__ == "__main__":
    main()
