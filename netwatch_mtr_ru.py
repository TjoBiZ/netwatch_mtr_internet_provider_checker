#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NETWATCH MTR — монитор маршрута и потерь (Linux/macOS) с учётом аксиомы:
потери на промежуточных хопах считаются только во время недоступности ЦЕЛИ.

Что делает:
- Каждую ~1 сек запускает `mtr -r -w -n -c 1 -i 1 <target>`:
  выводит таблицу в консоль и в файл полного лога текущей «эпохи».
- Ведёт отдельные файлы в рабочей папке запуска netwatch_run_<target>_<TS>/:
  * mtr_full_epoch_<N>.log       — полный MTR за эпоху (ротация по смене маршрута с дебаунсом).
  * mtr_events_lost.log          — только периоды потерь (ежесекундные блоки) + "OK interval".
  * mtr_route_flaps.log          — смены маршрута, которые совпадают с падением цели >2с.
  * target_ping.log              — непрерывный системный ping до ЦЕЛИ (с таймштампами).
  * hop_pings/<IP>.txt           — непрерывные ping по IP-хопам (кроме '???' и цели).
  * summary.csv                  — секундная сводка (loss/route_changed/signature).
  * agg_per_hop.csv              — агрегат по IP-хопам (учёт только когда цель DOWN).
  * loss_episodes.csv            — эпизоды падения цели с деталями.
  * route_changes.csv            — CSV-журнал смен маршрута (нормализованные сигнатуры).
  * INDEX.md                     — индекс.

Ключевые правила:
- Базовые '???' индексы (из 1-го снимка эпохи) исключаются из детекции потерь и решений о ротации.
- Ротация эпох: новая нормализованная сигнатура должна держаться ≥3 снимка подряд
  И прошло ≥60с с предыдущей ротации.
- Потери на хопах учитываются ТОЛЬКО когда цель не отвечает (аксиома).
- В момент смены маршрута фиксируется корреляция с падением цели >2с (лог flaps), а также строка в route_changes.csv.
- Все подпроцессы останавливаются корректно по Ctrl+C.

Зависимости: системные `mtr`, `ping`; опционально `gawk`. Внешние пакеты Python не используются.
"""

from __future__ import annotations

import os
import re
import sys
import time
import signal
import shutil
import threading
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------- НАСТРОЙКИ ----------------------------

SNAPSHOT_PERIOD_SEC = 1.0                 # период снимков mtr
ROUTE_CHANGE_STABLE_SNAPSHOTS = 3         # новая сигнатура должна держаться N подряд снимков
ROTATION_MIN_GAP_SEC = 60                 # минимальный интервал между ротациями эпох (сек)
MAX_HOP_PINGERS = 32                      # лимит параллельных ping по хопам (0 = без лимита)

FLAP_WINDOW_SEC = 5.0                     # окно после смены маршрута для поиска падения цели
TARGET_LOSS_THRESHOLD_SEC = 2.0           # порог «цель недоступна» для логирования флапа (>N сек)

AGG_FLUSH_EVERY_SEC = 10                  # как часто переписывать agg_per_hop.csv

# ---------------------------- УТИЛИТЫ ----------------------------

def ts_human() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ts_file() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def ts_br() -> str:
    return "[" + ts_human() + "]"

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def on_linux() -> bool:
    return sys.platform.startswith("linux")

def on_macos() -> bool:
    return sys.platform == "darwin"

# ---------------- mtr: проверка и sudo-перезапуск при необходимости ----------------

def try_mtr_once(target: str) -> Tuple[bool, str]:
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
    if not have("mtr"):
        print("Ошибка: 'mtr' не найден в PATH. Установите mtr.")
        sys.exit(1)
    ok, out = try_mtr_once(target)
    if ok:
        return
    need_root = ("mtr-packet" in out or "Operation not permitted" in out
                 or "Permission denied" in out or "not permitted" in out
                 or "raw socket" in out)
    if need_root and os.geteuid() != 0 and have("sudo"):
        print("⚠️  mtr требует привилегий. Перезапускаю скрипт через sudo — введите пароль.")
        os.execvp("sudo", ["sudo", sys.executable, os.path.abspath(__file__), *sys.argv[1:]])
    else:
        print("mtr не стартовал. Вывод:\n" + (out.strip() or "(пусто)"))
        print("Подсказка: macOS — suid для mtr-packet или sudo; Linux — sudo для raw-сокетов.")
        sys.exit(1)

# ----------------------------- ПАРСИНГ MTR -----------------------------

@dataclass
class Hop:
    idx: int
    host: str   # IP или '???'
    loss: float
    snt: int
    last: float
    avg: float
    best: float
    wrst: float
    stdev: float

_MTR_LINE_RE = re.compile(
    r"""^\s*(?P<idx>\d+)\.\|\-\-\s+
        (?P<host>\S+)\s+
        (?P<loss>\d+\.\d)\%\s+
        (?P<snt>\d+)\s+
        (?P<last>[\d\.]+)\s+
        (?P<avg>[\d\.]+)\s+
        (?P<best>[\d\.]+)\s+
        (?P<wrst>[\d\.]+)\s+
        (?P<stdev>[\d\.]+)
    """, re.X
)

def parse_mtr_report(raw: str) -> List[Hop]:
    hops: List[Hop] = []
    for line in raw.splitlines():
        m = _MTR_LINE_RE.match(line)
        if not m:
            continue
        hops.append(Hop(
            idx=int(m.group("idx")),
            host=m.group("host"),
            loss=float(m.group("loss")),
            snt=int(m.group("snt")),
            last=float(m.group("last")),
            avg=float(m.group("avg")),
            best=float(m.group("best")),
            wrst=float(m.group("wrst")),
            stdev=float(m.group("stdev")),
        ))
    return hops

def signature(hops: List[Hop]) -> str:
    return "|".join(f"{h.idx}:{h.host}" for h in hops)

def normalized_signature(hops: List[Hop], excluded_idxs: set[int]) -> str:
    parts=[]
    for h in hops:
        host = "???" if h.idx in excluded_idxs else h.host
        parts.append(f"{h.idx}:{host}")
    return "|".join(parts)

# ----------------------- Потоки ping по хопам и цели -----------------------

class PingThread(threading.Thread):
    """Системный 'ping' в файл <IP>.txt с таймштампами (через gawk, если есть)."""
    def __init__(self, ip: str, outfile: Path):
        super().__init__(daemon=True)
        self.ip = ip
        self.outfile = outfile
        self.proc: Optional[subprocess.Popen] = None
        self.stop_evt = threading.Event()
        self.have_gawk = have("gawk")

    def _cmd(self) -> List[str]:
        if on_linux():
            return ["ping", "-n", "-O", "-i", "1", self.ip]
        else:
            return ["ping", "-n", "-i", "1", self.ip]

    def run(self) -> None:
        self.outfile.parent.mkdir(parents=True, exist_ok=True)
        with self.outfile.open("a", encoding="utf-8") as f:
            f.write(f"{ts_br()} [СТАРТ ping {self.ip}]\n"); f.flush()
            if self.have_gawk:
                ping_cmd = " ".join(self._cmd())
                gawk_cmd = r"""gawk '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0; fflush(); }'"""
                shell_cmd = f"{ping_cmd} | {gawk_cmd}"
                self.proc = subprocess.Popen(
                    ["/bin/bash", "-lc", shell_cmd],
                    stdout=f, stderr=subprocess.STDOUT, text=True, bufsize=1
                )
                while not self.stop_evt.is_set() and self.proc.poll() is None:
                    time.sleep(0.2)
            else:
                self.proc = subprocess.Popen(
                    self._cmd(),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
                )
                for line in self.proc.stdout:
                    if self.stop_evt.is_set():
                        break
                    f.write(f"{ts_br()} {line.rstrip()}\n"); f.flush()
            f.write(f"{ts_br()} [СТОП  ping {self.ip}]\n"); f.flush()

    def stop(self) -> None:
        self.stop_evt.set()
        if self.proc and self.proc.poll() is None:
            try: self.proc.terminate()
            except Exception: pass

class TargetPingThread(threading.Thread):
    """
    Непрерывный ping до цели; пишет строки с таймштампами и отслеживает, активна ли потеря.
    """
    _TS_PREFIX_RE = re.compile(r"^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\]\s*")

    def __init__(self, ip: str, outfile: Path):
        super().__init__(daemon=True)
        self.ip = ip
        self.outfile = outfile
        self.proc: Optional[subprocess.Popen] = None
        self.stop_evt = threading.Event()
        self.have_gawk = have("gawk")
        self.lock = threading.Lock()
        self.loss_active = False
        self.loss_start: Optional[datetime] = None

    def _cmd(self) -> List[str]:
        if on_linux():
            return ["ping", "-n", "-O", "-i", "1", self.ip]
        else:
            return ["ping", "-n", "-i", "1", self.ip]

    def _classify(self, line: str) -> Optional[bool]:
        s = line.strip()
        if not s:
            return None
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
        if self.have_gawk:
            ping_cmd = " ".join(self._cmd())
            gawk_cmd = r"""gawk '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0; fflush(); }'"""
            popen_cmd = ["/bin/bash", "-lc", f"{ping_cmd} | {gawk_cmd}"]
        else:
            popen_cmd = self._cmd()

        with self.outfile.open("a", encoding="utf-8") as f:
            f.write(f"{ts_br()} [СТАРТ ping ЦЕЛИ {self.ip}]\n"); f.flush()
            self.proc = subprocess.Popen(
                popen_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            try:
                for line in self.proc.stdout:
                    if self.stop_evt.is_set():
                        break
                    if self.have_gawk:
                        f.write(line.rstrip() + "\n")
                    else:
                        f.write(f"{ts_br()} {line.rstrip()}\n")
                    f.flush()
                    kind = self._classify(line)
                    now = datetime.now()
                    with self.lock:
                        if kind is True:
                            self.loss_active = False
                            self.loss_start = None
                        elif kind is False:
                            if not self.loss_active:
                                self.loss_active = True
                                self.loss_start = now
            finally:
                f.write(f"{ts_br()} [СТОП  ping ЦЕЛИ {self.ip}]\n"); f.flush()

    def stop(self) -> None:
        self.stop_evt.set()
        if self.proc and self.proc.poll() is None:
            try: self.proc.terminate()
            except Exception: pass

    def loss_state(self) -> Tuple[bool, float, Optional[datetime]]:
        with self.lock:
            if self.loss_active and self.loss_start:
                dur = (datetime.now() - self.loss_start).total_seconds()
                return True, dur, self.loss_start
            return False, 0.0, None

# ------------------------------- МОНИТОР -------------------------------

class NetwatchMTR:
    """
    Один запуск = одна папка netwatch_run_<target>_<TS>/ с файлами:
      - mtr_full_epoch_<N>.log, mtr_events_lost.log, mtr_route_flaps.log,
        target_ping.log, hop_pings/<IP>.txt, summary.csv, agg_per_hop.csv,
        loss_episodes.csv, route_changes.csv, INDEX.md
    """
    def __init__(self, target: str):
        self.target = target
        self.root = Path(f"netwatch_run_{self.target}_{ts_file()}")
        self.root.mkdir(parents=True, exist_ok=True)

        # файлы
        self.events_log = self.root / "mtr_events_lost.log"
        self.flaps_log  = self.root / "mtr_route_flaps.log"
        self.summary_csv= self.root / "summary.csv"
        self.agg_csv    = self.root / "agg_per_hop.csv"
        self.episodes_csv = self.root / "loss_episodes.csv"
        self.routechg_csv  = self.root / "route_changes.csv"
        self.index_md   = self.root / "INDEX.md"
        self.hops_dir   = self.root / "hop_pings"
        self.hops_dir.mkdir(exist_ok=True)
        self.target_ping_file = self.root / "target_ping.log"

        # эпохи
        self.epoch_id = 0
        self.full_log = self._new_epoch_full_log()

        # состояния
        self.pingers: Dict[str, PingThread] = {}
        self.target_pinger: Optional[TargetPingThread] = None

        self.prev_norm_sig: Optional[str] = None
        self.prev_raw_sig: Optional[str] = None

        self.excluded_idxs: set[int] = set()
        self.baseline_set = False

        # дебаунс ротации
        self.pending_sig: Optional[str] = None
        self.pending_count = 0
        self.last_rotation_at = datetime.min

        # loss/OK состояние цели (для эпизодов)
        self.target_down_prev = False
        self.current_episode_start: Optional[datetime] = None
        self.current_episode_first_fault: Optional[Tuple[int,str,str]] = None  # (idx, ip, prev_ip)
        self.current_episode_route_changes = 0
        self.norm_sig_at_episode_start = ""
        self.norm_sig_at_episode_end   = ""

        # агрегация по IP-хопам
        self.hop_stats: Dict[str, Dict[str, int]] = {}  # ip -> counters
        self.first_fault_current_ip: Optional[str] = None
        self.first_fault_active = False
        self.last_agg_flush = time.time()

        # стартуем ping цели
        self.target_pinger = TargetPingThread(self.target, self.target_ping_file)
        self.target_pinger.start()

        # заголовки CSV
        if not self.summary_csv.exists():
            with self.summary_csv.open("w", encoding="utf-8") as f:
                f.write("timestamp,epoch,target_down,loss_hops_unfiltered,loss_hops_if_target_down,route_changed,route_signature\n")
        if not self.agg_csv.exists():
            with self.agg_csv.open("w", encoding="utf-8") as f:
                f.write("ip,loss_seconds_when_target_down,first_fault_events\n")
        if not self.episodes_csv.exists():
            with self.episodes_csv.open("w", encoding="utf-8") as f:
                f.write("start,end,duration_s,first_fault_idx,first_fault_ip,prev_ip_before_fault,route_changes_in_episode,norm_sig_start,norm_sig_end\n")
        if not self.routechg_csv.exists():
            with self.routechg_csv.open("w", encoding="utf-8") as f:
                f.write("timestamp,epoch_before,epoch_after,old_norm_sig,new_norm_sig\n")

        # индекс
        with self.index_md.open("w", encoding="utf-8") as f:
            f.write(f"# NETWATCH запуск для {self.target}\n\n")
            f.write(f"- Старт: {ts_human()}\n")
            f.write(f"- Каталог: {self.root}\n\n")

    # ---------- служебные методы ----------

    def _new_epoch_full_log(self) -> Path:
        self.epoch_id += 1
        p = self.root / f"mtr_full_epoch_{self.epoch_id}.log"
        with p.open("a", encoding="utf-8") as f:
            f.write(f"{ts_br()} Новая эпоха #{self.epoch_id}\n")
        with self.index_md.open("a", encoding="utf-8") as idx:
            idx.write(f"- Эпоха #{self.epoch_id}: `{p.name}` начата в {ts_human()}\n")
        self.last_rotation_at = datetime.now()
        return p

    def _snapshot_mtr(self) -> Tuple[str, List[Hop]]:
        cmd = ["mtr", "-r", "-w", "-n", "-c", "1", "-i", "1", self.target]
        try:
            raw = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raw = e.output or ""
        return raw, parse_mtr_report(raw)

    def _ensure_pingers(self, hops: List[Hop]) -> None:
        ips_now = [h.host for h in hops if h.host != "???" and h.host != self.target]
        if MAX_HOP_PINGERS > 0:
            ips_now = ips_now[:MAX_HOP_PINGERS]
        # старт новых
        for ip in ips_now:
            if ip not in self.pingers:
                th = PingThread(ip, self.hops_dir / f"{ip}.txt")
                th.start()
                self.pingers[ip] = th
        # остановка лишних
        for ip in list(self.pingers.keys()):
            if ip not in ips_now:
                self.pingers[ip].stop()
                self.pingers[ip].join(timeout=2)
                del self.pingers[ip]

    def _update_baseline_exclusions(self, hops: List[Hop]) -> None:
        if self.baseline_set:
            return
        self.excluded_idxs = {h.idx for h in hops if h.host == "???"}
        self.baseline_set = True
        with self.index_md.open("a", encoding="utf-8") as idx:
            if self.excluded_idxs:
                idx.write(f"- Исключены базовые индексы '???': {sorted(self.excluded_idxs)}\n")
            else:
                idx.write(f"- Базовых '???' нет\n")

    def _maybe_rotate_epoch(self, norm_sig: str) -> bool:
        """
        Возвращает True, если была смена нормализованной сигнатуры
        (для записи в summary), вне зависимости от того, произошла ли ротация.
        """
        changed = (self.prev_norm_sig is not None and norm_sig != self.prev_norm_sig)

        if self.prev_norm_sig is None:
            self.prev_norm_sig = norm_sig
            return False

        if not changed:
            self.pending_sig = None
            self.pending_count = 0
            return changed

        # Есть отличие — накапливаем
        if self.pending_sig != norm_sig:
            self.pending_sig = norm_sig
            self.pending_count = 1
        else:
            self.pending_count += 1

        # Условие ротации
        enough = self.pending_count >= ROUTE_CHANGE_STABLE_SNAPSHOTS
        gap_ok = (datetime.now() - self.last_rotation_at).total_seconds() >= ROTATION_MIN_GAP_SEC
        if enough and gap_ok:
            old = self.prev_norm_sig
            self.prev_norm_sig = norm_sig
            # новая эпоха
            old_epoch = self.epoch_id
            self.full_log = self._new_epoch_full_log()
            # CSV про смену маршрута
            with self.routechg_csv.open("a", encoding="utf-8") as f:
                f.write(f"{ts_human()},{old_epoch},{self.epoch_id},\"{old}\",\"{norm_sig}\"\n")
            self.pending_sig = None
            self.pending_count = 0
        return changed

    def _append_summary(self, hops: List[Hop], target_down: bool, route_changed: bool, norm_sig: str) -> None:
        loss_unfiltered = [f"{h.idx}:{h.host}" for h in hops if h.loss > 0.0]
        loss_cond = [f"{h.idx}:{h.host}" for h in hops if h.loss > 0.0 and h.idx not in self.excluded_idxs] if target_down else []
        with self.summary_csv.open("a", encoding="utf-8") as f:
            f.write(",".join([
                ts_human(),
                str(self.epoch_id),
                "1" if target_down else "0",
                '"' + ";".join(loss_unfiltered) + '"',
                '"' + ";".join(loss_cond) + '"',
                "1" if route_changed else "0",
                '"' + norm_sig + '"'
            ]) + "\n")

    def _flush_agg_csv(self) -> None:
        now = time.time()
        if (now - self.last_agg_flush) < AGG_FLUSH_EVERY_SEC:
            return
        self.last_agg_flush = now
        with self.agg_csv.open("w", encoding="utf-8") as f:
            f.write("ip,loss_seconds_when_target_down,first_fault_events\n")
            for ip, stat in sorted(self.hop_stats.items()):
                f.write(f"{ip},{stat.get('loss_sec',0)},{stat.get('first_fault_events',0)}\n")

    # ------------------- эпизоды падения цели и "первый виновник" -------------------

    def _detect_first_fault(self, hops: List[Hop]) -> Optional[Tuple[int,str,str]]:
        """
        Возвращает (idx, ip_or_qmarks, prev_ip) для самого раннего проблемного хопа
        при условии, что индекс не в excluded_idxs.
        Проблемный — либо loss>0, либо host=='???'. prev_ip — IP предшествующего хопа (если есть).
        """
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

    def _update_per_hop_counters(self, hops: List[Hop], target_down: bool, first_fault: Optional[Tuple[int,str,str]]) -> None:
        if not target_down:
            # завершение непрерывности "первого виновника"
            self.first_fault_active = False
            self.first_fault_current_ip = None
            return

        # учёт потерь на хопах только когда цель DOWN
        for h in hops:
            if h.idx in self.excluded_idxs:
                continue
            if h.loss > 0.0:
                st = self.hop_stats.setdefault(h.host, {"loss_sec":0, "first_fault_events":0})
                st["loss_sec"] += 1

        # первый виновник — считаем события (не каждую секунду)
        if first_fault:
            _, ip, _ = first_fault
            if ip != self.first_fault_current_ip or not self.first_fault_active:
                # новое событие
                st = self.hop_stats.setdefault(ip, {"loss_sec":0, "first_fault_events":0})
                st["first_fault_events"] += 1
                self.first_fault_current_ip = ip
                self.first_fault_active = True
        else:
            self.first_fault_active = False
            self.first_fault_current_ip = None

    # ------------------- главный цикл -------------------

    def loop(self) -> None:
        while True:
            t0 = time.time()
            raw, hops = self._snapshot_mtr()
            header = f"===== {ts_human()} target={self.target} =====\n"
            block  = header + raw + "\n"

            # консоль + полный лог эпохи
            sys.stdout.write(block); sys.stdout.flush()
            with self.full_log.open("a", encoding="utf-8") as f:
                f.write(block)

            # пинги по хопам
            self._ensure_pingers(hops)
            # базовые исключения (только один раз на эпоху)
            self._update_baseline_exclusions(hops)

            # нормализованная сигнатура и возможная ротация
            norm_sig = normalized_signature(hops, self.excluded_idxs)
            route_changed = self._maybe_rotate_epoch(norm_sig)

            # состояние цели
            target_down, dur, since = self.target_pinger.loss_state() if self.target_pinger else (False,0.0,None)

            # "первый виновник" для текущего снимка (важно до записи эпизодов)
            first_fault = self._detect_first_fault(hops) if target_down else None

            # события смены маршрута ↔ падение цели >2с: лог flaps
            if route_changed and self.target_pinger and dur > TARGET_LOSS_THRESHOLD_SEC:
                with self.flaps_log.open("a", encoding="utf-8") as f:
                    f.write(f"{ts_br()} ROUTE CHANGE while TARGET DOWN >{int(TARGET_LOSS_THRESHOLD_SEC)}s (since {since.strftime('%H:%M:%S') if since else 'n/a'})\n")

            # events_lost: писать блоки только во время потерь (loss на любом не исключённом хопе)
            loss_now = any((h.loss > 0.0) and (h.idx not in self.excluded_idxs) for h in hops)
            if loss_now:
                with self.events_log.open("a", encoding="utf-8") as f:
                    f.write(block)

            # summary.csv (включая условный список потерь при target_down)
            self._append_summary(hops, target_down, route_changed, norm_sig)

            # учёт по IP-хопам — ТОЛЬКО когда цель DOWN
            self._update_per_hop_counters(hops, target_down, first_fault)

            # учёт эпизодов падения цели
            if target_down and not self.target_down_prev:
                # старт эпизода
                self.current_episode_start = datetime.now()
                self.current_episode_first_fault = first_fault  # может быть None
                self.current_episode_route_changes = 1 if route_changed else 0
                self.norm_sig_at_episode_start = norm_sig
            elif target_down and self.target_down_prev:
                if route_changed:
                    self.current_episode_route_changes += 1
            elif (not target_down) and self.target_down_prev:
                # завершение эпизода
                end = datetime.now()
                start = self.current_episode_start or end
                dur = int((end - start).total_seconds())
                ff_idx, ff_ip, prev_ip = (-1, "", "")
                if self.current_episode_first_fault:
                    ff_idx, ff_ip, prev_ip = self.current_episode_first_fault
                self.norm_sig_at_episode_end = norm_sig
                with self.episodes_csv.open("a", encoding="utf-8") as f:
                    f.write(",".join([
                        start.strftime("%Y-%m-%d %H:%M:%S"),
                        end.strftime("%Y-%m-%d %H:%M:%S"),
                        str(dur),
                        str(ff_idx),
                        f"\"{ff_ip}\"",
                        f"\"{prev_ip}\"",
                        str(self.current_episode_route_changes),
                        f"\"{self.norm_sig_at_episode_start}\"",
                        f"\"{self.norm_sig_at_episode_end}\""
                    ]) + "\n")
                # сброс
                self.current_episode_start = None
                self.current_episode_first_fault = None
                self.current_episode_route_changes = 0
                self.norm_sig_at_episode_start = ""
                self.norm_sig_at_episode_end = ""

            self.target_down_prev = target_down

            # периодически переписываем агрегаты
            self._flush_agg_csv()

            # такт ~1 сек
            elapsed = time.time() - t0
            if elapsed < SNAPSHOT_PERIOD_SEC:
                time.sleep(max(0.0, SNAPSHOT_PERIOD_SEC - elapsed))

# ------------------------------- ВХОД -------------------------------

def main() -> None:
    if len(sys.argv) >= 2:
        target = sys.argv[1].strip()
    else:
        target = input("Куда пингуем (например, 8.8.8.8)? ").strip()
    if not target:
        print("Цель не задана. Выход.")
        sys.exit(1)

    ensure_mtr_or_reexec_with_sudo(target)

    mon = NetwatchMTR(target)

    def on_sigint(signum, frame):
        print(f"\n{ts_br()} Завершение...")
        for th in mon.pingers.values():
            th.stop()
        for th in mon.pingers.values():
            th.join(timeout=2)
        if mon.target_pinger:
            mon.target_pinger.stop()
            mon.target_pinger.join(timeout=2)
        # финальный flush агрегатов
        mon._flush_agg_csv()
        print(f"{ts_br()} Готово. Каталог: {mon.root}")
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)
    mon.loop()

if __name__ == "__main__":
    main()
