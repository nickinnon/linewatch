#!/usr/bin/env python3
"""
linewatch - a continuous, low-rate connection monitor that records only outages.

Once per second it pings:

    router    your home router (the default gateway)
    hop       the first ISP router past the modem that answers ping
    internet  two anycast addresses (1.1.1.1 and 8.8.8.8 by default)

and classifies each disruption by where it starts.

Event classes (written to events.log / events.csv, each with a raw receipt):
    line      router fine; ISP hop and internet fail together
              -> modem, coax/cable plant, or the ISP access network
    upstream  router and ISP hop fine; every internet target fails
              -> past the first ISP hop
    lan       router and internet fail together -> inside the home network
    wan       router fine, internet fails, and no ISP hop is configured

Counted in the summaries, never raised as events:
    hop-only     only the ISP hop drops pings (routers deprioritize ICMP to themselves)
    router-only  only the home router drops pings (same thing, on your router)
    single       only one internet target fails (that destination, not your line)
    mixed        any other partial combination

A target counts as failed in a round when its reply is lost (no reply within
--timeout) or slower than --stall-ms.

Python 3.8+, standard library only, no admin/root rights. Linux and macOS use an
unprivileged ICMP socket; Windows uses the IcmpSendEcho API.

    linewatch.py [run] [options]        monitor (default command)
    linewatch.py check                  quick test that pinging works on this machine
    linewatch.py compare DIR_A DIR_B    line up events from two homes
"""

import argparse
import csv
import datetime as dt
import ipaddress
import os
import platform
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from collections import Counter, deque

VERSION = "1.1"
WINDOWS = sys.platform == "win32"
LOCK_FILE = "linewatch.lock"
STOP_FILE = "linewatch.stop"
IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
MAGIC = b"LWv1"
EVENT_CLASSES = ("lan", "line", "upstream", "wan")  # tie-break order
NOISE_CLASSES = ("hop-only", "router-only", "single", "mixed")


# --------------------------------------------------------------------------- time

def local_str(t):
    d = dt.datetime.fromtimestamp(t).astimezone()
    return d.strftime("%Y-%m-%d %H:%M:%S.") + "%03d %s" % (d.microsecond // 1000, d.tzname())


def local_iso(t):
    return dt.datetime.fromtimestamp(t).astimezone().isoformat(timespec="milliseconds")


def utc_iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def file_stamp(t):
    return dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d_%H%M%S")


# --------------------------------------------------------------------------- platform helpers

def run_cmd(cmd, timeout=30):
    """Run a command; return its stdout, or '' on any failure. No console window on Windows."""
    kw = {}
    if WINDOWS:
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout, **kw).stdout or ""
    except (subprocess.SubprocessError, OSError):
        return ""


def is_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def lock_file(out_dir):
    """Exclusively lock out_dir/linewatch.lock. Returns the open file, or None if another
    linewatch already holds it."""
    os.makedirs(out_dir, exist_ok=True)
    f = open(os.path.join(out_dir, LOCK_FILE), "a+")
    try:
        if WINDOWS:
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except OSError:
        f.close()
        return None


def unlock_file(f):
    try:
        if WINDOWS:
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    except OSError:
        pass
    f.close()


def is_running(out_dir):
    f = lock_file(out_dir)
    if f is None:
        return True
    unlock_file(f)
    return False


def clock_offset(server="time.cloudflare.com", timeout=3.0):
    """SNTP query. Returns seconds to add to the local clock to match the server, or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            t1 = time.time()
            s.sendto(b"\x23" + bytes(47), (server, 123))
            data, _ = s.recvfrom(48)
            t4 = time.time()
        finally:
            s.close()

        def ntp_time(o):
            sec, frac = struct.unpack("!II", data[o:o + 8])
            return sec - 2208988800 + frac / 2.0 ** 32

        return ((ntp_time(32) - t1) + (ntp_time(40) - t4)) / 2
    except (OSError, struct.error):
        return None


def describe_offset(off):
    if off is None:
        return "offset unknown"
    return "%d ms %s time.cloudflare.com" % (round(abs(off) * 1000), "behind" if off > 0 else "ahead of")


# --------------------------------------------------------------------------- ICMP

def icmp_checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class PingerBase:
    """send(ip, rnd) fires one echo request; wait(timeout) returns [(src_ip, rnd, rtt_ms)]."""

    def probe(self, ip, tries=3, wait=1.5):
        """True if ip answers at least one of `tries` echoes within `wait` seconds."""
        for i in range(tries):
            self.send(ip, (1 << 40) + i)
        end = time.monotonic() + wait
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return False
            if any(src == ip for src, _, _ in self.wait(left)):
                return True


class SocketPinger(PingerBase):
    """Linux and macOS: unprivileged ICMP datagram socket."""

    def __init__(self, token):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        except OSError as e:
            hint = ""
            if sys.platform.startswith("linux"):
                hint = "\nAllow it with: sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'"
            sys.exit("linewatch: cannot open an ICMP socket (%s).%s" % (e, hint))
        self.sock.setblocking(False)
        self.token = token & 0xFFFF  # tells our replies apart from other programs' pings
        self.sent = {}

    def send(self, ip, rnd):
        payload = MAGIC + struct.pack("!HQ", self.token, rnd) + bytes(22)
        pkt = struct.pack("!BBHHH", 8, 0, 0, self.token, rnd & 0xFFFF) + payload
        pkt = pkt[:2] + struct.pack("!H", icmp_checksum(pkt)) + pkt[4:]
        self.sent[(ip, rnd)] = time.monotonic_ns()
        try:
            self.sock.sendto(pkt, (ip, 0))
            return True
        except OSError:
            self.sent.pop((ip, rnd), None)
            return False

    def wait(self, timeout):
        out = []
        try:
            ready, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
        except InterruptedError:
            ready = []
        while ready:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:  # includes BlockingIOError: nothing left to read
                break
            t = time.monotonic_ns()
            if data and data[0] >> 4 == 4:  # macOS includes the IP header
                data = data[(data[0] & 0x0F) * 4:]
            if len(data) < 22 or data[0] != 0 or data[8:12] != MAGIC:
                continue
            token, rnd = struct.unpack("!HQ", data[12:22])
            t0 = self.sent.pop((addr[0], rnd), None) if token == self.token else None
            if t0 is not None:
                out.append((addr[0], rnd, (t - t0) / 1e6))
        if len(self.sent) > 5000:  # forget requests that never got a reply
            cutoff = time.monotonic_ns() - 120 * 10 ** 9
            self.sent = {k: v for k, v in self.sent.items() if v > cutoff}
        return out


class WinPinger(PingerBase):
    """Windows: IcmpSendEcho from iphlpapi.dll (no admin rights). Each request runs in a
    worker thread so several can be in flight at once."""

    def __init__(self, token, timeout_s, workers=64):
        import ctypes
        import queue
        import threading
        self.ctypes, self.queue = ctypes, queue
        lib = ctypes.WinDLL("iphlpapi.dll")
        lib.IcmpCreateFile.restype = ctypes.c_void_p
        lib.IcmpCreateFile.argtypes = []
        lib.IcmpSendEcho.restype = ctypes.c_ulong
        lib.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort,
                                     ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
        self.lib = lib
        self.invalid = ctypes.c_void_p(-1).value
        self.timeout_ms = max(1, int(timeout_s * 1000))
        self.payload = MAGIC + struct.pack("!HQ", token & 0xFFFF, 0) + bytes(22)
        self.jobs = queue.Queue()
        self.results = queue.Queue()
        for _ in range(workers):
            threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        ct = self.ctypes
        handle = self.lib.IcmpCreateFile()
        if not handle or handle == self.invalid:
            return
        req = ct.create_string_buffer(self.payload, len(self.payload))
        reply = ct.create_string_buffer(1024)
        while True:
            ip, rnd = self.jobs.get()
            try:
                addr = struct.unpack("=L", socket.inet_aton(ip))[0]
                t0 = time.monotonic_ns()
                n = self.lib.IcmpSendEcho(handle, addr, req, len(self.payload), None,
                                          reply, len(reply), self.timeout_ms)
                t1 = time.monotonic_ns()
                if n:
                    src, status = struct.unpack_from("=LL", reply.raw, 0)
                    if status == 0 and src == addr:  # 0 = IP_SUCCESS
                        self.results.put((ip, rnd, (t1 - t0) / 1e6))
            except Exception:
                pass

    def send(self, ip, rnd):
        self.jobs.put((ip, rnd))
        return True

    def wait(self, timeout):
        out = []
        try:
            out.append(self.results.get(timeout=max(0.001, timeout)))
        except self.queue.Empty:
            return out
        while True:
            try:
                out.append(self.results.get_nowait())
            except self.queue.Empty:
                return out


def make_pinger(token, timeout_s):
    return WinPinger(token, timeout_s) if WINDOWS else SocketPinger(token)


# --------------------------------------------------------------------------- network discovery

def parse_route_print(text):
    """Windows `route print -4 0.0.0.0`: the gateway of the lowest-metric default route."""
    best = None
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0" and is_ipv4(p[2]):
            metric = int(p[4]) if p[4].isdigit() else 1 << 30
            if best is None or metric < best[0]:
                best = (metric, p[2])
    return best[1] if best else None


def default_gateway():
    if WINDOWS:
        return parse_route_print(run_cmd(["route", "print", "-4", "0.0.0.0"]))
    if os.path.exists("/proc/net/route"):  # Linux
        try:
            best = None
            with open("/proc/net/route") as f:
                for line in list(f)[1:]:
                    p = line.split()
                    flags = int(p[3], 16)
                    if p[1] == "00000000" and flags & 0x1 and flags & 0x2:
                        metric = int(p[6])
                        gw = socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
                        if best is None or metric < best[0]:
                            best = (metric, gw)
            return best[1] if best else None
        except (OSError, ValueError, IndexError):
            return None
    m = re.search(r"gateway:\s*(" + IPV4 + r")\b", run_cmd(["route", "-n", "get", "default"]))  # macOS
    return m.group(1) if m else None


def vpn_warning(gw, target):
    """Linux: warn when traffic to `target` would not leave through the router."""
    if WINDOWS or not shutil.which("ip"):
        return None
    out = run_cmd(["ip", "route", "get", target])
    if out and ("via %s " % gw) not in out:
        return ("WARNING: traffic to %s does not go through the router %s (%s). "
                "A VPN is probably active; results will not describe your line."
                % (target, gw, out.strip().splitlines()[0]))
    return None


def trace(target, maxhops=8):
    if WINDOWS:
        cmd = ["tracert", "-d", "-h", str(maxhops), "-w", "1000", target]
    elif shutil.which("tracepath"):
        cmd = ["tracepath", "-n", "-m", str(maxhops), target]
    elif shutil.which("traceroute"):
        cmd = ["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(maxhops), target]
    else:
        return None
    return run_cmd(cmd, timeout=120) or None


def path_ips(text):
    """Hop addresses, in order, from tracepath / traceroute / tracert output."""
    ips = []
    for line in (text or "").splitlines():
        if not re.match(r"\s*\d+\??:?\s", line):
            continue
        found = [x for x in re.findall(r"(?<![\d.])" + IPV4 + r"(?![\d.])", line) if is_ipv4(x)]
        if found and found[-1] not in ips:
            ips.append(found[-1])
    return ips


def detect_hop(prober, gw, target):
    """First public router past the gateway that answers ping. Returns (ip or None, trace text)."""
    text = trace(target)
    for ip in path_ips(text):
        if ip in (gw, target) or ipaddress.ip_address(ip).is_private:
            continue
        if prober.probe(ip):
            return ip, text
    return None, text


# --------------------------------------------------------------------------- data

class Target:
    def __init__(self, name, ip, role):
        self.name, self.ip, self.role = name, ip, role


class Round:
    __slots__ = ("n", "t_wall", "t_mono_ns", "rtt", "settle", "cls")

    def __init__(self, n, t_wall, t_mono_ns, names, settle=False):
        self.n = n
        self.t_wall = t_wall
        self.t_mono_ns = t_mono_ns
        self.rtt = {name: None for name in names}  # ms, or None = lost
        self.settle = settle
        self.cls = None


def classify(rtt, roles, stall_ms):
    bad = {n: (v is None or v > stall_ms) for n, v in rtt.items()}
    router = [n for n in rtt if roles[n] == "router"]
    hop = [n for n in rtt if roles[n] == "hop"]
    inet = [n for n in rtt if roles[n] == "internet"]
    r_bad = any(bad[n] for n in router)
    h_bad = any(bad[n] for n in hop) if hop else None
    i_all = bool(inet) and all(bad[n] for n in inet)
    i_any = any(bad[n] for n in inet)
    if i_all:
        if r_bad:
            return "lan"
        if h_bad is None:
            return "wan"
        return "line" if h_bad else "upstream"
    if not (r_bad or h_bad or i_any):
        return "ok"
    if r_bad and not h_bad and not i_any:
        return "router-only"
    if h_bad and not r_bad and not i_any:
        return "hop-only"
    if i_any and not r_bad and not h_bad:
        return "single"
    return "mixed"


class Event:
    def __init__(self, core, pre, post, targets, interval, stall_ms):
        self.core, self.pre, self.post = core, pre, post
        self.start = core[0].t_wall
        self.end = core[-1].t_wall + interval
        self.duration = self.end - self.start
        counts = Counter(r.cls for r in core)
        self.class_counts = counts
        ev = {c: counts[c] for c in EVENT_CLASSES if counts[c]}
        self.cls = max(ev, key=lambda c: (ev[c], -EVENT_CLASSES.index(c)))
        names = [t.name for t in targets]
        roles = {t.name: t.role for t in targets}

        def is_bad(r, n):
            v = r.rtt.get(n)
            return v is None or v > stall_ms

        self.per_target = {}
        for n in names:
            vals = [r.rtt[n] for r in core if r.rtt.get(n) is not None]
            self.per_target[n] = {
                "lost": sum(1 for r in core if r.rtt.get(n) is None),
                "slow": sum(1 for v in vals if v > stall_ms),
                "max": max(vals) if vals else None,
            }
        by_role = {}
        for role in ("router", "hop", "internet"):
            members = [n for n in names if roles[n] == role]
            if not members:
                by_role[role] = None
            elif role == "internet":
                by_role[role] = sum(1 for r in core if all(is_bad(r, n) for n in members))
            else:
                by_role[role] = sum(1 for r in core if any(is_bad(r, n) for n in members))
        self.by_role = by_role
        maxes = [v["max"] for v in self.per_target.values() if v["max"] is not None]
        self.max_rtt = max(maxes) if maxes else None


class Detector:
    """Turns finalized rounds into events. Pure logic, no I/O."""

    def __init__(self, targets, interval, stall_ms, quiet_rounds, context_rounds, on_event,
                 on_round=None):
        self.targets = targets
        self.roles = {t.name: t.role for t in targets}
        self.interval = interval
        self.stall_ms = stall_ms
        self.quiet = quiet_rounds
        self.ring = deque(maxlen=context_rounds)
        self.on_event = on_event
        self.on_round = on_round
        self.open = None

    def set_targets(self, targets):
        self.flush()
        self.targets = targets
        self.roles = {t.name: t.role for t in targets}
        self.ring.clear()

    def feed(self, r):
        r.cls = "settle" if r.settle else classify(r.rtt, self.roles, self.stall_ms)
        if self.on_round:
            self.on_round(r)
        if self.open is None:
            if r.cls in EVENT_CLASSES:
                self.open = {"pre": list(self.ring), "rounds": [r], "last_bad": 0, "ok": 0}
            else:
                self.ring.append(r)
            return
        ev = self.open
        ev["rounds"].append(r)
        if r.cls in EVENT_CLASSES:
            ev["ok"] = 0
            ev["last_bad"] = len(ev["rounds"]) - 1
        else:  # ok, settle, and noise rounds all count toward closing the event
            ev["ok"] += 1
            if ev["ok"] >= self.quiet:
                self._close()

    def flush(self):
        if self.open:
            self._close()

    def _close(self):
        ev, self.open = self.open, None
        core = ev["rounds"][: ev["last_bad"] + 1]
        post = ev["rounds"][ev["last_bad"] + 1:]
        self.ring.clear()
        self.ring.extend(ev["rounds"][-(self.ring.maxlen or 1):])
        self.on_event(Event(core, ev["pre"], post, self.targets, self.interval, self.stall_ms))


class Stats:
    """Per-period counters for the summary log (coverage + background noise)."""

    def __init__(self, targets):
        self.reset(targets)

    def reset(self, targets=None):
        if targets is not None:
            self.targets = targets
        self.first = self.last = None
        self.rounds = 0
        self.settle = 0
        self.classes = Counter()
        self.events = Counter()
        self.t = {t.name: {"lost": 0, "slow": 0, "n": 0, "sum": 0.0, "max": 0.0} for t in self.targets}

    def add(self, r, stall_ms):
        if self.first is None:
            self.first = r.t_wall
        self.last = r.t_wall
        if r.cls == "settle":
            self.settle += 1
            return
        self.rounds += 1
        self.classes[r.cls] += 1
        for name, v in r.rtt.items():
            s = self.t.get(name)
            if s is None:
                continue
            if v is None:
                s["lost"] += 1
            else:
                s["n"] += 1
                s["sum"] += v
                s["max"] = max(s["max"], v)
                if v > stall_ms:
                    s["slow"] += 1


# --------------------------------------------------------------------------- output

class Output:
    def __init__(self, out_dir):
        self.dir = os.path.abspath(os.path.expanduser(out_dir))
        os.makedirs(os.path.join(self.dir, "receipts"), exist_ok=True)

    def path(self, name):
        return os.path.join(self.dir, name)

    def append(self, name, text, echo=True):
        with open(self.path(name), "a", encoding="utf-8") as f:
            f.write(text.rstrip("\n") + "\n")
        if echo:
            print(text, flush=True)

    def csv_row(self, name, header, row):
        p = self.path(name)
        new = not os.path.exists(p) or os.path.getsize(p) == 0
        with open(p, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(header)
            w.writerow(row)

    def note(self, text):
        self.append("summary.log", "%s  %s" % (local_str(time.time()), text))


EVENT_HEADER = ["start_epoch", "end_epoch", "start_utc", "start_local", "duration_s", "class",
                "bad_rounds", "router_bad", "hop_bad", "internet_bad", "max_rtt_ms",
                "class_counts", "receipt"]
SUMMARY_HEADER = ["period_start_epoch", "period_end_epoch", "period_start_local", "rounds",
                  "settle_rounds", "router_loss_pct", "hop_loss_pct", "internet_down_pct",
                  "events", "event_classes", "noise", "detail"]


def write_event(out, ev, targets, args):
    receipt = "receipts/%s-%s.txt" % (file_stamp(ev.start), ev.cls)
    names = [t.name for t in targets]
    widths = [max(12, len(n) + 2) for n in names]

    def cell(v):
        return "LOST" if v is None else "%.1f" % v

    lines = [
        "linewatch %s receipt: %s event" % (VERSION, ev.cls.upper()),
        "start     %s   (%s, epoch %.3f)" % (local_iso(ev.start), utc_iso(ev.start), ev.start),
        "end       %s" % local_iso(ev.end),
        "duration  %.1f s over %d rounds; round classes: %s" % (
            ev.duration, len(ev.core), ", ".join("%s %d" % kv for kv in ev.class_counts.most_common())),
        "targets   " + " | ".join("%s %s" % (t.name, t.ip) for t in targets),
        "settings  interval %gs, timeout %gs, a reply slower than %d ms counts as a stall" % (
            args.interval, args.timeout, args.stall_ms),
        "",
        "Columns are round-trip times in ms. '>>' marks rounds inside the event.",
        "",
        "   %-29s %-15s " % ("time (local)", "epoch") + "".join(n.ljust(w) for n, w in zip(names, widths)) + "class",
    ]
    core_ids = {id(r) for r in ev.core}
    for r in ev.pre + ev.core + ev.post:
        mark = ">> " if id(r) in core_ids else "   "
        lines.append(mark + "%-29s %-15.3f " % (local_iso(r.t_wall), r.t_wall)
                     + "".join(cell(r.rtt.get(n)).ljust(w) for n, w in zip(names, widths)) + (r.cls or ""))
    with open(out.path(receipt), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    def frac(role):
        v = ev.by_role.get(role)
        return "-" if v is None else "%d/%d" % (v, len(ev.core))

    out.append("events.log", "%s  %-8s %6.1fs  router %s | hop %s | internet %s bad rounds | max %s  -> %s" % (
        local_str(ev.start), ev.cls.upper(), ev.duration, frac("router"), frac("hop"), frac("internet"),
        "-" if ev.max_rtt is None else "%.0f ms" % ev.max_rtt, receipt))
    out.csv_row("events.csv", EVENT_HEADER, [
        "%.3f" % ev.start, "%.3f" % ev.end, utc_iso(ev.start), local_iso(ev.start), "%.1f" % ev.duration,
        ev.cls, len(ev.core),
        "" if ev.by_role["router"] is None else ev.by_role["router"],
        "" if ev.by_role["hop"] is None else ev.by_role["hop"],
        "" if ev.by_role["internet"] is None else ev.by_role["internet"],
        "" if ev.max_rtt is None else "%.0f" % ev.max_rtt,
        " ".join("%s:%d" % kv for kv in sorted(ev.class_counts.items())), receipt])


def write_summary(out, stats, targets):
    if stats.first is None:
        return
    roles = {t.name: t.role for t in targets}

    def loss_pct(role):
        names = [n for n in stats.t if roles.get(n) == role]
        if not names or not stats.rounds:
            return None
        return max(stats.t[n]["lost"] for n in names) * 100.0 / stats.rounds

    def fmt(v):
        return "-" if v is None else "%.2f%%" % v

    inet_down = stats.classes["line"] + stats.classes["upstream"] + stats.classes["lan"] + stats.classes["wan"]
    inet_pct = inet_down * 100.0 / stats.rounds if stats.rounds else 0.0
    noise = " ".join("%s:%d" % (c, stats.classes[c]) for c in NOISE_CLASSES if stats.classes[c])
    evs = " ".join("%s:%d" % kv for kv in sorted(stats.events.items()))
    detail = " | ".join(
        "%s %d lost %d slow avg %s max %s" % (
            n, s["lost"], s["slow"], "%.1f" % (s["sum"] / s["n"]) if s["n"] else "-",
            "%.0f" % s["max"] if s["n"] else "-")
        for n, s in stats.t.items())
    out.append("summary.log", "%s  SUMMARY %s to %s  rounds %d  loss router %s hop %s  internet-down %.2f%%  events %d%s%s" % (
        local_str(time.time()), local_str(stats.first)[11:19], local_str(stats.last)[11:19], stats.rounds,
        fmt(loss_pct("router")), fmt(loss_pct("hop")), inet_pct, sum(stats.events.values()),
        " (%s)" % evs if evs else "", "  noise " + noise if noise else ""))
    out.csv_row("summary.csv", SUMMARY_HEADER, [
        "%.3f" % stats.first, "%.3f" % stats.last, local_iso(stats.first), stats.rounds, stats.settle,
        "" if loss_pct("router") is None else "%.3f" % loss_pct("router"),
        "" if loss_pct("hop") is None else "%.3f" % loss_pct("hop"),
        "%.3f" % inet_pct, sum(stats.events.values()), evs, noise, detail])


# --------------------------------------------------------------------------- monitor

def build_targets(gw, hop, internet):
    targets = [Target("router", gw, "router")]
    if hop:
        targets.append(Target("hop", hop, "hop"))
    for ip in internet:
        name = {"1.1.1.1": "cloudflare", "1.0.0.1": "cloudflare2", "8.8.8.8": "google",
                "8.8.4.4": "google2", "9.9.9.9": "quad9"}.get(ip, ip)
        targets.append(Target(name, ip, "internet"))
    ips = [t.ip for t in targets]
    if len(set(ips)) != len(ips):
        sys.exit("linewatch: the same address is used for two targets: %s" % ips)
    return targets


def resolve_targets(args, out, prober, gw=None):
    gw = gw or args.router
    waited = False
    while not gw:
        gw = default_gateway()
        if not gw:
            if not waited:
                out.note("waiting for a default gateway (network not up yet)")
                waited = True
            time.sleep(5)
    hop, how = None, "none"
    if args.hop == "auto":
        hop, text = detect_hop(prober, gw, args.internet[0])
        how = "auto" if hop else "auto: none found"
        if text:
            out.append("paths.log", "== %s  path to %s\n%s" % (local_str(time.time()), args.internet[0], text.rstrip()),
                       echo=False)
    elif args.hop != "none":
        hop, how = args.hop, "pinned"
        if not prober.probe(hop):
            out.note("note: hop %s did not answer a test ping; keeping it (it may be busy)" % hop)
    return gw, hop, how


def check():
    """One-shot test: find the router, ping it and 1.1.1.1, report the clock offset."""
    print("linewatch %s on %s, Python %s" % (VERSION, platform.platform(), platform.python_version()))
    pinger = make_pinger(os.getpid(), 3.0)
    gw = default_gateway()
    print("router (default gateway): %s" % (gw or "NOT FOUND"))
    ok = gw is not None
    for name, ip in (("router", gw), ("internet", "1.1.1.1")):
        if ip:
            good = pinger.probe(ip, tries=3, wait=3.0)
            print("ping %-8s %-15s %s" % (name, ip, "ok" if good else "NO REPLY"))
            ok = ok and good
    print("clock: %s" % describe_offset(clock_offset()))
    print("RESULT: %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


def run(args):
    out = Output(args.out)
    lock = lock_file(out.dir)  # held until the process exits
    if lock is None:
        sys.exit("linewatch: already running with log folder %s" % out.dir)
    stop_path = out.path(STOP_FILE)
    if os.path.exists(stop_path):
        os.remove(stop_path)
    prober = make_pinger(os.getpid() ^ 0x5A5A, 2.0)
    pinger = make_pinger(os.getpid(), args.timeout)
    stop = {"flag": False}

    def handle(signum, frame):
        stop["flag"] = True

    for sig in ("SIGTERM", "SIGINT", "SIGHUP", "SIGBREAK"):
        if hasattr(signal, sig):
            try:
                signal.signal(getattr(signal, sig), handle)
            except (OSError, ValueError):
                pass

    gw, hop, how = resolve_targets(args, out, prober)
    targets = build_targets(gw, hop, args.internet)
    out.note("linewatch %s started on %s | %s | hop: %s | interval %gs timeout %gs stall %dms | clock: %s"
             % (VERSION, platform.system(), ", ".join("%s %s" % (t.name, t.ip) for t in targets), how,
                args.interval, args.timeout, args.stall_ms, describe_offset(clock_offset())))
    warn = vpn_warning(gw, args.internet[0])
    if warn:
        out.note(warn)

    stats = Stats(targets)
    by_ip = {t.ip: t.name for t in targets}

    def on_event(ev):
        stats.events[ev.cls] += 1
        write_event(out, ev, detector.targets, args)

    detector = Detector(targets, args.interval, args.stall_ms, args.quiet, args.context, on_event,
                        on_round=lambda r: stats.add(r, args.stall_ms))

    def next_boundary(t):
        return (int(t // args.summary_every) + 1) * args.summary_every

    pending = {}
    rnd = 0
    mono0 = time.monotonic()
    next_tick = mono0
    last_wall, last_mono = time.time(), mono0
    settle_until = mono0 + args.settle
    boundary = next_boundary(time.time())
    next_gw_check = mono0 + 60

    while not stop["flag"]:
        now = time.monotonic()
        if now >= next_tick:
            if os.path.exists(stop_path):
                out.note("stop requested (%s)" % STOP_FILE)
                os.remove(stop_path)
                break
            wall = time.time()
            jump = (wall - last_wall) - (now - last_mono)
            late = now - next_tick
            if jump > 3 or late > 5 * args.interval:
                out.note("paused about %.0fs (sleep or scheduling stall); in-flight pings discarded"
                         % max(jump, late))
                pending.clear()
                detector.flush()
                settle_until = now + args.settle
                next_tick = now
            last_wall, last_mono = wall, now

            if now >= next_gw_check and not args.router:
                next_gw_check = now + 60
                new_gw = default_gateway()
                if new_gw and new_gw != gw:
                    out.note("default gateway changed %s -> %s; re-detecting targets" % (gw, new_gw))
                    pending.clear()
                    gw, hop, how = resolve_targets(args, out, prober, gw=new_gw)
                    write_summary(out, stats, targets)
                    targets = build_targets(gw, hop, args.internet)
                    by_ip = {t.ip: t.name for t in targets}
                    detector.set_targets(targets)
                    stats.reset(targets)
                    settle_until = time.monotonic() + args.settle
                    out.note("targets now %s (hop: %s)" % (", ".join("%s %s" % (t.name, t.ip) for t in targets), how))
                    next_tick = time.monotonic()
                    continue

            if wall >= boundary:
                write_summary(out, stats, targets)
                stats.reset()
                boundary = next_boundary(wall)

            rnd += 1
            r = Round(rnd, wall, time.monotonic_ns(), [t.name for t in targets], settle=now < settle_until)
            for t in targets:
                pinger.send(t.ip, rnd)
            pending[rnd] = r
            next_tick += args.interval

        for src, n, rtt in pinger.wait(max(0.0, min(next_tick - time.monotonic(), 0.5))):
            r = pending.get(n)
            name = by_ip.get(src)
            if r is not None and name in r.rtt and r.rtt[name] is None:
                r.rtt[name] = rtt

        cutoff = time.monotonic_ns() - int(args.timeout * 1e9)
        while pending:
            n = min(pending)
            if pending[n].t_mono_ns > cutoff:
                break
            detector.feed(pending.pop(n))

    detector.flush()
    write_summary(out, stats, targets)
    out.note("linewatch stopped (pings from the last %gs were still in flight and are not counted)" % args.timeout)
    unlock_file(lock)


# --------------------------------------------------------------------------- compare

def load_events(d):
    p = os.path.join(d, "events.csv")
    if not os.path.exists(p):
        sys.exit("compare: no events.csv in %s" % d)
    with open(p, newline="", encoding="utf-8") as f:
        return [{"start": float(r["start_epoch"]), "end": float(r["end_epoch"]), "cls": r["class"],
                 "dur": r["duration_s"]} for r in csv.DictReader(f)]


def load_coverage(d):
    p = os.path.join(d, "summary.csv")
    if not os.path.exists(p):
        return []
    with open(p, newline="", encoding="utf-8") as f:
        return [(float(r["period_start_epoch"]), float(r["period_end_epoch"]))
                for r in csv.DictReader(f) if int(r["rounds"] or 0) + int(r["settle_rounds"] or 0) > 0]


def compare(args):
    a, b = args.dir_a, args.dir_b
    data = {a: (load_events(a), load_coverage(a)), b: (load_events(b), load_coverage(b))}
    w = args.window

    def covered(cov, t):
        return any(s - w <= t <= e + w for s, e in cov)

    for me, other in ((a, b), (b, a)):
        evs, _ = data[me]
        oevs, ocov = data[other]
        if args.cls:
            evs = [e for e in evs if e["cls"] in args.cls]
            oevs = [e for e in oevs if e["cls"] in args.cls]
        matched = 0
        print("\nEvents in %s (%d), checked against %s:" % (me, len(evs), other))
        for e in evs:
            hits = [o for o in oevs if o["start"] - w <= e["end"] and o["end"] + w >= e["start"]]
            if hits:
                matched += 1
                o = hits[0]
                verdict = "MATCH    other: %s %ss, starts %+.1fs" % (o["cls"], o["dur"], o["start"] - e["start"])
            elif covered(ocov, e["start"]):
                verdict = "no match (other was monitoring)"
            else:
                verdict = "unknown  (other was not monitoring)"
            print("  %s  %-8s %6ss  %s" % (local_str(e["start"]), e["cls"], e["dur"], verdict))
        print("  -> %d of %d matched within +/-%gs" % (matched, len(evs), w))
    print("\nCoverage comes from summary.csv, which is written every --summary-every seconds,"
          "\nso the most recent few minutes of a running monitor may not count yet.")


# --------------------------------------------------------------------------- CLI

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "compare":
        p = argparse.ArgumentParser(prog="linewatch.py compare",
                                    description="Line up events recorded in two homes.")
        p.add_argument("dir_a")
        p.add_argument("dir_b")
        p.add_argument("--window", type=float, default=5.0,
                       help="seconds of slack when matching events (default 5)")
        p.add_argument("--class", dest="cls", action="append",
                       help="only compare this event class (repeatable), e.g. --class line")
        compare(p.parse_args(argv[1:]))
        return
    if argv and argv[0] == "check":
        sys.exit(check())
    if argv and argv[0] == "run":
        argv = argv[1:]
    p = argparse.ArgumentParser(prog="linewatch.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version="linewatch " + VERSION)
    p.add_argument("--out", default="~/linewatch-logs", help="log directory (default ~/linewatch-logs)")
    p.add_argument("--hop", default="auto",
                   help="ISP hop to ping: an IP, 'auto' (first public hop that answers), or 'none'")
    p.add_argument("--router", help="router IP (default: the default gateway, re-checked every minute)")
    p.add_argument("--internet", default="1.1.1.1,8.8.8.8",
                   help="comma-separated internet targets (default 1.1.1.1,8.8.8.8)")
    p.add_argument("--interval", type=float, default=1.0, help="seconds between rounds (default 1)")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="seconds to wait for a reply before calling it lost (default 10)")
    p.add_argument("--stall-ms", type=int, default=1000,
                   help="a reply slower than this counts as a failure (default 1000)")
    p.add_argument("--quiet", type=int, default=30,
                   help="clean rounds needed to close an event; closer events merge (default 30)")
    p.add_argument("--context", type=int, default=60,
                   help="rounds of lead-in kept in each receipt (default 60)")
    p.add_argument("--summary-every", type=int, default=900,
                   help="seconds between summary lines (default 900)")
    p.add_argument("--settle", type=float, default=30.0,
                   help="seconds to ignore after start, resume, or a network change (default 30)")
    args = p.parse_args(argv)
    args.internet = [x.strip() for x in args.internet.split(",") if x.strip()]
    if not args.internet:
        p.error("--internet needs at least one address")
    for ip in args.internet + ([args.router] if args.router else []) + \
            ([args.hop] if args.hop not in ("auto", "none") else []):
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            p.error("not an IPv4 address: %s" % ip)
    run(args)


if __name__ == "__main__":
    main()
