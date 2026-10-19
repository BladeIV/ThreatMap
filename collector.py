"""Syslog collection, MikroTik log parsing, GeoIP enrichment, storage and detection.

Everything here is UI-free so it can be tested or reused by a headless service.
"""

from __future__ import annotations

import glob
import ipaddress
import json
import os
import queue
import re
import socket
import sqlite3
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from functools import lru_cache

# ---------------------------------------------------------------- config

DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 514,
    "db": "events.db",
    "geoip_dir": "geoip",
    "stats_window_hours": 24,
    "default_location": None,  # {"name": "Home", "lat": .., "lon": ..}
    # "<ip, DNS name or syslog hostname>": {"name": .., "lat": .., "lon": .., "addresses": [..]}
    # "addresses" lists any other IPs/names the router's syslog may arrive from (e.g. a VPN IP).
    "routers": {},
}

DNS_REFRESH = 300  # seconds between re-resolving router DNS names (dynamic IPs change)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def load_config(path: str = "config.json") -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg


# ---------------------------------------------------------------- parsing

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 500: "IKE", 1433: "MSSQL", 1723: "PPTP", 1900: "SSDP",
    2000: "MT-BTest", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "Postgres",
    5900: "VNC", 6379: "Redis", 7547: "TR-069", 8080: "HTTP-alt",
    8291: "Winbox", 8443: "HTTPS-alt", 8728: "MT-API", 8729: "MT-API-SSL",
    9200: "Elastic", 11211: "Memcached", 27017: "MongoDB",
}

_ADDR = r"(?:\[[0-9a-fA-F:.]+\]|\d{1,3}(?:\.\d{1,3}){3})"
_SYSLOG_HDR = re.compile(
    r"^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d\s(?P<host>\S+)\s)?(?P<msg>.*)$",
    re.S,
)
_FW = re.compile(
    r"(?:(?P<prefix>\S+)\s)?(?P<chain>input|forward|output|prerouting|postrouting|srcnat|dstnat):\s"
    r".*?proto\s(?P<proto>\w+)(?:\s\((?P<flags>[^)]*)\))?,\s"
    rf"(?P<src>{_ADDR})(?::(?P<sport>\d+))?->(?P<dst>{_ADDR})(?::(?P<dport>\d+))?"
)
_LOGIN = re.compile(rf"login failure for user (?P<user>\S+) from (?P<src>{_ADDR}) via (?P<via>\S+)")

LOGIN_SERVICE = {"ssh": "SSH", "telnet": "Telnet", "winbox": "Winbox", "web": "WebFig",
                 "api": "MT-API", "ftp": "FTP"}


@dataclass
class Event:
    ts: float
    router: str
    kind: str          # "firewall" | "login"
    service: str
    proto: str = ""
    src: str = ""
    sport: int | None = None
    dst: str = ""
    dport: int | None = None
    chain: str = ""
    prefix: str = ""
    user: str = ""
    cc: str = ""
    country: str = ""
    city: str = ""
    lat: float | None = None
    lon: float | None = None
    asn: int | None = None
    org: str = ""
    raw: str = ""
    # target (router) location, filled from config, not stored
    t_lat: float | None = field(default=None, repr=False)
    t_lon: float | None = field(default=None, repr=False)


def _strip(addr: str) -> str:
    return addr[1:-1] if addr.startswith("[") else addr


def parse(raw: str, sender: str = "", ts: float | None = None) -> Event | None:
    """Parse one MikroTik syslog line. Returns None for lines that are not attacks."""
    m = _SYSLOG_HDR.match(raw.strip())
    host = (m.group("host") if m else None) or sender
    msg = m.group("msg") if m else raw
    ts = ts if ts is not None else time.time()

    lm = _LOGIN.search(msg)
    if lm:
        via = lm.group("via").lower()
        return Event(ts=ts, router=host, kind="login", service=LOGIN_SERVICE.get(via, via),
                     proto="TCP", src=_strip(lm.group("src")), user=lm.group("user"), raw=raw)

    fm = _FW.search(msg)
    if fm:
        dport = int(fm.group("dport")) if fm.group("dport") else None
        proto = fm.group("proto").upper()
        if dport is not None:
            service = SERVICES.get(dport, f"{proto}/{dport}")
        else:
            service = proto
        return Event(
            ts=ts, router=host, kind="firewall", service=service, proto=proto,
            src=_strip(fm.group("src")),
            sport=int(fm.group("sport")) if fm.group("sport") else None,
            dst=_strip(fm.group("dst")), dport=dport,
            chain=fm.group("chain"), prefix=fm.group("prefix") or "", raw=raw,
        )
    return None


# ---------------------------------------------------------------- geoip

def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class GeoResolver:
    """Offline lookups from local .mmdb files (MaxMind GeoLite2 or DB-IP Lite)."""

    def __init__(self, geoip_dir: str):
        self.city = self.asn = None
        self.city_file = self.asn_file = None
        try:
            import geoip2.database
        except ImportError:
            return
        files = glob.glob(os.path.join(geoip_dir, "*.mmdb"))
        for f in sorted(files):
            name = os.path.basename(f).lower()
            if "asn" in name and self.asn is None:
                self.asn, self.asn_file = geoip2.database.Reader(f), f
            elif ("city" in name or "country" in name) and self.city is None:
                self.city, self.city_file = geoip2.database.Reader(f), f
        self.country_only = bool(self.city) and \
            self.city.metadata().database_type.lower().endswith("country")

    @property
    def status(self) -> str:
        parts = []
        parts.append("geo " + (os.path.basename(self.city_file) if self.city else "MISSING"))
        parts.append("asn " + (os.path.basename(self.asn_file) if self.asn else "missing"))
        return " | ".join(parts)

    @lru_cache(maxsize=100_000)
    def lookup(self, ip: str) -> tuple:
        """-> (cc, country, city, lat, lon, asn, org)"""
        if not is_public(ip):
            return ("--", "Private/LAN", "", None, None, None, "")
        cc = country = city = org = ""
        lat = lon = asn = None
        if self.city is not None:
            try:
                if self.country_only:
                    r = self.city.country(ip)
                else:
                    r = self.city.city(ip)
                    city = r.city.name or ""
                    lat, lon = r.location.latitude, r.location.longitude
                cc = r.country.iso_code or ""
                country = r.country.name or ""
            except Exception:
                pass
        if self.asn is not None:
            try:
                a = self.asn.asn(ip)
                asn, org = a.autonomous_system_number, a.autonomous_system_organization or ""
            except Exception:
                pass
        return (cc or "??", country or "Unknown", city, lat, lon, asn, org)

    def enrich(self, ev: Event) -> Event:
        ev.cc, ev.country, ev.city, ev.lat, ev.lon, ev.asn, ev.org = self.lookup(ev.src)
        return ev


# ---------------------------------------------------------------- storage

_COLS = ["ts", "router", "kind", "service", "proto", "src", "sport", "dst", "dport", "chain",
         "prefix", "user", "cc", "country", "city", "lat", "lon", "asn", "org", "raw"]


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS events (ts REAL, router TEXT, kind TEXT, service TEXT, "
            "proto TEXT, src TEXT, sport INTEGER, dst TEXT, dport INTEGER, chain TEXT, prefix TEXT, "
            "user TEXT, cc TEXT, country TEXT, city TEXT, lat REAL, lon REAL, asn INTEGER, org TEXT, "
            "raw TEXT)")
        self.db.execute("CREATE INDEX IF NOT EXISTS ix_ts ON events(ts)")
        self.db.execute("CREATE INDEX IF NOT EXISTS ix_src ON events(src)")
        self.db.commit()

    def add_many(self, events: list[Event]) -> None:
        if not events:
            return
        rows = [tuple(asdict(e)[c] for c in _COLS) for e in events]
        self.db.executemany(f"INSERT INTO events VALUES ({','.join('?' * len(_COLS))})", rows)
        self.db.commit()

    def since(self, ts: float) -> list[Event]:
        cur = self.db.execute(f"SELECT {','.join(_COLS)} FROM events WHERE ts >= ? ORDER BY ts", (ts,))
        return [Event(**dict(zip(_COLS, row))) for row in cur]


# ---------------------------------------------------------------- stats + detection

class Stats:
    """Rolling counters over the last `window` seconds."""

    def __init__(self, window: float):
        self.window = window
        self.items: deque = deque()
        self.countries, self.asns, self.services, self.routers = Counter(), Counter(), Counter(), Counter()
        self.kinds, self.sources = Counter(), Counter()
        self.country_names: dict[str, str] = {}
        self.country_pos: dict[str, tuple] = {}

    def add(self, ev: Event) -> None:
        asn = f"AS{ev.asn} {ev.org}" if ev.asn else (ev.org or "Unknown")
        keys = (ev.cc, asn, ev.service, ev.router, ev.kind, ev.src)
        self.items.append((ev.ts, keys))
        for c, k in zip(self._counters(), keys):
            c[k] += 1
        self.country_names[ev.cc] = ev.country
        if ev.lat is not None:
            self.country_pos[ev.cc] = (ev.lat, ev.lon)

    def _counters(self):
        return (self.countries, self.asns, self.services, self.routers, self.kinds, self.sources)

    def expire(self, now: float) -> None:
        cutoff = now - self.window
        while self.items and self.items[0][0] < cutoff:
            _, keys = self.items.popleft()
            for c, k in zip(self._counters(), keys):
                c[k] -= 1
                if c[k] <= 0:
                    del c[k]

    @property
    def total(self) -> int:
        return len(self.items)


@dataclass
class Alert:
    ts: float
    kind: str
    src: str
    cc: str
    detail: str


class Detector:
    """Two starter SIEM rules: brute force and port scan, per source IP."""

    BRUTE_COUNT, BRUTE_WINDOW = 5, 60
    SCAN_PORTS, SCAN_WINDOW = 10, 60
    COOLDOWN = 300

    def __init__(self):
        self.logins: dict[str, deque] = defaultdict(deque)
        self.ports: dict[str, deque] = defaultdict(deque)
        self.last_alert: dict[tuple, float] = {}

    def check(self, ev: Event) -> Alert | None:
        now = ev.ts
        if ev.kind == "login":
            q = self.logins[ev.src]
            q.append(now)
            while q and q[0] < now - self.BRUTE_WINDOW:
                q.popleft()
            if len(q) >= self.BRUTE_COUNT:
                return self._fire("Brute force", ev, f"{len(q)} failed {ev.service} logins in "
                                                     f"{self.BRUTE_WINDOW}s (user {ev.user})")
        elif ev.dport is not None:
            q = self.ports[ev.src]
            q.append((now, ev.dport))
            while q and q[0][0] < now - self.SCAN_WINDOW:
                q.popleft()
            distinct = len({p for _, p in q})
            if distinct >= self.SCAN_PORTS:
                return self._fire("Port scan", ev, f"{distinct} ports in {self.SCAN_WINDOW}s")
        return None

    def _fire(self, kind: str, ev: Event, detail: str) -> Alert | None:
        key = (kind, ev.src)
        if ev.ts - self.last_alert.get(key, 0) < self.COOLDOWN:
            return None
        self.last_alert[key] = ev.ts
        return Alert(ev.ts, kind, ev.src, ev.cc, detail)


# ---------------------------------------------------------------- listener

class SyslogListener(threading.Thread):
    """Receives UDP syslog (RouterOS remote logging is UDP only) into a queue."""

    def __init__(self, host: str, port: int, out: queue.Queue):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.out = out

    def run(self) -> None:
        while True:
            try:
                data, (addr, _) = self.sock.recvfrom(8192)
            except OSError:
                continue
            self.out.put((time.time(), addr, data.decode("utf-8", errors="replace")))


class RouterDirectory(threading.Thread):
    """Maps the address a syslog packet came from to a configured router.

    Config keys and "addresses" may be IPs, syslog hostnames or DNS names; DNS names
    (e.g. MikroTik IP Cloud *.sn.mynetname.net) are re-resolved every DNS_REFRESH seconds.
    """

    def __init__(self, routers: dict):
        super().__init__(daemon=True)
        self.static: dict[str, dict] = {}
        self.dns_names: dict[str, dict] = {}
        for key, info in (routers or {}).items():
            for k in [key, *info.get("addresses", [])]:
                self.static[k] = info
                if not _is_ip(k) and "." in k:
                    self.dns_names[k] = info
        self.resolved: dict[str, dict] = {}
        self.resolve()

    def resolve(self) -> None:
        found = {}
        for name, info in self.dns_names.items():
            try:
                for ip in {a[4][0] for a in socket.getaddrinfo(name, None, socket.AF_INET)}:
                    found[ip] = info
            except OSError:
                pass  # keep going; old mapping stays until the next successful refresh
        if found or not self.resolved:
            self.resolved = found

    def run(self) -> None:
        while True:
            time.sleep(DNS_REFRESH)
            self.resolve()

    def known_sender(self, sender: str) -> bool:
        """True only for the packet's real source address (the syslog hostname is spoofable)."""
        return sender in self.static or sender in self.resolved

    def get(self, sender: str, host: str) -> dict | None:
        return self.static.get(sender) or self.resolved.get(sender) or self.static.get(host)


class Pipeline:
    """Ties listener -> parse -> enrich -> store/stats/detect together."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.raw_q: queue.Queue = queue.Queue()
        self.geo = GeoResolver(cfg["geoip_dir"])
        self.store = Store(cfg["db"])
        self.stats = Stats(cfg["stats_window_hours"] * 3600)
        self.detector = Detector()
        self.alerts: deque[Alert] = deque(maxlen=50)
        self.received = self.unparsed = self.rejected = 0
        self.last_event_ts: float | None = None
        self.on_raw = None  # optional callback(sender, line) for every line received
        self.listener = SyslogListener(cfg["listen_host"], cfg["listen_port"], self.raw_q)
        self.routers = RouterDirectory(cfg.get("routers"))
        for ev in self.store.since(time.time() - self.stats.window):
            self.stats.add(ev)

    def start(self) -> None:
        self.listener.start()
        self.routers.start()

    def router_info(self, sender: str, host: str) -> tuple[str, float | None, float | None]:
        info = self.routers.get(sender, host)
        if info is None:
            info = self.cfg.get("default_location") or {}
            name = host or sender
        else:
            name = info.get("name", host or sender)
        return name, info.get("lat"), info.get("lon")

    def drain(self, limit: int = 5000) -> tuple[list[Event], list[Alert]]:
        """Process queued syslog lines. Returns new events and alerts."""
        events, alerts = [], []
        for _ in range(limit):
            try:
                ts, sender, line = self.raw_q.get_nowait()
            except queue.Empty:
                break
            self.received += 1
            if self.cfg.get("only_known_routers") and not self.routers.known_sender(sender):
                self.rejected += 1
                if self.on_raw:
                    self.on_raw(sender, "[REJECTED: not a configured router] " + line)
                continue
            if self.on_raw:
                self.on_raw(sender, line)
            ev = parse(line, sender, ts)
            if ev is None:
                self.unparsed += 1
                continue
            host = ev.router
            ev.router, ev.t_lat, ev.t_lon = self.router_info(sender, host)
            self.geo.enrich(ev)
            events.append(ev)
            self.stats.add(ev)
            a = self.detector.check(ev)
            if a:
                alerts.append(a)
                self.alerts.appendleft(a)
        if events:
            self.store.add_many(events)
            self.last_event_ts = events[-1].ts
        self.stats.expire(time.time())
        return events, alerts
