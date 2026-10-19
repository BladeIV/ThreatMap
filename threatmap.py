"""MikroTik threat map: live terminal map of attacks hitting your routers, from their syslog.

    python threatmap.py                  # listen on UDP 514, config.json, events.db
    python threatmap.py --port 5514 --db test.db
    python threatmap.py --headless       # no UI, print events (for running as a service)

Keys: q quit, p pause, c clear arcs
"""

from __future__ import annotations

import argparse
import math
import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich.text import Text

import landmask
from collector import Event, Pipeline, load_config

# ---------------------------------------------------------------- palette

BG = "#101114"
LAND = "#3b4150"
DIM = "#6b7280"
FG = "#d1d5db"
BRIGHT = "#f3f4f6"
ACCENT = "#00c8ff"
HEAD = "#ff2d6f"
KIND_COLOR = {"login": "#ff2d6f", "firewall": "#00c8ff"}
ALERT_COLOR = "#ffa000"
KIND_LABEL = {"login": "Login fail", "firewall": "FW drop"}

ARC_GROW = 1.4      # seconds for the arc head to travel source -> router
ARC_LIFE = 5.0      # seconds an arc stays visible
MAX_ARCS = 80


# ---------------------------------------------------------------- map

_MASK = [int(r, 16) for r in landmask.ROWS]
_MASK_W = landmask.WIDTH
_LAT_TOP, _LAT_BOT = landmask.LAT_TOP, landmask.LAT_BOTTOM


def _is_land(lat: float, lon: float) -> bool:
    r = int(_LAT_TOP - lat)
    c = int(lon + 180) % _MASK_W
    if not 0 <= r < len(_MASK):
        return False
    return bool((_MASK[r] >> (_MASK_W - 1 - c)) & 1)


class WorldMap:
    def __init__(self):
        self.size = (0, 0)
        self.base: list[list[bool]] = []

    def resize(self, w: int, h: int) -> None:
        if (w, h) == self.size:
            return
        self.size = (w, h)
        self.base = []
        for y in range(h):
            row = []
            for x in range(w):
                lat, lon = self.unproject(x + 0.5, y + 0.5)
                # sample a few points per cell so thin land survives downscaling
                hits = sum(_is_land(lat + dy, lon + dx)
                           for dy in (-0.6 * self.dlat, 0, 0.6 * self.dlat)
                           for dx in (-0.3 * self.dlon, 0.3 * self.dlon))
                row.append(hits >= 2)
            self.base.append(row)

    @property
    def dlat(self) -> float:
        return (_LAT_TOP - _LAT_BOT) / self.size[1] / 2

    @property
    def dlon(self) -> float:
        return 360 / self.size[0] / 2

    def project(self, lat: float, lon: float) -> tuple[float, float]:
        w, h = self.size
        lat = max(_LAT_BOT, min(_LAT_TOP, lat))
        return (lon + 180) / 360 * w, (_LAT_TOP - lat) / (_LAT_TOP - _LAT_BOT) * h

    def unproject(self, x: float, y: float) -> tuple[float, float]:
        w, h = self.size
        return _LAT_TOP - y / h * (_LAT_TOP - _LAT_BOT), x / w * 360 - 180


@dataclass
class Arc:
    sx: float
    sy: float
    tx: float
    ty: float
    born: float
    color: str

    def points(self, n: int):
        # quadratic bezier bowed upwards, proportional to distance
        mx, my = (self.sx + self.tx) / 2, (self.sy + self.ty) / 2
        dist = math.hypot(self.tx - self.sx, (self.ty - self.sy) * 2)
        cx, cy = mx, my - dist * 0.18
        for i in range(n + 1):
            t = i / n
            x = (1 - t) ** 2 * self.sx + 2 * (1 - t) * t * cx + t ** 2 * self.tx
            y = (1 - t) ** 2 * self.sy + 2 * (1 - t) * t * cy + t ** 2 * self.ty
            yield t, x, y


def render_map(wm: WorldMap, w: int, h: int, arcs: list[Arc], now: float,
               origins: list[tuple[str, float, float, str]],
               targets: dict[str, tuple[float, float]]) -> Text:
    wm.resize(w, h)
    chars = [["·" if wm.base[y][x] else " " for x in range(w)] for y in range(h)]
    styles = [[LAND] * w for _ in range(h)]

    def put(x: float, y: float, ch: str, st: str) -> None:
        xi, yi = int(x), int(y)
        if 0 <= xi < w and 0 <= yi < h:
            chars[yi][xi] = ch
            styles[yi][xi] = st

    for a in arcs:
        age = now - a.born
        progress = min(1.0, age / ARC_GROW)
        fading = age > ARC_LIFE - 1.5
        n = max(4, int(math.hypot(a.tx - a.sx, (a.ty - a.sy) * 2) * 1.2))
        for t, x, y in a.points(n):
            if t > progress:
                break
            st = a.color if not fading else f"{a.color} dim"
            put(x, y, "•" if t > progress - 0.12 else "·", st)
        if progress < 1:
            put(*_bez_at(a, progress), "●", f"bold {a.color}")
        elif age < ARC_GROW + 0.6:
            put(a.tx, a.ty, "✸", f"bold {HEAD}")

    for cc, lat, lon, color in origins:
        x, y = wm.project(lat, lon)
        put(x, y, "●", f"bold {color}")
        for i, ch in enumerate(cc):
            put(x + 1 + i, y, ch, f"bold {color}")

    for name, (lat, lon) in targets.items():
        x, y = wm.project(lat, lon)
        put(x, y, "◎", f"bold {HEAD}")
        for i, ch in enumerate(name[:14]):
            put(x + 2 + i, y, ch, f"bold {HEAD}")

    out = Text()
    for y in range(h):
        row, st_row = chars[y], styles[y]
        run_start = 0
        for x in range(1, w + 1):
            if x == w or st_row[x] != st_row[run_start]:
                out.append("".join(row[run_start:x]), style=st_row[run_start])
                run_start = x
        if y < h - 1:
            out.append("\n")
    return out


def _bez_at(a: Arc, t: float) -> tuple[float, float]:
    for tt, x, y in a.points(40):
        if tt >= t:
            return x, y
    return a.tx, a.ty


# ---------------------------------------------------------------- app state

class App:
    def __init__(self, pipe: Pipeline):
        self.pipe = pipe
        self.wm = WorldMap()
        self.arcs: deque[Arc] = deque(maxlen=MAX_ARCS)
        self.feed: deque[Event] = deque(maxlen=200)
        self.paused = False
        self.running = True
        self.targets: dict[str, tuple[float, float]] = {}
        for r in (pipe.cfg.get("routers") or {}).values():
            if r.get("lat") is not None:
                self.targets[r.get("name", "router")] = (r["lat"], r["lon"])
        dl = pipe.cfg.get("default_location")
        if dl and dl.get("lat") is not None and not self.targets:
            self.targets[dl.get("name", "home")] = (dl["lat"], dl["lon"])
        for ev in pipe.store.since(time.time() - 3600)[-200:]:
            self.feed.appendleft(ev)

    def tick(self) -> None:
        events, _ = self.pipe.drain()
        if self.paused:
            return
        now = time.time()
        for ev in events:
            self.feed.appendleft(ev)
            if ev.lat is not None and ev.t_lat is not None:
                if ev.router not in self.targets:
                    self.targets[ev.router] = (ev.t_lat, ev.t_lon)
                self.arcs.append(_PendingArc(ev, now, KIND_COLOR.get(ev.kind, ACCENT)))
        while self.arcs and now - self.arcs[0].born > ARC_LIFE:
            self.arcs.popleft()


@dataclass
class _PendingArc:
    """Arc stored in lat/lon so it survives terminal resizes."""
    ev: Event
    born: float
    color: str


# ---------------------------------------------------------------- panels

def bar_rows(counter, total: int, n: int, label, color: str, width: int = 12) -> Table:
    t = Table.grid(padding=(0, 1))
    t.add_column(no_wrap=True, width=18, overflow="ellipsis")
    t.add_column(no_wrap=True, width=width)
    t.add_column(justify="right", width=6)
    top = counter.most_common(n)
    if not top:
        t.add_row(Text("waiting for data", style=DIM), "", "")
    for key, count in top:
        share = count / total if total else 0
        filled = max(1, round(share * width))
        bar = Text("█" * filled, style=color) + Text("·" * (width - filled), style=LAND)
        t.add_row(Text(label(key), style=FG), bar, Text(f"{share * 100:.1f}%", style=FG))
    return t


def side_panel(app: App) -> Group:
    s = app.pipe.stats
    total = s.total
    hours = app.pipe.cfg["stats_window_hours"]
    parts = [
        Text.assemble(("YOUR MIKROTIKS · SYSLOG", DIM)),
        Text.assemble((f"Last {hours}h  ", f"bold {HEAD}"), (f"{total:,} attack events", FG)),
        Text(""),
        Text("TOP ATTACK ORIGINS", style=f"bold {BRIGHT}"),
        bar_rows(s.countries, total, 8, lambda cc: s.country_names.get(cc, cc), "#0e8fbf"),
        Text(""),
        Text("TOP SOURCE NETWORKS (ASN)", style=f"bold {BRIGHT}"),
        bar_rows(s.asns, total, 5, lambda a: a, "#0e8fbf"),
        Text(""),
        Text("TARGETED SERVICES", style=f"bold {BRIGHT}"),
        bar_rows(s.services, total, 6, lambda x: x, HEAD),
        Text(""),
        Text("ROUTERS HIT", style=f"bold {BRIGHT}"),
        bar_rows(s.routers, total, 4, lambda x: x, ACCENT),
        Text(""),
        Text("ALERTS", style=f"bold {ALERT_COLOR}"),
    ]
    if not app.pipe.alerts:
        parts.append(Text("none yet", style=DIM))
    for a in list(app.pipe.alerts)[:5]:
        parts.append(Text.assemble((time.strftime("%H:%M:%S ", time.localtime(a.ts)), DIM),
                                   (f"{a.kind} ", f"bold {ALERT_COLOR}"),
                                   (f"{a.src} {a.cc}", FG)))
        parts.append(Text(f"  {a.detail}", style=DIM, overflow="ellipsis", no_wrap=True))
    return Group(*parts)


def feed_table(app: App, rows: int) -> Table:
    t = Table(box=None, padding=(0, 1), expand=True, show_edge=False,
              header_style=DIM, title_justify="left")
    for name, kw in [("TIME", {"width": 8}), ("ROUTER", {"max_width": 14}),
                     ("TYPE", {"width": 10}), ("SERVICE", {"width": 10}),
                     ("SOURCE", {"min_width": 15}), ("ORIGIN", {"ratio": 2}),
                     ("NETWORK", {"ratio": 3}), ("", {"width": 1}), ("TARGET", {"min_width": 15})]:
        t.add_column(name, no_wrap=True, overflow="ellipsis", **kw)
    for i, ev in enumerate(list(app.feed)[:rows]):
        st = BRIGHT if i == 0 else (FG if i < 4 else DIM)
        color = KIND_COLOR.get(ev.kind, ACCENT)
        origin = ", ".join(p for p in (ev.city, ev.country) if p) or "unknown"
        net = f"AS{ev.asn} {ev.org}" if ev.asn else (ev.org or "")
        src = f"{ev.src}" + (f":{ev.sport}" if ev.sport and ev.kind != "firewall" else "")
        target = f"{ev.dst}:{ev.dport}" if ev.dport else (ev.dst or f"user {ev.user}")
        t.add_row(
            Text(time.strftime("%H:%M:%S", time.localtime(ev.ts)), style=DIM),
            Text(ev.router, style=st),
            Text("● " + KIND_LABEL.get(ev.kind, ev.kind), style=f"bold {color}" if i < 4 else color),
            Text(ev.service, style=st),
            Text(src, style=st),
            Text(origin, style=st),
            Text(net, style=DIM),
            Text("→", style=color),
            Text(target, style=f"bold {st}" if i < 4 else st),
        )
    return t


def build(app: App, width: int, height: int):
    now = time.time()
    side_w = 44
    feed_rows = max(4, min(10, height // 4))
    map_h = max(8, height - feed_rows - 5)
    map_w = max(30, width - side_w - 3)

    origins = []
    s = app.pipe.stats
    for cc, _ in s.countries.most_common(6):
        if cc in s.country_pos:
            lat, lon = s.country_pos[cc]
            origins.append((cc, lat, lon, ACCENT))

    app.wm.resize(map_w, map_h)
    arcs = []
    for pa in app.arcs:
        sx, sy = app.wm.project(pa.ev.lat, pa.ev.lon)
        tx, ty = app.wm.project(pa.ev.t_lat, pa.ev.t_lon)
        arcs.append(Arc(sx, sy, tx, ty, pa.born, pa.color))
    world = render_map(app.wm, map_w, map_h, arcs, now, origins, app.targets)

    p = app.pipe
    last = "never" if p.last_event_ts is None else f"{now - p.last_event_ts:.0f}s ago"
    header = Text.assemble(
        ("● ", HEAD), ("THREATMAP ", f"bold {BRIGHT}"), ("MIKROTIK SYSLOG  ", DIM),
        ("● LIVE" if not app.paused else "❚❚ PAUSED", f"bold {ACCENT}" if not app.paused else f"bold {ALERT_COLOR}"),
        (f"   udp/{p.cfg['listen_port']}  ", DIM),
        (f"last event {last}  ", FG),
        (time.strftime("%a %d %b %H:%M:%S"), FG),
    )
    status = Text.assemble(
        ("q", f"bold {HEAD}"), (" quit  ", FG), ("p", f"bold {HEAD}"), (" pause  ", FG),
        ("c", f"bold {HEAD}"), (" clear  ", FG),
        (f"   {p.received:,} lines received · {p.unparsed:,} non-attack lines · "
         f"{p.rejected:,} rejected · {p.geo.status}", DIM),
    )

    map_block: list = [world]
    if not app.targets:
        map_block.append(Text("No router location set: add lat/lon in config.json to draw arcs.",
                              style=ALERT_COLOR))
    if p.geo.city is None:
        map_block.append(Text("No GeoIP database in ./geoip: origins can't be located. See README.",
                              style=ALERT_COLOR))

    layout = Layout()
    layout.split_column(
        Layout(header, size=1),
        Layout(name="body", size=map_h + 1),
        Layout(Text("─" * width, style=LAND), size=1),
        Layout(Group(Text("ATTACKS ON YOUR ROUTERS", style=f"bold {BRIGHT}"), feed_table(app, feed_rows)),
               size=feed_rows + 2),
        Layout(status, size=1),
    )
    layout["body"].split_row(Layout(Group(*map_block), name="map"),
                             Layout(side_panel(app), size=side_w))
    return layout


# ---------------------------------------------------------------- input

def key_reader(app: App) -> None:
    if os.name == "nt":
        import msvcrt
        while app.running:
            if msvcrt.kbhit():
                handle_key(app, msvcrt.getwch())
            time.sleep(0.05)
    else:
        import select, termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while app.running:
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    handle_key(app, sys.stdin.read(1))
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def handle_key(app: App, k: str) -> None:
    k = k.lower()
    if k == "q":
        app.running = False
    elif k == "p":
        app.paused = not app.paused
    elif k == "c":
        app.arcs.clear()


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--port", type=int, help="UDP port to listen on (default from config, 514)")
    ap.add_argument("--db", help="SQLite file to store events in")
    ap.add_argument("--headless", action="store_true", help="no UI, print one line per event")
    ap.add_argument("--raw", action="store_true",
                    help="with --headless, also print every received line as-is (setup check)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.port:
        cfg["listen_port"] = args.port
    if args.db:
        cfg["db"] = args.db

    try:
        pipe = Pipeline(cfg)
    except OSError as e:
        sys.exit(f"Can't listen on udp/{cfg['listen_port']}: {e}\n"
                 "Is another syslog server using it? Try --port 5514 and point the Miks at that.")
    pipe.start()

    if args.headless:
        print(f"listening on udp/{cfg['listen_port']} | {pipe.geo.status}", flush=True)
        if args.raw:
            pipe.on_raw = lambda sender, line: print(f"RAW from {sender}: {line.strip()}", flush=True)
        while True:
            events, alerts = pipe.drain()
            for ev in events:
                where = ", ".join(p for p in (ev.city, ev.country) if p)
                net = f" AS{ev.asn} {ev.org}" if ev.asn else ""
                target = f"{ev.dst}:{ev.dport}" if ev.dport else (ev.dst or f"user {ev.user}")
                print(f"{time.strftime('%H:%M:%S', time.localtime(ev.ts))} {ev.router} "
                      f"{KIND_LABEL.get(ev.kind, ev.kind)} {ev.service} {ev.src} [{where}]{net} "
                      f"-> {target}", flush=True)
            for a in alerts:
                print(f"ALERT {a.kind} {a.src} {a.cc}: {a.detail}", flush=True)
            time.sleep(0.2)

    app = App(pipe)
    console = Console(style=f"on {BG}")
    threading.Thread(target=key_reader, args=(app,), daemon=True).start()
    with Live(console=console, screen=True, auto_refresh=False) as live:
        while app.running:
            app.tick()
            w, h = console.size
            live.update(build(app, w, h), refresh=True)
            time.sleep(0.1)


if __name__ == "__main__":
    main()
