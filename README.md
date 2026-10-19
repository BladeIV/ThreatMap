# MikroTik Threat Map

A live terminal map of real attacks hitting **your** MikroTik routers, built from their syslog.
Every arc is a real dropped packet or failed login: origin located offline with GeoIP, stored in
SQLite, with two starter SIEM detections (brute force, port scan).

```
MikroTiks --syslog UDP--> threatmap.py --> parse --> GeoIP + ASN --> SQLite + map + alerts
```

## Files

| File | What it does |
|---|---|
| `threatmap.py` | The terminal UI (and `--headless` mode) |
| `collector.py` | Syslog listener, MikroTik parser, GeoIP, SQLite store, stats, detections |
| `landmask.py` | Embedded world outline for the map (generated, no download needed) |
| `send_test_logs.py` | Sends **fake** MikroTik-style lines, for testing without a router |
| `config.example.json` | Copy to `config.json` and edit |

## 1. Install

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Get a GeoIP database (free, offline)

Put the `.mmdb` files in a `geoip` folder next to the scripts. Either:

- **DB-IP Lite** (no account): download "IP to City Lite" and "IP to ASN Lite" in MMDB format from
  db-ip.com, unzip the `.gz` files into `geoip/`
- **MaxMind GeoLite2** (free account): `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` into `geoip/`

The app finds files by name: anything with `city` (or `country`) and anything with `asn`.
Update them monthly; IP allocations change.

## 3. Configure

Copy `config.example.json` to `config.json`. Under `routers`, key each Mik by the IP its syslog
arrives **from** (or its syslog hostname / identity) and give it a name and lat/lon so arcs land in
the right place. Routers not listed use `default_location`.

- A key can be an IP, a DNS name (such as a MikroTik IP Cloud `*.sn.mynetname.net` address,
  re-resolved every 5 minutes so dynamic IPs keep working) or the router's syslog hostname.
- `addresses` lists any other IPs the router's logs may arrive from, such as its VPN tunnel IP.
- `"only_known_routers": true` drops lines from any other source address. Turn this on whenever
  syslog can arrive from the internet, so nobody can feed fake attacks into your map. It matches
  on the packet's real source address, not the hostname inside the line (which anyone can fake).
  Run with `--headless --raw` to see rejected lines marked `[REJECTED ...]`.

## 4. Point the MikroTiks at it (RouterOS v7)

Replace `192.168.88.10` with the IP of the machine running `threatmap.py`:

```
/system logging action add name=siem target=remote remote=192.168.88.10 remote-port=514 bsd-syslog=yes syslog-facility=local0
/system logging add topics=firewall action=siem
/system logging add topics=system,account action=siem
```

Make your existing WAN drop rule log. **Edit the rule you already have instead of adding a new
one**, since a new drop rule in the wrong position can lock you out:

```
/ip firewall filter print where chain=input action=drop
/ip firewall filter set [find where chain=input action=drop in-interface-list=WAN] log=yes log-prefix="WAN-DROP"
```

Do the same for your `forward` drop rule if you want attacks aimed at devices behind the router.
Don't log accepted traffic; the volume will drown the useful lines.

## 5. Run

```
python threatmap.py
```

Keys: `q` quit, `p` pause, `c` clear arcs.

Windows will ask to allow Python through the firewall the first time: allow it on **private**
networks only. If port 514 is taken, use `--port 5514` and set `remote-port=5514` on the Miks.

To run it as a background service without the UI:

```
python threatmap.py --headless
```

## Testing without a router

The test sender produces **fake** data, so keep it on its own port and database:

```
python threatmap.py --port 5514 --db test.db
python send_test_logs.py
```

Delete `test.db` afterwards.

## What gets recognised

| Log line | Shown as |
|---|---|
| `WAN-DROP input: in:ether1 ... proto TCP (SYN), 1.2.3.4:5555->203.0.113.5:8291, len 60` | FW drop, Winbox |
| `login failure for user admin from 1.2.3.4 via ssh` | Login fail, SSH |

Other lines (DHCP, interface up/down, etc.) are counted as non-attack lines and ignored.

## Detections

- **Brute force**: 5 or more failed logins from one IP within 60 seconds
- **Port scan**: 10 or more different ports from one IP within 60 seconds

Each alert fires at most once per IP every 5 minutes. Thresholds are at the top of `Detector` in
`collector.py`.

## Querying the history

Everything is in `events.db` (SQLite):

```sql
SELECT country, COUNT(*) FROM events GROUP BY country ORDER BY 2 DESC;
SELECT src, org, COUNT(*) FROM events WHERE kind='login' GROUP BY src ORDER BY 3 DESC LIMIT 20;
```

## Things to know

- **The location is where the IP is hosted, not where the person is.** Most attacks come from
  VPS, cloud providers and compromised machines.
- **Syslog over UDP is unencrypted and can drop packets.** Fine on your LAN; for remote Miks, send
  it over a VPN (WireGuard on RouterOS v7) rather than across the internet.
- Seeing lots of Winbox (8291) and SSH hits is normal. Make sure those services are restricted to
  trusted addresses under `/ip service`.
