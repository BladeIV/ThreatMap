"""Send FAKE MikroTik-style syslog lines, to test the map without touching a router.

    python send_test_logs.py                 # to 127.0.0.1:5514, 3 lines/s
    python send_test_logs.py --rate 10

Run the map against a separate port and database so test data never mixes with real data:

    python threatmap.py --port 5514 --db test.db
"""

import argparse
import random
import socket
import time

PORTS = [22, 22, 22, 23, 23, 8291, 8291, 8291, 8728, 80, 443, 3389, 445, 53, 5060, 1723, 7547]
USERS = ["admin", "admin", "root", "user", "support", "mikrotik", "test"]
VIA = ["ssh", "ssh", "winbox", "telnet", "web", "api"]


def random_public_ip() -> str:
    while True:
        a = random.choice([1, 2, 5, 14, 23, 27, 31, 36, 37, 39, 41, 43, 45, 46, 49, 58, 59, 60, 61,
                           77, 78, 80, 81, 82, 85, 91, 92, 93, 94, 95, 101, 103, 104, 106, 109, 110,
                           111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
                           125, 128, 129, 134, 138, 139, 141, 143, 146, 147, 149, 150, 151, 152,
                           154, 156, 157, 159, 161, 162, 164, 165, 167, 170, 171, 175, 176, 177,
                           178, 179, 180, 181, 182, 183, 185, 186, 187, 188, 189, 190, 191, 193,
                           194, 195, 196, 197, 200, 201, 202, 203, 210, 211, 212, 213, 217, 218,
                           219, 220, 221, 222, 223])
        ip = f"{a}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        if not ip.startswith(("203.0.113.", "198.51.100.", "192.0.2.")):
            return ip


def ts() -> str:
    return time.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)


def fw_line(src: str, dport: int, wan="203.0.113.5") -> str:
    proto = "UDP" if dport in (53, 5060, 123) else "TCP"
    flags = " (SYN)" if proto == "TCP" else ""
    return (f"<134>{ts()} TEST-MIK WAN-DROP input: in:ether1 out:(unknown 0), connection-state:new "
            f"src-mac 4c:5e:0c:aa:bb:cc, proto {proto}{flags}, {src}:{random.randint(1024, 65535)}"
            f"->{wan}:{dport}, len 60")


def login_line(src: str, user: str, via: str) -> str:
    return f"<36>{ts()} TEST-MIK system,error,critical login failure for user {user} from {src} via {via}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--rate", type=float, default=3.0, help="lines per second")
    ap.add_argument("--count", type=int, default=0, help="stop after N lines (0 = forever)")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pool = [random_public_ip() for _ in range(40)]   # repeat offenders, like real scanners
    brute = random.choice(pool)
    scanner = random.choice(pool)
    sent = 0
    print(f"sending FAKE test logs to {args.host}:{args.port} (Ctrl+C to stop)")
    while not args.count or sent < args.count:
        r = random.random()
        if r < 0.08:        # brute-force burst from one IP, should raise an alert
            lines = [login_line(brute, random.choice(USERS), "ssh") for _ in range(6)]
        elif r < 0.12:      # port sweep from one IP, should raise an alert
            lines = [fw_line(scanner, p) for p in random.sample(range(1, 10000), 12)]
        elif r < 0.30:
            lines = [login_line(random.choice(pool), random.choice(USERS), random.choice(VIA))]
        else:
            src = random.choice(pool) if random.random() < 0.6 else random_public_ip()
            lines = [fw_line(src, random.choice(PORTS))]
        for line in lines:
            sock.sendto(line.encode(), (args.host, args.port))
            sent += 1
        time.sleep(1 / args.rate)


if __name__ == "__main__":
    main()
