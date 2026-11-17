#!/usr/bin/env python3
"""Read-only host stats for the ops.chinmoy.site dashboard.

Reports host metrics, per-container/service CPU and memory, a disk breakdown of
$HOME, and a live inventory of containers and services. Needs no root: names and
usage come from /proc, which also covers rootful containers via their conmon.
"""
import hmac
import json
import os
import platform
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BIND = os.environ.get("STATS_BIND", "100.73.232.54")
PORT = int(os.environ.get("STATS_PORT", "3788"))
HOME = str(Path.home())
TOKEN_FILE = Path(os.environ.get("STATS_TOKEN_FILE", Path.home() / ".config/stats-agent/token"))
COMPOSE_FILE = Path(os.environ.get("STATS_COMPOSE", Path.home() / "stack/compose.yml"))
TOKEN = TOKEN_FILE.read_text().strip()
if not TOKEN:
    raise SystemExit(f"empty token file: {TOKEN_FILE}")
EXPECTED = f"Bearer {TOKEN}".encode()

TOP_N = 10
INVENTORY_SEC = 10
DISK_SCAN_SEC = 30 * 60
CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
OWN_UID = os.getuid()
NOISE_UNITS = {"dbus", "ssh-agent", "at-spi-dbus-bus", "gpg-agent", "dirmngr", "keyboxd"}
CID_RE = re.compile(r"libpod(?:-payload)?-([0-9a-f]{64})")
UNIT_RE = re.compile(r"/([^/]+)\.service(?=/|$)")


def cpu_sample():
    with open("/proc/stat") as f:
        parts = [int(x) for x in f.readline().split()[1:]]
    return parts[3] + parts[4], sum(parts)


def mem_info():
    values = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, rest = line.split(":", 1)
            values[key] = int(rest.split()[0]) * 1024
    total = values["MemTotal"]
    available = values.get("MemAvailable", values.get("MemFree", 0))
    used = max(0, total - available)
    return {"total": total, "used": used, "available": available, "pct": round(used / total * 100, 1) if total else 0}


def disk_info(mount="/"):
    s = os.statvfs(mount)
    total = s.f_blocks * s.f_frsize
    used = (s.f_blocks - s.f_bfree) * s.f_frsize
    available = s.f_bavail * s.f_frsize
    denom = used + available
    return {"mount": mount, "total": total, "used": used, "available": available, "pct": round(used / denom * 100, 1) if denom else 0}


def net_sample():
    best = None
    with open("/proc/net/dev") as f:
        for line in f.readlines()[2:]:
            name, rest = line.split(":", 1)
            name = name.strip()
            if name == "lo" or name.startswith(("veth", "br-", "podman", "docker", "tailscale")):
                continue
            parts = rest.split()
            row = {"iface": name, "rx": int(parts[0]), "tx": int(parts[8]), "at": time.monotonic()}
            if name == "eth0" or name.startswith("en"):
                return row
            best = best or row
    return best


def uptime_sec():
    with open("/proc/uptime") as f:
        return float(f.read().split()[0])


def arg_after(args, *flags):
    for i, a in enumerate(args[:-1]):
        if a in flags:
            return args[i + 1]
    return None


def scan_procs():
    """Return (processes, conmons). Processes that exit mid-scan are skipped."""
    procs, conmons = [], []
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        pid = entry.name
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                raw = f.read().decode(errors="replace")
            end = raw.rfind(")")
            comm = raw[raw.find("(") + 1:end]
            fields = raw[end + 2:].split()
            start_ticks = int(fields[19])
            if comm == "conmon":
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    args = f.read().decode(errors="replace").split("\0")
                cid = arg_after(args, "-c", "--cid")
                name = arg_after(args, "-n", "--name")
                if cid and name:
                    conmons.append({"cid": cid, "name": name, "root": entry.stat().st_uid == 0, "start": start_ticks})
            rss = int(fields[21]) * PAGE_SIZE
            ticks = int(fields[11]) + int(fields[12])
            if rss == 0 and ticks == 0:
                continue
            with open(f"/proc/{pid}/cgroup") as f:
                cgroup = f.read()
            procs.append({"pid": pid, "comm": comm, "rss": rss, "ticks": ticks, "start": start_ticks, "cgroup": cgroup})
        except (OSError, ValueError, IndexError):
            continue
    return procs, conmons


def owner_of(proc, names):
    """Attribute a process to its container, else its systemd unit, else its command."""
    cid = CID_RE.search(proc["cgroup"])
    if cid:
        return names.get(cid.group(1), f"container {cid.group(1)[:12]}"), "container"
    units = UNIT_RE.findall(proc["cgroup"])
    if units:
        return units[-1], "service"
    return proc["comm"], "process"


def compose_services(path):
    try:
        text = path.read_text()
    except OSError:
        return []
    names, inside = [], False
    for line in text.splitlines():
        if re.match(r"^services:\s*$", line):
            inside = True
        elif re.match(r"^\S", line) and not line.startswith("#"):
            inside = False
        elif inside:
            m = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
            if m:
                names.append(m.group(1))
    return names


def run_json(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        return json.loads(r.stdout) if r.stdout.strip() else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def is_local_system_unit(unit):
    """Units an admin added, as opposed to the distro's."""
    p = f"/etc/systemd/system/{unit}"
    return not unit.startswith("snap.") and os.path.isfile(p) and not os.path.islink(p)


inventory = {"podman": [], "user": [], "system": [], "declared": [], "at": 0.0, "running": False}
disk_state = {"rows": None, "home": 0, "at": None, "last_try": 0.0, "running": False}


def refresh_inventory():
    args = ["list-units", "--type=service", "--state=running,failed", "--no-legend", "--plain", "--output=json"]
    try:
        podman = run_json(["podman", "ps", "-a", "--format", "json"])
        user = run_json(["systemctl", "--user", *args])
        system = [u for u in run_json(["systemctl", *args]) if is_local_system_unit(u.get("unit", ""))]
        inventory.update(podman=podman, user=user, system=system, declared=compose_services(COMPOSE_FILE), at=time.monotonic())
    finally:
        inventory["running"] = False


def scan_disk():
    try:
        r = subprocess.run(["nice", "-n", "19", "ionice", "-c3", "du", "-x", "-d1", "-k", HOME],
                           capture_output=True, text=True, timeout=900)
        sizes = {}
        for line in r.stdout.splitlines():
            size, _, p = line.partition("\t")
            if size.isdigit():
                sizes[p] = int(size) * 1024
        home_total = sizes.pop(HOME, 0)
        if home_total:
            rows = [{"name": "~/" + os.path.basename(p), "bytes": b} for p, b in sizes.items()]
            disk_state.update(rows=sorted(rows, key=lambda x: -x["bytes"]), home=home_total, at=time.time())
    except (OSError, subprocess.SubprocessError):
        pass
    finally:
        disk_state["running"] = False


def kick_background():
    now = time.monotonic()
    if not inventory["running"] and now - inventory["at"] >= INVENTORY_SEC:
        inventory["running"] = True
        threading.Thread(target=refresh_inventory, daemon=True).start()
    if not disk_state["running"] and now - disk_state["last_try"] >= DISK_SCAN_SEC:
        disk_state["running"] = True
        disk_state["last_try"] = now
        threading.Thread(target=scan_disk, daemon=True).start()


def build_inventory(conmons, usage, now_up):
    containers = {}
    for c in conmons:
        if c["name"].endswith("-infra"):
            continue
        containers[c["name"]] = {
            "name": c["name"], "scope": "rootful" if c["root"] else "rootless", "state": "running",
            "uptimeSec": max(0, now_up - c["start"] / CLK_TCK), "bytes": usage.get(c["name"], 0),
        }
    for c in inventory["podman"]:
        names = c.get("Names") or []
        if not names or c.get("IsInfra") or names[0] in containers:
            continue
        containers[names[0]] = {"name": names[0], "scope": "rootless", "state": c.get("State", "unknown"), "uptimeSec": None, "bytes": 0}
    for name in inventory["declared"]:
        if name not in containers:
            containers[name] = {"name": name, "scope": "rootful", "state": "not running", "uptimeSec": None, "bytes": 0}

    services = []
    for scope, units in (("user", inventory["user"]), ("system", inventory["system"])):
        for u in units:
            name = u.get("unit", "").removesuffix(".service")
            if not name or name in NOISE_UNITS or name in containers:
                continue
            services.append({"name": name, "scope": scope, "state": u.get("sub", "unknown"), "failed": u.get("active") == "failed", "bytes": usage.get(name, 0)})
    return sorted(containers.values(), key=lambda c: (c["scope"], c["name"])), sorted(services, key=lambda s: (s["scope"], s["name"]))


def disk_breakdown(disk):
    rows = disk_state["rows"]
    if rows is None:
        return [], None
    shown = rows[:TOP_N - 2]
    rest = sum(r["bytes"] for r in rows[TOP_N - 2:])
    out = list(shown)
    if rest:
        out.append({"name": "rest of ~", "bytes": rest})
    outside = max(0, disk["used"] - disk_state["home"])
    if outside:
        out.append({"name": "outside ~ (system, rootful containers)", "bytes": outside})
    return sorted(out, key=lambda x: -x["bytes"]), disk_state["at"]


lock = threading.Lock()
prev_cpu = cpu_sample()
prev_net = net_sample()
prev_ticks = {(p["pid"], p["start"]): p["ticks"] for p in scan_procs()[0]}
last_cpu_pct = None
time.sleep(0.2)


def collect():
    global prev_cpu, prev_net, prev_ticks, last_cpu_pct
    kick_background()
    with lock:
        cur = cpu_sample()
        idle, total = cur[0] - prev_cpu[0], cur[1] - prev_cpu[1]
        if total > 0:
            last_cpu_pct = round(max(0.0, min(100.0, (1 - idle / total) * 100)), 1)
            prev_cpu = cur

        net = net_sample()
        rx_rate = tx_rate = None
        if net and prev_net and prev_net["iface"] == net["iface"] and net["at"] > prev_net["at"]:
            dt = net["at"] - prev_net["at"]
            rx_rate = max(0.0, (net["rx"] - prev_net["rx"]) / dt)
            tx_rate = max(0.0, (net["tx"] - prev_net["tx"]) / dt)
        if net:
            prev_net = net
        cpu_pct = last_cpu_pct

        procs, conmons = scan_procs()
        names = {c["cid"]: c["name"] for c in conmons}
        container_names = set(names.values())
        groups, ticks_now = {}, {}
        for p in procs:
            key = (p["pid"], p["start"])
            ticks_now[key] = p["ticks"]
            name, kind = owner_of(p, names)
            if name in container_names:
                kind = "container"
            g = groups.setdefault(name, {"name": name, "kind": kind, "bytes": 0, "procs": 0, "ticks": 0})
            g["bytes"] += p["rss"]
            g["procs"] += 1
            g["ticks"] += max(0, p["ticks"] - prev_ticks.get(key, p["ticks"]))
        prev_ticks = ticks_now

    now_up = uptime_sec()
    usage = {g["name"]: g["bytes"] for g in groups.values()}
    containers, services = build_inventory(conmons, usage, now_up)
    disk = disk_info("/")
    disk_rows, disk_at = disk_breakdown(disk)
    by_mem = sorted(groups.values(), key=lambda g: -g["bytes"])[:TOP_N]
    by_cpu = sorted((g for g in groups.values() if g["ticks"] > 0), key=lambda g: -g["ticks"])[:TOP_N]
    load = os.getloadavg()
    cpus = os.cpu_count() or 1
    return {
        "hostname": platform.node(),
        "platform": f"{platform.system()} {platform.release()} · {platform.machine()}",
        "uptimeSec": now_up,
        "cpus": cpus,
        "load": {"m1": load[0], "m5": load[1], "m15": load[2]},
        "cpu": {"pct": cpu_pct, "cores": cpus},
        "mem": mem_info(),
        "disk": disk,
        "net": {"iface": net["iface"], "rx": net["rx"], "tx": net["tx"], "rxRate": rx_rate, "txRate": tx_rate} if net else None,
        "top": {
            "memory": [{"name": g["name"], "kind": g["kind"], "bytes": g["bytes"], "procs": g["procs"]} for g in by_mem],
            "cpu": [{"name": g["name"], "kind": g["kind"], "pct": round(g["ticks"] / total * 100, 1) if total > 0 else 0} for g in by_cpu],
            "disk": disk_rows,
            "diskAt": disk_at,
        },
        "containers": containers,
        "services": services,
    }


class Handler(BaseHTTPRequestHandler):
    timeout = 5
    server_version = "stats-agent"
    sys_version = ""

    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), EXPECTED):
            return self.reply(401, {"error": "unauthorized"})
        if self.path != "/stats":
            return self.reply(404, {"error": "not found"})
        self.reply(200, collect())

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    kick_background()
    print(f"stats-agent listening on {BIND}:{PORT}", flush=True)
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
