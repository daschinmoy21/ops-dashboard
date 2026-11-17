# ops.chinmoy.site

Password-protected ops dashboard for the netcup and oracle servers.

- `server.mjs`, `index.html`, `login.html`: the dashboard (Node, no dependencies).
  Listens on `HOST:PORT` (unit sets `10.89.0.1:8788`, the podman bridge Traefik
  routes to; defaults to `127.0.0.1`). HTML is read at startup, so restart after edits.
- `stats-agent/stats_agent.py`: read-only host stats served over token-protected
  HTTP. Runs on each server (netcup: `127.0.0.1:8789`, oracle: tailnet `:3788`).
  On netcup `~/opt/stats-agent/stats_agent.py` is a symlink to this file.
- `systemd/`: the user units (`~/.config/systemd/user/`).

Secrets stay out of git (`auth.json`, `*.token`, `~/.config/stats-agent/token`).

## Metrics and windows

Nothing is stored; every poll is a snapshot.
- PSI (`/proc/pressure/*` and each cgroup's `*.pressure`) carries the kernel's own
  10 s / 60 s / 300 s averages.
- cgroup counters (CPU time, throttling, IO bytes) become rates against the previous
  poll; `rates.intervalSec` says how long that window was.
- Cgroups whose threads park in io_uring waits are flagged `ioUring`: the kernel
  counts those idle waits as IO stall, so their IO PSI reads ~100% on an idle disk.

## Deploy

    systemctl --user restart observability-dashboard stats-agent

Oracle: copy `stats-agent/stats_agent.py` over its `~/opt/stats-agent/stats_agent.py`
and `systemctl --user restart stats-agent`.
