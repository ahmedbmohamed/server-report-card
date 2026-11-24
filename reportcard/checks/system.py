"""Server: disk, memory, load, failed services, crashes (out of memory), restarts, clock."""
import os
import re

from ..util import CRIT, INFO, OK, UNKNOWN, WARN, plural, read, result
from ..util import run as sh

AREA = "server"
REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "jfs", "reiserfs", "f2fs"}


def mounts(text):
    seen, out = set(), []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 3 or cols[2] not in REAL_FS:
            continue
        dev, mnt = cols[0], cols[1].replace("\\040", " ")
        if len(cols) > 3 and "ro" in cols[3].split(","):
            continue
        if dev in seen or mnt.startswith(("/snap", "/var/lib/docker", "/var/lib/containers")):
            continue
        seen.add(dev)
        out.append(mnt)
    return out


def check_disks(ctx, metrics):
    warn, crit = ctx.cfg.int("server", "disk_warn"), ctx.cfg.int("server", "disk_crit")
    out, usage = [], {}
    for mnt in mounts(read("/proc/mounts")):
        try:
            st = os.statvfs(mnt)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        if not total:
            continue
        free = st.f_bavail * st.f_frsize
        pct = round(100.0 * (total - free) / total)
        ipct = round(100.0 * (st.f_files - st.f_favail) / st.f_files) if st.f_files else 0
        usage[mnt] = {"pct": pct, "free_gb": round(free / 1e9, 1), "total_gb": round(total / 1e9, 1), "inodes_pct": ipct}
        level = max(pct, ipct)
        if level >= warn:
            out.append(result("disk:" + mnt, AREA, CRIT if level >= crit else WARN,
                              "Disk %s is %d%% full (%s GB free)." % (mnt, level, usage[mnt]["free_gb"]),
                              why="When a disk is full, the website, database and backups stop working.",
                              action="Clean old files/logs or add disk space soon.",
                              detail="space %d%%, inodes %d%%" % (pct, ipct)))
    metrics["disks"] = usage
    if not usage:
        return [result("disk", AREA, UNKNOWN, "I could not read the disk usage.")]
    if not out:
        main = usage.get("/") or list(usage.values())[0]
        out.append(result("disk", AREA, OK, "Disk space is fine (%d%% used, %s GB free)." % (main["pct"], main["free_gb"]),
                          detail="; ".join("%s %d%%" % (m, u["pct"]) for m, u in usage.items())))
    return out


def meminfo(text):
    m = {}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        try:
            m[k] = int(v.split()[0]) * 1024
        except (ValueError, IndexError):
            pass
    return m


def check_memory(ctx, metrics):
    m = meminfo(read("/proc/meminfo"))
    total = m.get("MemTotal")
    if not total:
        return [result("memory", AREA, UNKNOWN, "I could not read the memory usage.")]
    avail = m.get("MemAvailable", m.get("MemFree", 0))
    pct = 100.0 * avail / total
    metrics["mem_available_pct"] = round(pct, 1)
    metrics["mem_total_gb"] = round(total / 1e9, 1)
    w, c = ctx.cfg.int("server", "memory_warn"), ctx.cfg.int("server", "memory_crit")
    if pct < w:
        return [result("memory", AREA, CRIT if pct < c else WARN, "Memory is almost full (%d%% free)." % pct,
                       why="The server slows down and programs get killed when memory runs out.",
                       action="Find what uses the memory, or move to a bigger server.")]
    return [result("memory", AREA, OK, "Memory is fine (%d%% free of %s GB)." % (pct, metrics["mem_total_gb"]))]


def check_load(ctx, metrics):
    try:
        l15 = os.getloadavg()[2]
    except OSError:
        return []
    cpus = os.cpu_count() or 1
    metrics["load15"] = round(l15, 2)
    metrics["cpus"] = cpus
    if l15 > 2 * cpus:
        return [result("load", AREA, WARN, "The server is overloaded right now.",
                       why="Pages load slowly or time out.", action="Find the busy program or add CPU.",
                       detail="load %.2f on %d CPUs" % (l15, cpus))]
    return []


def check_services(ctx, metrics):
    out = []
    rc, txt, err = sh(["systemctl", "list-units", "--failed", "--plain", "--no-legend", "--no-pager"], timeout=20)
    failed = [ln.split()[0] for ln in txt.splitlines() if ln.strip() and ln.split()[0] != "●"] if rc == 0 else []
    failed += [ln.split()[1] for ln in txt.splitlines() if ln.strip().startswith("●") and len(ln.split()) > 1]
    metrics["failed_units"] = failed
    for name in ctx.cfg.list("server", "services"):
        unit = name if "." in name else name + ".service"
        rc, state, _ = sh(["systemctl", "is-active", unit], timeout=10)
        state = state.strip() or "unknown"
        if state != "active":
            out.append(result("service:" + name, AREA, CRIT, "%s is not running (%s)." % (name, state),
                              why="Whatever depends on it (website, database, email) is down.",
                              action="Restart it and find out why it stopped.",
                              detail="systemctl is-active %s -> %s" % (unit, state)))
    watched = {(n if "." in n else n + ".service") for n in ctx.cfg.list("server", "services")}
    ignored = {(n if "." in n else n + ".service") for n in ctx.cfg.list("server", "ignore_failed_units")}
    other = [u for u in failed if u not in watched and u not in ignored]
    if other:
        out.append(result("services.failed", AREA, WARN, "%s failed: %s." % (plural(len(other), "background service"), ", ".join(other)),
                          why="Something that should run on the server is broken.",
                          action="Check why it failed (systemctl status).", detail=" ".join(other)))
    if not out:
        watched_txt = ", ".join(ctx.cfg.list("server", "services"))
        out.append(result("services", AREA, OK, "All services are running%s." % (" (%s)" % watched_txt if watched_txt else "")))
    return out


RE_OOM = re.compile(r"Out of memory: Kill(?:ed)? process \d+ \((?P<name>[^)]+)\)")


def check_crashes(ctx, metrics):
    rc, out, _ = sh(["journalctl", "-k", "--since", "@%d" % ctx.since, "--until", "@%d" % ctx.now,
                     "-o", "cat", "--no-pager", "-q"], timeout=60)
    kills = [m.group("name") for m in RE_OOM.finditer(out)] if rc == 0 else []
    metrics["oom_kills"] = kills
    res = []
    if kills:
        res.append(result("oom", AREA, WARN, "The server ran out of memory and stopped %s (%s)." % (
            plural(len(kills), "program"), ", ".join(sorted(set(kills)))),
            why="A killed program can mean the website or database went down for a while.",
            action="Add memory or limit the program that uses too much.", kind="event"))
    boot_id = read("/proc/sys/kernel/random/boot_id").strip()
    prev = ctx.state.get("boot_id")
    ctx.state["boot_id"] = boot_id
    up = float((read("/proc/uptime") or "0").split()[0])
    metrics["uptime_days"] = round(up / 86400, 1)
    if prev and prev != boot_id:
        metrics["reboots"] = 1
        res.append(result("reboot.happened", AREA, INFO, "The server restarted (up for %s since)." % (
            plural(int(up // 86400), "day") if up >= 86400 else plural(int(up // 3600), "hour")), kind="event"))
    return res


def check_clock(ctx):
    rc, out, _ = sh(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=10)
    if rc == 0 and out.strip() == "no":
        return [result("clock", AREA, WARN, "The server clock is not synchronised.",
                       why="A wrong clock breaks HTTPS, logs and scheduled backups.",
                       action="Turn on time sync (chrony or systemd-timesyncd).")]
    return []


def run(ctx):
    metrics = {}
    out = check_disks(ctx, metrics) + check_memory(ctx, metrics) + check_load(ctx, metrics)
    out += check_services(ctx, metrics)
    if not ctx.quick:
        out += check_crashes(ctx, metrics) + check_clock(ctx)
    return out, metrics
