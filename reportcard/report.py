"""Turn a week of daily snapshots into one report: score, headline, highlights, findings by area."""
import collections
import time

from .checks import AREAS
from .util import CRIT, INFO, OK, SEVERITY, UNKNOWN, WARN, fmt_int, plural, result, worst

PENALTY = {CRIT: 20, WARN: 7, UNKNOWN: 2, INFO: 0, OK: 0}


def grade(score):
    for limit, g in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= limit:
            return g
    return "F"


def merge_events(snapshots):
    """Event findings: keep every distinct problem seen during the week, worst first."""
    by_id = collections.OrderedDict()
    for s in snapshots:
        for r in s["results"]:
            if r["kind"] != "event":
                continue
            cur = by_id.get(r["id"])
            if cur is None:
                by_id[r["id"]] = dict(r, titles=[r["title"]])
                continue
            if r["title"] not in cur["titles"]:
                cur["titles"].append(r["title"])
            if SEVERITY[r["status"]] >= SEVERITY[cur["status"]]:
                titles = cur["titles"]
                cur.update(r)
                cur["titles"] = titles
    out = []
    for r in by_id.values():
        if len(r["titles"]) > 1 and r["status"] != OK:
            r["title"] = " ".join(t for t in r["titles"])
        out.append(r)
    return out


def weekly_ssh(snapshots, statuses):
    total = sum(s["metrics"].get("security", {}).get("ssh_attempts", 0) for s in snapshots)
    bans = sum(s["metrics"].get("security", {}).get("bans", 0) for s in snapshots)
    ips = collections.Counter()
    for s in snapshots:
        for ip, n in s["metrics"].get("security", {}).get("ssh_top_ips", []):
            ips[ip] += n
    if not total:
        return result("ssh.attacks", "security", OK, "No break-in attempts through SSH this week.", kind="event"), total, bans
    title = "%s to break in through SSH this week" % plural(total, "attempt")
    title += "; Fail2ban blocked %s." % plural(bans, "address", "addresses") if bans else "."
    title += " None got in."
    r = result("ssh.attacks", "security", INFO, title, kind="event",
               detail="Top sources: " + ", ".join("%s (%d)" % x for x in ips.most_common(5)))
    return r, total, bans


def outages(events):
    """Website outages detected by the hourly alert check."""
    down = collections.defaultdict(list)
    for e in events:
        if e.get("type") == "alert" and str(e.get("id", "")).startswith("site:"):
            down[e["id"]].append(e)
    out = {}
    for sid, evs in down.items():
        evs.sort(key=lambda e: e["time"])
        n, secs, start = 0, 0, None
        for e in evs:
            if e["state"] == "problem" and start is None:
                start, n = e["time"], n + 1
            elif e["state"] == "resolved" and start is not None:
                secs += e["time"] - start
                start = None
        if start is not None:
            secs += time.time() - start
        out[sid[5:]] = {"count": n, "seconds": int(secs)}
    return out


def build(cfg, snapshots, events=(), now=None, days=7):
    now = now or time.time()
    if not snapshots:
        raise ValueError("no data yet: run `server-report-card collect` first")
    latest = snapshots[-1]
    findings = [r for r in latest["results"] if r["kind"] == "state"]
    ev = [r for r in merge_events(snapshots) if r["id"] != "ssh.attacks"]
    statuses = collections.defaultdict(list)
    for s in snapshots:
        for r in s["results"]:
            statuses[r["id"]].append(r["status"])
    ssh, attempts, bans = weekly_ssh(snapshots, statuses)
    if any(r["area"] == "security" for r in latest["results"]):
        ev.insert(0, ssh)
    # fail2ban: replace the daily "blocked today" with the weekly total
    for r in findings + ev:
        if r["id"] == "fail2ban" and r["status"] == OK:
            r["title"] = "Fail2ban is on and blocked %s this week." % plural(bans, "address", "addresses")
    findings += ev

    # Backups: how many days of the week were covered
    days_with_data = [s for s in snapshots if "backup_ok" in s["metrics"].get("backups", {})]
    ok_days = sum(1 for s in days_with_data if s["metrics"]["backups"]["backup_ok"])

    # Website outages from the hourly alerts
    down = outages(events)
    still_down = {r["id"][5:] for r in findings if r["id"].startswith("site:") and r["status"] == CRIT}
    for url, o in down.items():
        if o["count"] and url not in still_down:
            findings.append(result("outage:" + url, "website", WARN,
                                   "%s was down %s this week (about %s in total)." % (
                                       url, plural(o["count"], "time"), _dur(o["seconds"])),
                                   why="Visitors could not reach the site during that time.",
                                   action="Look at what caused it so it does not happen again.", kind="event"))

    # ---- score and headline
    problems = [r for r in findings if r["status"] in (WARN, CRIT)]
    score = max(0, 100 - sum(PENALTY[r["status"]] for r in findings))
    crit = [r for r in problems if r["status"] == CRIT]
    if crit:
        headline = "Action needed: %s." % plural(len(crit), "urgent problem")
        overall = CRIT
    elif problems:
        headline = "Your server is working. %s to look at." % plural(len(problems), "thing")
        overall = WARN
    else:
        headline = "All good. Your server is healthy."
        overall = OK

    # ---- the week in 30 seconds
    m = latest["metrics"]
    hl = []
    if days_with_data:
        restore = [r for r in findings if r["id"] == "restore"]
        text = "Backups: %d of %d days OK." % (ok_days, len(days_with_data))
        if restore and restore[0]["status"] == CRIT:
            text += " But the last restore test FAILED."
        elif restore and restore[0]["status"] == OK:
            text += " Restore test passed."
        hl.append(("backups", worst(r["status"] for r in findings if r["area"] == "backups"), text))
    if any(r["area"] == "security" for r in findings):
        hl.append(("security", WARN if worst(statuses.get("ssh.attacks", [OK])) == WARN else OK,
                   "Security: %s break-in attempts, none got in." % fmt_int(attempts) if attempts else
                   "Security: no break-in attempts."))
    sites = m.get("website", {}).get("sites", {})
    if sites:
        total_down = sum(o["count"] for u, o in down.items() if u not in still_down)
        if still_down:
            hl.append(("website", CRIT, "Website: DOWN right now."))
        else:
            hl.append(("website", WARN if total_down else worst(r["status"] for r in findings if r["id"].startswith("site:")),
                       "Website: online all week." if not total_down else "Website: down %s this week." % plural(total_down, "time")))
        ssl_days = [v["ssl_days"] for v in sites.values() if v.get("ssl_days") is not None]
        if ssl_days:
            d = min(ssl_days)
            hl.append(("website", OK if d >= cfg.int("website", "ssl_warn_days") else WARN,
                       "SSL certificate: valid for %s more days." % int(d) if d >= 0 else "SSL certificate: EXPIRED."))
    if "security_updates" in m.get("security", {}):
        n = m["security"]["security_updates"]
        hl.append(("security", OK if not n else WARN,
                   "Updates: all security fixes installed." if not n else "Updates: %s waiting." % plural(n, "security fix", "security fixes")))
    doms = m.get("email", {}).get("domains", {})
    if doms:
        st = worst(r["status"] for r in findings if r["area"] == "email")
        hl.append(("email", OK if st == INFO else st, "Email setup (SPF, DKIM, DMARC): %s." % ("correct" if st in (OK, INFO) else "needs attention")))
    disks = m.get("server", {}).get("disks", {})
    if disks:
        top = max(disks.items(), key=lambda kv: kv[1]["pct"])
        hl.append(("server", worst(r["status"] for r in findings if r["id"].startswith("disk")),
                   "Disk: %d%% used." % top[1]["pct"]))

    # ---- sections
    sections = []
    for key, label, _ in AREAS:
        items = [r for r in findings if r["area"] == key]
        if not items:
            continue
        items.sort(key=lambda r: -SEVERITY[r["status"]])
        sections.append({"key": key, "label": label, "status": worst(r["status"] for r in items), "items": items})

    per_day = [(time.strftime("%a", time.localtime(s["time"])),
                s["metrics"].get("security", {}).get("ssh_attempts", 0)) for s in snapshots[-days:]]
    period = (snapshots[0]["time"], latest["time"])
    return {
        "host": latest.get("host", {}), "period": period, "generated": now, "days_of_data": len(snapshots),
        "score": score, "grade": grade(score), "overall": overall, "headline": headline,
        "highlights": hl, "problems": sorted(problems, key=lambda r: -SEVERITY[r["status"]]),
        "sections": sections, "attacks_per_day": per_day,
        "server_name": cfg.get("report", "server_name") or latest.get("host", {}).get("hostname", ""),
        "client_name": cfg.get("report", "client_name"),
        "provider_name": cfg.get("report", "provider_name"),
        "provider_contact": cfg.get("report", "provider_contact"),
    }


def _dur(secs):
    if secs < 3600:
        return plural(max(1, secs // 60), "minute")
    return plural(round(secs / 3600.0), "hour")
