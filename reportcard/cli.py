"""Command line: collect (daily), alerts (hourly), report (weekly), check, restore-test, test-notify, demo."""
import argparse
import copy
import fcntl
import os
import socket
import sys
import time

from . import __version__, render, report
from .checks import AREAS, Context, backups, run_all
from .config import Config
from .notify import send
from .store import Store
from .util import CRIT, os_name

QUICK_AREAS = ("backups", "website", "server")


def host_info():
    return {"hostname": socket.gethostname(), "os": os_name(), "kernel": os.uname().release}


class Lock:
    def __init__(self, store):
        self.path = os.path.join(store.dir, ".lock")
        store.ensure()

    def __enter__(self):
        self.fh = open(self.path, "w")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()


def process_alerts(cfg, store, state, results, areas, quiet=False):
    """Send an alert for each new urgent problem, and a 'resolved' message when it is gone."""
    open_alerts = state.setdefault("alerts", {})
    now = time.time()
    current = {r["id"]: r for r in results if r["status"] == CRIT}
    host = cfg.get("report", "server_name") or socket.gethostname()
    sent = []
    for rid, r in current.items():
        if rid in open_alerts:
            continue
        text = "%s\n\n%s%s" % (r["title"], (r["why"] + "\n") if r.get("why") else "",
                               ("Next step: " + r["action"]) if r.get("action") else "")
        res = send(cfg, "\U0001F534 ALERT %s: %s" % (host, r["title"]), text.strip(), alert=True)
        if r["kind"] == "state":       # events (new root account...) are reported once, never "resolved"
            open_alerts[rid] = {"since": now, "title": r["title"], "area": r["area"]}
        store.add_event({"type": "alert", "id": rid, "state": "problem", "title": r["title"], "sent": res})
        sent.append(("problem", r["title"], res))
    broken = {r["area"] for r in results if r["id"].endswith(".error")}
    for rid in list(open_alerts):
        a = open_alerts[rid]
        # resolved only when that check really ran this time and is no longer urgent
        if a.get("area") not in areas or a.get("area") in broken or rid in current:
            continue
        dur = report._dur(int(now - a["since"]))
        res = send(cfg, "✅ RESOLVED %s: %s" % (host, a["title"]), "Fixed after %s." % dur, alert=True)
        store.add_event({"type": "alert", "id": rid, "state": "resolved", "title": a["title"], "sent": res})
        del open_alerts[rid]
        sent.append(("resolved", a["title"], res))
    if not quiet:
        for kind, title, res in sent:
            print("%s alert: %s %s" % (kind, title, res or "(no channel enabled)"))
    return sent


def cmd_collect(cfg, store, args):
    with Lock(store):
        state = store.load("state.json")
        now = time.time()
        since = max(state.get("last_collect", now - 86400), now - 3 * 86400)
        ctx = Context(cfg, state, since, now)
        ctx.store = store
        results, metrics = run_all(ctx)
        snap = {"time": now, "since": since, "host": host_info(), "results": results, "metrics": metrics,
                "version": __version__}
        day = store.save_snapshot(snap)
        process_alerts(cfg, store, state, results, [k for k, _, _ in AREAS],
                       quiet=args.quiet)
        state["last_collect"] = now
        store.save("state.json", state)
    if not args.quiet:
        print(render.terminal(results))
        print("\nSaved snapshot %s in %s" % (day, store.snap_dir))
    return 0


def cmd_alerts(cfg, store, args):
    with Lock(store):
        state = store.load("state.json")
        now = time.time()
        ctx = Context(cfg, copy.deepcopy(state), now - 3600, now, quick=True)
        ctx.store = store
        results, _ = run_all(ctx, only=QUICK_AREAS)
        process_alerts(cfg, store, state, results, QUICK_AREAS, quiet=args.quiet)
        store.save("state.json", state)
    return 0


def cmd_check(cfg, store, args):
    now = time.time()
    state = copy.deepcopy(store.load("state.json"))      # read-only: never changes the saved baselines
    ctx = Context(cfg, state, now - 86400, now)
    ctx.store = store
    results, _ = run_all(ctx, only=args.area or None)
    print(render.terminal(results))
    return 1 if any(r["status"] == CRIT for r in results) else 0


def cmd_report(cfg, store, args):
    days = args.days or cfg.int("report", "days")
    now = time.time()
    snaps = store.snapshots(now - days * 86400 - 3600)
    if not snaps:
        print("No data yet. Run `server-report-card collect` first (it runs every day once installed).", file=sys.stderr)
        return 2
    rep = report.build(cfg, snaps, store.events(now - days * 86400), now, days)
    html_text = render.html_report(rep)
    out = args.out or os.path.join(store.dir, "reports", time.strftime("report-%Y-%m-%d.html"))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    print(render.text_report(rep))
    print("\nHTML report: %s" % out)
    if args.send:
        res = send(cfg, render.subject(rep), render.text_report(rep), html_text)
        if not res:
            print("Nothing sent: enable [email] or [telegram] in %s" % cfg.path, file=sys.stderr)
            return 2
        for ch, err in res:
            print("sent by %s" % ch if not err else "FAILED by %s: %s" % (ch, err))
        return 1 if any(err for _, err in res) else 0
    return 0


def cmd_restore_test(cfg, store, args):
    res = backups.restore_test(cfg, store)
    for r in res.get("repos", []):
        print("%s: %s, %s files compared, %d different, %d missing, %ss%s" % (
            r["name"], "PASSED" if r["ok"] else "FAILED", r.get("files_checked", 0), len(r.get("different", [])),
            len(r.get("missing", [])), r.get("seconds"), (" (" + r["error"] + ")") if r.get("error") else ""))
    if res.get("error"):
        print("FAILED: %s" % res["error"])
    return 0 if res.get("ok") else 1


def cmd_test_notify(cfg, store, args):
    res = send(cfg, "✅ Test from server-report-card on %s" % socket.gethostname(),
               "If you can read this, alerts and weekly reports will reach you.")
    if not res:
        print("No channel enabled: set enabled = true under [email] or [telegram] in %s" % cfg.path)
        return 2
    for ch, err in res:
        print("%s: %s" % (ch, "OK" if not err else "FAILED - " + err))
    return 1 if any(err for _, err in res) else 0


def cmd_demo(cfg, store, args):
    from .demo import demo_snapshots
    snaps, events = demo_snapshots()
    for k, v in (("server_name", "Shop web server (shop.example.com)"), ("client_name", "Example Shop Ltd"),
                 ("provider_name", "Your Linux admin"), ("provider_contact", "admin@example.com")):
        if not cfg.get("report", k):
            cfg.cp.set("report", k, v)
    rep = report.build(cfg, snaps, events, snaps[-1]["time"] + 3600)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(render.html_report(rep))
    print(render.text_report(rep))
    print("\nDemo report: %s" % args.out)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="server-report-card",
                                 description="A weekly server health and security report a business owner can read.")
    ap.add_argument("-c", "--config", help="config file (default /etc/server-report-card/config.ini)")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("collect", help="run every check and save today's results (daily timer)")
    p.add_argument("-q", "--quiet", action="store_true")
    p = sub.add_parser("alerts", help="fast checks, alert on new urgent problems (hourly timer)")
    p.add_argument("-q", "--quiet", action="store_true")
    p = sub.add_parser("check", help="run the checks now and print them (changes nothing)")
    p.add_argument("area", nargs="*", choices=["security", "backups", "website", "email", "server"])
    p = sub.add_parser("report", help="build the weekly report from the saved results")
    p.add_argument("--days", type=int)
    p.add_argument("--out", help="write the HTML report here")
    p.add_argument("--send", action="store_true", help="send it by email/Telegram")
    sub.add_parser("restore-test", help="restore the latest backup into a temp folder and compare (monthly timer)")
    sub.add_parser("test-notify", help="send a test message on every enabled channel")
    p = sub.add_parser("demo", help="write a sample report with made-up data")
    p.add_argument("--out", default="demo-report.html")
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 2
    cfg = Config(args.config)
    if not cfg.loaded and args.cmd not in ("demo", "check"):
        print("Note: %s not found, using defaults." % cfg.path, file=sys.stderr)
    store = Store(cfg.data_dir)
    handler = {"collect": cmd_collect, "alerts": cmd_alerts, "check": cmd_check, "report": cmd_report,
               "restore-test": cmd_restore_test, "test-notify": cmd_test_notify, "demo": cmd_demo}[args.cmd]
    try:
        return handler(cfg, store, args)
    except PermissionError as exc:
        print("Permission denied (%s). Run as root: the checks read system logs and firewall state." % exc, file=sys.stderr)
        return 2
