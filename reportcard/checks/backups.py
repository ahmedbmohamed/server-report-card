"""Backups: did the last backup run, how old is it, and can it really be restored?"""
import glob
import hashlib
import json
import os
import shutil
import tempfile
import time

from ..util import CRIT, OK, UNKNOWN, WARN, human_age, plural, result
from ..util import run as sh

AREA = "backups"


def parse_time(value):
    """ISO 8601 (as written by `date -Is` or restic) -> epoch seconds."""
    import datetime
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    if "." in v:                                   # restic: 2026-11-24T02:30:01.123456789+01:00
        head, _, rest = v.partition(".")
        tz = ""
        for sep in ("+", "-"):
            if sep in rest:
                tz = sep + rest.split(sep, 1)[1]
        v = head + tz
    if len(v) > 19 and v[-3] == ":":               # +01:00 -> +0100 for strptime on Python 3.6
        v = v[:-3] + v[-2:]
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            d = datetime.datetime.strptime(v, fmt)
            return d.timestamp()
        except ValueError:
            continue
    raise ValueError("unknown time format: %s" % value)


def load_env(path):
    env = dict(os.environ)
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("export "):
                line = line[7:]
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def status_name(path):
    n = os.path.basename(path)
    for pre in ("last-backup-",):
        if n.startswith(pre):
            n = n[len(pre):]
    return n[:-5] if n.endswith(".json") else n


def sources(cfg):
    """Every backup we can find: status files, restic repositories, marker files."""
    found = []
    for pattern in cfg.list("backups", "status_files"):
        for p in sorted(glob.glob(pattern)):
            try:
                with open(p, encoding="utf-8") as fh:
                    d = json.load(fh)
                found.append({"name": status_name(p), "kind": "status", "ok": d.get("status") == "ok",
                              "time": parse_time(d["time"]), "detail": d.get("step") or d.get("snapshot", "")})
            except (OSError, ValueError, KeyError) as exc:
                found.append({"name": status_name(p), "kind": "status", "error": str(exc)})
    for pattern in cfg.list("backups", "restic_env_files"):
        for p in sorted(glob.glob(pattern)):
            name = os.path.basename(os.path.dirname(p))
            try:
                env = load_env(p)
            except OSError as exc:
                found.append({"name": name, "kind": "restic", "error": str(exc)})
                continue
            rc, out, err = sh(["restic", "snapshots", "--json", "--latest", "1", "--no-lock"], timeout=300, env=env)
            if rc != 0:
                found.append({"name": name, "kind": "restic", "env": p, "error": (err or out).strip()[-300:]})
                continue
            snaps = json.loads(out or "[]")
            if not snaps:
                found.append({"name": name, "kind": "restic", "env": p, "ok": False, "time": 0, "detail": "no snapshots"})
                continue
            last = max(snaps, key=lambda s: s["time"])
            found.append({"name": name, "kind": "restic", "env": p, "ok": True, "time": parse_time(last["time"]),
                          "detail": "snapshot %s" % last.get("short_id", last.get("id", "")[:8])})
    for pattern in cfg.list("backups", "marker_files"):
        for p in sorted(glob.glob(pattern)):
            found.append({"name": os.path.basename(p), "kind": "marker", "ok": True, "time": os.path.getmtime(p)})
    return found


def check_backups(ctx, metrics):
    cfg = ctx.cfg
    max_age = cfg.int("backups", "max_age_hours") * 3600
    found = sources(cfg)
    if not found:
        if not cfg.bool("backups", "required"):
            return []
        return [result("backup", AREA, CRIT, "I found no backups on this server.",
                       why="If the disk dies or the server is hacked, everything is lost.",
                       action="Set up automatic daily backups to another location.",
                       detail="Looked for: %s" % ", ".join(cfg.list("backups", "status_files") +
                                                           cfg.list("backups", "restic_env_files") +
                                                           cfg.list("backups", "marker_files")))]
    out, good = [], 0
    with_status = {b["name"] for b in found if b["kind"] == "status"}
    shown = [b for b in found if not (b["kind"] == "restic" and b["name"] in with_status)]
    for b in shown:
        if b.get("error"):
            out.append(result("backup:" + b["name"], AREA, UNKNOWN, "I could not read the backup %s." % b["name"],
                              action="Ask your administrator to check the backup access.", detail=b["error"]))
            continue
        age = ctx.now - b["time"] if b["time"] else None
        if not b["ok"]:
            out.append(result("backup:" + b["name"], AREA, CRIT, "The last backup failed (%s ago)." % human_age(age) if age else
                              "The backup has never completed.",
                              why="If something breaks now, recent data cannot be recovered.",
                              action="Fix the backup today.", detail=b.get("detail", "")))
        elif age > max_age:
            out.append(result("backup:" + b["name"], AREA, CRIT, "The last good backup is %s old." % human_age(age),
                              why="The daily backup has stopped running.",
                              action="Find out why the backup stopped and run it now.", detail=b.get("detail", "")))
        else:
            good += 1
            out.append(result("backup:" + b["name"], AREA, OK, "Last backup %s ago, it worked." % human_age(age),
                              detail="%s %s" % (b["name"], b.get("detail", ""))))
    metrics["backup_ok"] = good == len(shown)
    metrics["backups"] = [{k: v for k, v in b.items() if k != "env"} for b in found]
    return out


# ------------------------------------------------------------------ restore test
def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def compare(live_root, restored_root, snapshot_time, limit=2000):
    """Compare restored files with live files that did not change since the snapshot."""
    checked, different, missing = 0, [], []
    for dirpath, dirs, files in os.walk(live_root):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(dirpath, d))]
        for f in files:
            live = os.path.join(dirpath, f)
            try:
                st = os.lstat(live)
            except OSError:
                continue
            if not os.path.isfile(live) or os.path.islink(live) or st.st_mtime >= snapshot_time - 1:
                continue
            restored = os.path.join(restored_root, live.lstrip("/"))
            if not os.path.isfile(restored):
                missing.append(live)
                continue
            try:
                if file_hash(live) != file_hash(restored):
                    different.append(live)
            except OSError:
                continue
            checked += 1
            if checked >= limit:
                return checked, different, missing
    return checked, different, missing


def restore_test(cfg, store, now=None):
    """Restore the latest restic snapshot of one folder into a temp dir and compare it with the live files."""
    now = now or time.time()
    path = cfg.get("backups", "restore_test_path") or "/etc"
    repos = [b for b in sources(cfg) if b["kind"] == "restic" and not b.get("error")]
    if not repos:
        res = {"time": now, "ok": False, "error": "no restic repository found (restore test only works with restic)"}
        store.save("restore-test.json", res)
        return res
    results = []
    for b in repos:
        env = load_env(b["env"])
        tmp = tempfile.mkdtemp(prefix="reportcard-restore-")
        try:
            t0 = time.time()
            rc, out, err = sh(["restic", "restore", "latest", "--target", tmp, "--include", path, "--no-lock"],
                              timeout=3600, env=env)
            r = {"name": b["name"], "seconds": round(time.time() - t0, 1), "snapshot": b.get("detail", "")}
            if rc != 0:
                r.update(ok=False, error=(err or out).strip()[-300:])
            else:
                checked, different, missing = compare(path, tmp, b["time"])
                r.update(files_checked=checked, different=different[:20], missing=missing[:20])
                r["ok"] = checked > 0 and not different and not missing
                if checked == 0:
                    r["error"] = "no file to compare in %s" % path
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        results.append(r)
    res = {"time": now, "path": path, "ok": all(r["ok"] for r in results), "repos": results}
    store.save("restore-test.json", res)
    return res


def check_restore(ctx, store):
    every = ctx.cfg.int("backups", "restore_test_days")
    last = store.load("restore-test.json") if store else {}
    if not last:
        return [result("restore", AREA, WARN, "The backup has never been test-restored.",
                       why="Many companies only discover their backups are broken on the day they need them.",
                       action="Run a restore test (server-report-card restore-test). It runs monthly once installed.")]
    age = ctx.now - last.get("time", 0)
    files = sum(r.get("files_checked", 0) for r in last.get("repos", []))
    if not last.get("ok"):
        errs = "; ".join(r.get("error", "") or "%d different, %d missing" % (len(r.get("different", [])), len(r.get("missing", [])))
                         for r in last.get("repos", [])) or last.get("error", "")
        return [result("restore", AREA, CRIT, "The last restore test failed (%s ago)." % human_age(age),
                       why="The backup may not bring your data back.",
                       action="Your administrator must fix the backup.", detail=errs)]
    if age > every * 1.5 * 86400:
        return [result("restore", AREA, WARN, "The last restore test is %s old." % human_age(age),
                       action="Run a new restore test.")]
    return [result("restore", AREA, OK, "Restore test passed %s ago: %s restored and identical." % (
        human_age(age), plural(files, "file")), detail="path %s" % last.get("path", ""))]


def run(ctx):
    metrics = {}
    out = check_backups(ctx, metrics)
    if out and not ctx.quick and any(b.get("kind") == "restic" for b in metrics.get("backups", [])):
        out += check_restore(ctx, getattr(ctx, "store", None))
    return out, metrics
