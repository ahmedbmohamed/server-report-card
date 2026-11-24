import json
import os
import time

from reportcard import cli, render, report
from reportcard.checks import Context, backups
from reportcard.demo import demo_snapshots
from reportcard.store import Store
from reportcard.util import CRIT, OK, WARN, result


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t))


def test_backup_status_files(cfg, tmp_path):
    now = time.time()
    (tmp_path / "last-backup-shop.json").write_text(json.dumps({"status": "ok", "time": _iso(now - 3600), "snapshot": "ab12cd34"}))
    (tmp_path / "last-backup-old.json").write_text(json.dumps({"status": "ok", "time": _iso(now - 3 * 86400)}))
    (tmp_path / "last-backup-bad.json").write_text(json.dumps({"status": "failed", "time": _iso(now - 600), "step": "restic backup"}))
    c = cfg.write("[backups]\nstatus_files = %s/last-backup-*.json\nrestic_env_files =\n" % tmp_path)
    m = {}
    out = {r["id"]: r for r in backups.check_backups(Context(c, {}, now - 86400, now), m)}
    assert out["backup:shop"]["status"] == OK
    assert out["backup:old"]["status"] == CRIT and "3 days" in out["backup:old"]["title"]
    assert out["backup:bad"]["status"] == CRIT and "failed" in out["backup:bad"]["title"]
    assert m["backup_ok"] is False


def test_no_backup_is_urgent(cfg, tmp_path):
    c = cfg.write("[backups]\nstatus_files = %s/none-*.json\nrestic_env_files =\n" % tmp_path)
    out = backups.check_backups(Context(c, {}, 0), {})
    assert out[0]["status"] == CRIT and "no backups" in out[0]["title"]


def test_restore_compare(tmp_path):
    live, restored = tmp_path / "live", tmp_path / "restored"
    (live / "etc").mkdir(parents=True)
    for name, text in (("a.conf", "same"), ("b.conf", "live"), ("c.conf", "only live")):
        (live / "etc" / name).write_text(text)
    rdir = restored / str(live / "etc").lstrip("/")
    rdir.mkdir(parents=True)
    (rdir / "a.conf").write_text("same")
    (rdir / "b.conf").write_text("changed")
    checked, different, missing = backups.compare(str(live / "etc"), str(restored), time.time() + 10)
    assert checked == 2 and different == [str(live / "etc" / "b.conf")] and missing == [str(live / "etc" / "c.conf")]
    # files changed after the snapshot are skipped
    assert backups.compare(str(live / "etc"), str(restored), 0)[0] == 0


def test_demo_report_scores_and_renders(cfg):
    c = cfg.write("")
    snaps, events = demo_snapshots()
    rep = report.build(c, snaps, events, snaps[-1]["time"])
    assert rep["overall"] == WARN and rep["score"] == 79 and rep["grade"] == "B"
    titles = [r["title"] for r in rep["problems"]]
    assert any("12 days" in t for t in titles) and any("22 minutes" in t for t in titles)
    ssh = [r for s in rep["sections"] for r in s["items"] if r["id"] == "ssh.attacks"][0]
    assert ssh["title"].startswith("1,242 attempts") and "64 addresses" in ssh["title"]
    page = render.html_report(rep)
    assert "Your week in 30 seconds" in page and "Test server" in page and "<script" not in page
    assert "score 79/100" in render.text_report(rep)


def test_report_escapes_html(cfg):
    c = cfg.write("")
    snap = {"time": time.time(), "host": {}, "metrics": {},
            "results": [result("x", "server", WARN, "<img src=x onerror=alert(1)>", action="<b>do</b>")]}
    page = render.html_report(report.build(c, [snap]))
    assert "<img src=x" not in page and "&lt;img src=x" in page


def test_alerts_once_then_resolved(cfg, monkeypatch):
    c = cfg.write("")
    store = Store(str(cfg.data))
    sent = []
    monkeypatch.setattr(cli, "send", lambda cfg, subject, text, html=None, alert=False: sent.append(subject) or [])
    state = {}
    down = [result("site:https://x.test", "website", CRIT, "x.test is DOWN.")]
    cli.process_alerts(c, store, state, down, ["website"], quiet=True)
    cli.process_alerts(c, store, state, down, ["website"], quiet=True)          # still down: no second alert
    assert len(sent) == 1 and "ALERT" in sent[0]
    up = [result("site:https://x.test", "website", OK, "x.test is online.")]
    cli.process_alerts(c, store, state, up, ["server"], quiet=True)             # website not checked: stays open
    assert len(sent) == 1
    cli.process_alerts(c, store, state, up, ["website"], quiet=True)
    assert len(sent) == 2 and "RESOLVED" in sent[1] and not state["alerts"]
    ev = store.events(0)
    assert [e["state"] for e in ev] == ["problem", "resolved"]
    assert report.outages(ev)["https://x.test"]["count"] == 1


def test_event_alert_is_not_resolved_later(cfg, monkeypatch):
    c = cfg.write("")
    sent = []
    monkeypatch.setattr(cli, "send", lambda *a, **k: sent.append(a[1]) or [])
    state = {}
    r = [result("users.root", "security", CRIT, "A second admin-level account appeared: toor.", kind="event")]
    cli.process_alerts(c, Store(str(cfg.data)), state, r, ["security"], quiet=True)
    cli.process_alerts(c, Store(str(cfg.data)), state, [], ["security"], quiet=True)
    assert len(sent) == 1 and not state["alerts"]


def test_store_snapshots(cfg):
    store = Store(str(cfg.data))
    now = time.time()
    store.save_snapshot({"time": now - 8 * 86400, "results": []})
    store.save_snapshot({"time": now, "results": []})
    assert len(store.snapshots(now - 7 * 86400)) == 1
    assert oct(os.stat(str(cfg.data)).st_mode)[-3:] == "700"


def test_self_signed_certificate_is_read(tmp_path):
    """A self-signed certificate is reported as untrusted, but we still read its expiry date."""
    import shutil
    import socket
    import ssl
    import subprocess
    import threading

    import pytest

    from reportcard.checks import website
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-days", "40", "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        for _ in range(2):
            c, _ = srv.accept()
            try:
                ctx.wrap_socket(c, server_side=True).close()
            except (ssl.SSLError, OSError):
                c.close()

    threading.Thread(target=serve, daemon=True).start()
    left, problem, _ = website.certificate("localhost", port, timeout=5)
    srv.close()
    assert 38 < left <= 40
    assert problem and "self" in problem.lower()
