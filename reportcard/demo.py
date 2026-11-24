"""Made-up week of data for `server-report-card demo` (README screenshot, trying the tool)."""
import time

from .util import INFO, OK, WARN, result


def demo_snapshots(now=None):
    now = now or time.time()
    start = now - 6 * 86400
    attacks = [182, 240, 96, 310, 151, 205, 58]
    bans = [9, 12, 5, 16, 8, 11, 3]
    snaps = []
    for i, (n, b) in enumerate(zip(attacks, bans)):
        t = start + i * 86400
        last = i == 6
        res = [
            result("ssh.attacks", "security", INFO, "", kind="event"),
            result("fail2ban", "security", OK, "", kind="event", detail="jails: sshd, nginx-botsearch"),
            result("firewall", "security", OK, "The firewall is on (ufw)."),
            result("ports", "security", OK, "Open ports unchanged: 22/tcp (SSH), 80/tcp (website), 443/tcp (secure website)."),
            result("users", "security", OK, "No new accounts. 2 accounts can log in.", detail="deploy, maria"),
            result("updates.security", "security", WARN, "3 security fixes waiting to be installed.",
                   why="Known holes stay open until the fixes are installed.",
                   action="Install the updates (and reboot if asked).", detail="openssl, libssl3, sudo") if last else
            result("updates", "security", OK, "The system is fully up to date."),
            result("updates.auto", "security", INFO, "Updates are installed by hand, not automatically.",
                   action="Consider automatic security updates (unattended-upgrades / dnf-automatic)."),
            result("backup:shop", "backups", OK, "Last backup 4 hours ago, it worked.", detail="shop snapshot 3fa91c2e"),
            result("restore", "backups", OK, "Restore test passed 9 days ago: 1,284 files restored and identical.",
                   detail="path /etc"),
            result("site:https://shop.example.com", "website", OK, "shop.example.com is online (0.4 s).",
                   detail="HTTP 200 in 412 ms"),
            result("ssl:shop.example.com", "website", WARN, "The SSL certificate of shop.example.com expires in 12 days.",
                   why="When it expires, browsers block the site.",
                   action="Renew it now and check that automatic renewal works.", detail="issuer Let's Encrypt"),
            result("domain:example.com", "website", OK, "Domain example.com is registered for 231 more days."),
            result("spf:example.com", "email", OK, "example.com: SPF is set up.", detail="v=spf1 include:_spf.google.com ~all"),
            result("dmarc:example.com", "email", INFO,
                   "example.com: DMARC is in monitoring mode (p=none): it does not stop fake emails yet.",
                   action="After checking the reports, move to p=quarantine.", detail="v=DMARC1; p=none; rua=mailto:dmarc@example.com"),
            result("dkim:example.com", "email", OK, "example.com: DKIM signing key found (google)."),
            result("bl:203.0.113.10", "email", OK, "The server address 203.0.113.10 is on no spam blacklist."),
            result("disk", "server", OK, "Disk space is fine (48% used, 21.3 GB free)."),
            result("memory", "server", OK, "Memory is fine (61% free of 4.1 GB)."),
            result("services", "server", OK, "All services are running (nginx, postgresql, shop-app)."),
        ]
        if i == 3:
            res.append(result("ssh.logins", "security", INFO, "2 logins, all from known addresses.", kind="event"))
        snaps.append({
            "time": t, "since": t - 86400, "version": "demo",
            "host": {"hostname": "shop-web-01", "os": "Ubuntu 22.04.5 LTS", "kernel": "5.15.0-126-generic"},
            "results": res,
            "metrics": {
                "security": {"ssh_attempts": n, "bans": b, "ssh_top_ips": [["198.51.100.23", n // 3], ["192.0.2.77", n // 5]],
                             "security_updates": 3 if last else 0, "updates": 5 if last else 0},
                "backups": {"backup_ok": True},
                "website": {"sites": {"https://shop.example.com": {"code": 200, "ms": 412, "ssl_days": 12 - (6 - i) * 0}}},
                "email": {"domains": {"example.com": {}}},
                "server": {"disks": {"/": {"pct": 48, "free_gb": 21.3}}},
            },
        })
    events = [
        {"type": "alert", "id": "site:https://shop.example.com", "state": "problem", "time": start + 2 * 86400 + 3600 * 14},
        {"type": "alert", "id": "site:https://shop.example.com", "state": "resolved", "time": start + 2 * 86400 + 3600 * 14 + 22 * 60},
    ]
    return snaps, events
