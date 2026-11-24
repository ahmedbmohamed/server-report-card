"""Security: SSH attacks and logins, users, open ports, updates, fail2ban, firewall."""
import collections
import glob
import os
import re

from ..util import CRIT, INFO, OK, UNKNOWN, WARN, os_family, plural, read, result, which
from ..util import run as sh

AREA = "security"

# ---------------------------------------------------------------- SSH log parsing
RE_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9A-Fa-f:.]+)")
RE_FAILED = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam|none) for "
                       r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+)")
RE_CLOSED = re.compile(r"Connection (?:closed|reset) by authenticating user (?P<user>\S+) "
                       r"(?P<ip>[0-9A-Fa-f:.]+) port \d+ \[preauth\]")
RE_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+)")
RE_PREFIX = re.compile(r"^(?P<ts>\S+) \S+ [^:\[]+(?:\[\d+\])?: (?P<msg>.*)$")


def parse_ssh(lines):
    """Count attack attempts and successful logins in sshd log lines (journalctl -o short-iso)."""
    attempts = 0
    ips, users = collections.Counter(), collections.Counter()
    logins = []
    for line in lines:
        m = RE_PREFIX.match(line)
        ts, msg = (m.group("ts"), m.group("msg")) if m else ("", line)
        a = RE_ACCEPTED.search(msg)
        if a:
            logins.append({"time": ts, "user": a.group("user"), "ip": a.group("ip"), "method": a.group("method")})
            continue
        f = RE_INVALID.search(msg)
        if not f:
            f = RE_FAILED.search(msg)
            if f and f.group("invalid"):
                continue          # already counted by the "Invalid user" line
        if not f:
            f = RE_CLOSED.search(msg)
        if f:
            attempts += 1
            ips[f.group("ip")] += 1
            users[f.group("user") or "(empty)"] += 1
    return {"attempts": attempts, "top_ips": ips.most_common(5), "top_users": users.most_common(5),
            "unique_ips": len(ips), "logins": logins}


def ssh_lines(since, until):
    rc, out, err = sh(["journalctl", "_COMM=sshd", "_COMM=sshd-session", "--since", "@%d" % since,
                        "--until", "@%d" % until, "-o", "short-iso", "--no-pager", "-q"], timeout=120)
    if rc == 0:
        return out.splitlines(), None
    return [], (err or "journalctl failed").strip()


def sshd_settings():
    rc, out, _ = sh(["sshd", "-T"], timeout=20)
    if rc != 0:
        rc, out, _ = sh(["/usr/sbin/sshd", "-T"], timeout=20)
    if rc != 0:
        return {}
    s = {}
    for line in out.splitlines():
        k, _, v = line.partition(" ")
        s[k.lower()] = v.strip().lower()
    return s


def check_ssh(ctx, metrics):
    out = []
    lines, err = ssh_lines(ctx.since, ctx.now)
    if err:
        out.append(result("ssh.log", AREA, UNKNOWN, "I could not read the login log.", detail=err))
        return out
    p = parse_ssh(lines)
    metrics.update({"ssh_attempts": p["attempts"], "ssh_unique_ips": p["unique_ips"],
                    "ssh_top_ips": p["top_ips"], "ssh_top_users": p["top_users"], "logins": p["logins"]})
    sshd = sshd_settings()
    pw = sshd.get("passwordauthentication") == "yes"
    root = sshd.get("permitrootlogin", "")
    detail = "Top sources: %s" % (", ".join("%s (%d)" % x for x in p["top_ips"]) or "none")
    if p["attempts"]:
        status = WARN if pw else INFO
        title = "%s to break in through SSH, from %s." % (
            plural(p["attempts"], "attempt"), plural(p["unique_ips"], "address", "addresses"))
        if not pw:
            title += " All failed: the server only accepts keys, not passwords."
        out.append(result("ssh.attacks", AREA, status, title, kind="event", detail=detail,
                          why="Password logins are allowed, so a weak password could be guessed." if pw else "",
                          action="Turn off password logins and use SSH keys only." if pw else ""))
    else:
        out.append(result("ssh.attacks", AREA, OK, "No break-in attempts through SSH.", kind="event"))
    if sshd and root in ("yes",):
        out.append(result("ssh.root", AREA, WARN, "The admin account (root) can log in directly over the internet.",
                          why="Root is the first account attackers try.",
                          action="Set PermitRootLogin to no (or prohibit-password).",
                          detail="sshd -T: permitrootlogin %s" % root))

    # Successful logins: new addresses and root logins deserve a look
    known = set(ctx.state.setdefault("known_login_ips", []))
    first_run = not ctx.state.get("logins_baselined")
    new, roots = [], []
    for lg in p["logins"]:
        if lg["user"] == "root":
            roots.append(lg)
        if lg["ip"] not in known and not first_run:
            new.append(lg)
        known.add(lg["ip"])
    ctx.state["known_login_ips"] = sorted(known)[-200:]
    ctx.state["logins_baselined"] = True
    who = ", ".join(sorted({"%s from %s" % (lg["user"], lg["ip"]) for lg in p["logins"]})) or "none"
    if new:
        out.append(result("ssh.new_ip", AREA, WARN,
                          "Someone logged in from a new address: %s." % ", ".join(
                              sorted({"%s from %s" % (lg["user"], lg["ip"]) for lg in new})),
                          why="A login from an unknown place can mean a stolen password or key.",
                          action="Check this was you or your team. If not, tell your administrator now.",
                          kind="event", detail="Logins: " + who))
    if roots:
        out.append(result("ssh.root_login", AREA, WARN, "Someone logged in directly as root %s." % plural(len(roots), "time"),
                          why="Direct root logins leave no trace of who did what.",
                          action="Use personal accounts with sudo instead.", kind="event", detail="Logins: " + who))
    if p["logins"] and not new and not roots:
        out.append(result("ssh.logins", AREA, INFO, "%s, all from known addresses." % plural(len(p["logins"]), "login"),
                          kind="event", detail="Logins: " + who))
    return out


# ---------------------------------------------------------------- users
NOLOGIN = ("nologin", "false", "sync", "shutdown", "halt")


def login_users(passwd_text):
    users = {}
    for line in passwd_text.splitlines():
        parts = line.split(":")
        if len(parts) < 7 or line.startswith("#"):
            continue
        name, uid, shell = parts[0], parts[2], parts[6]
        try:
            uid = int(uid)
        except ValueError:
            continue
        if uid == 0 or (uid >= 1000 and uid != 65534 and not shell.endswith(NOLOGIN)):
            users[name] = uid
    return users


def admin_members(group_text):
    members = set()
    for line in group_text.splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[0] in ("sudo", "wheel", "admin"):
            members.update(m for m in parts[3].split(",") if m)
    return members


def check_users(ctx):
    users = login_users(read("/etc/passwd"))
    admins = admin_members(read("/etc/group"))
    base = ctx.state.get("users")
    base_admins = set(ctx.state.get("admins", []))
    ctx.state["users"] = users
    ctx.state["admins"] = sorted(admins)
    if base is None:
        return [result("users", AREA, OK, "%s can log in (%s). I will tell you when this changes." % (
            plural(len(users), "account"), ", ".join(sorted(users))), detail="admins: %s" % ", ".join(sorted(admins)))]
    out = []
    added = sorted(set(users) - set(base))
    extra_root = sorted(u for u in added if users[u] == 0)
    if extra_root:
        out.append(result("users.root", AREA, CRIT, "A second admin-level account appeared: %s." % ", ".join(extra_root),
                          why="Attackers create hidden root accounts to come back later.",
                          action="Call your administrator today.", kind="event"))
    if added:
        out.append(result("users.new", AREA, WARN, "New login account created: %s." % ", ".join(added),
                          why="Every account is a way in.", action="Check this was planned.", kind="event"))
    new_admins = sorted(admins - base_admins)
    if new_admins:
        out.append(result("users.admin", AREA, WARN, "New admin rights given to: %s." % ", ".join(new_admins),
                          why="Admin accounts can change everything on the server.",
                          action="Check this was planned.", kind="event"))
    removed = sorted(set(base) - set(users))
    if removed:
        out.append(result("users.removed", AREA, INFO, "Account removed: %s." % ", ".join(removed), kind="event"))
    if not out:
        out.append(result("users", AREA, OK, "No new accounts. %s can log in." % plural(len(users), "account"),
                          detail=", ".join(sorted(users))))
    return out


# ---------------------------------------------------------------- open ports
RISKY = {3306: "MySQL/MariaDB database", 5432: "PostgreSQL database", 6379: "Redis", 27017: "MongoDB",
         9200: "Elasticsearch", 11211: "Memcached", 2375: "Docker API", 5900: "VNC remote desktop",
         3389: "Remote desktop", 21: "FTP (unencrypted)", 23: "Telnet (unencrypted)", 445: "Windows file sharing"}
NAMES = {22: "SSH", 80: "website", 443: "secure website", 8080: "web app", 8443: "web app", 25: "email (SMTP)", 587: "email submission",
         465: "email (SMTPS)", 993: "email (IMAPS)", 143: "email (IMAP)", 110: "email (POP3)", 995: "email (POP3S)",
         53: "DNS", 123: "time sync"}


def parse_ss(text):
    """Public listening sockets from `ss -H -tulnp`: {"22/tcp": "sshd"}."""
    ports = {}
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        proto = cols[0]
        local = cols[4]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        if not port.isdigit() or addr.startswith("127.") or addr in ("::1", "localhost"):
            continue
        if proto == "udp" and int(port) in (68, 546, 5353, 323):   # DHCP client, mDNS, chrony local
            continue
        m = re.search(r'users:\(\("([^"]+)"', line)
        ports["%s/%s" % (port, proto)] = m.group(1) if m else ""
    return ports


def check_ports(ctx, metrics):
    rc, out, err = sh(["ss", "-H", "-tulnp"], timeout=20)
    if rc != 0:
        return [result("ports", AREA, UNKNOWN, "I could not list the open ports.", detail=err)]
    ignore = set(ctx.cfg.list("security", "ignore_ports"))
    ports = {k: v for k, v in parse_ss(out).items() if k not in ignore}
    metrics["ports"] = ports
    base = ctx.state.get("ports")
    ctx.state["ports"] = ports
    res = []

    def label(k):
        n = int(k.split("/")[0])
        name = RISKY.get(n) or NAMES.get(n) or (ports.get(k) or "unknown program")
        return "%s (%s)" % (k, name)

    risky = sorted(k for k in ports if int(k.split("/")[0]) in RISKY and k.endswith("tcp"))
    if risky:
        res.append(result("ports.risky", AREA, WARN, "%s should not be reachable from the internet: %s." % (
            "This service" if len(risky) == 1 else "These services", ", ".join(label(k) for k in risky)),
            why="Databases and remote-desktop ports are attacked all day long.",
            action="Make the service listen on 127.0.0.1 only, or block the port in the firewall.",
            detail="Listening on all addresses. The firewall may still block it; check from outside."))
    if base is not None:
        new = sorted(set(ports) - set(base))
        if new:
            res.append(result("ports.new", AREA, WARN, "New open port: %s." % ", ".join(label(k) for k in new),
                              why="A new open port is a new door into the server.",
                              action="Check this was planned (new app or service).", kind="event"))
    if not res:
        res.append(result("ports", AREA, OK, ("Open ports: %s." if base is None else "Open ports unchanged: %s.") % (
            ", ".join(label(k) for k in sorted(ports, key=lambda x: int(x.split("/")[0]))) or "none"),
            detail=" ".join(sorted(ports))))
    return res


# ---------------------------------------------------------------- updates
def apt_updates():
    rc, out, err = sh(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=120)
    if rc != 0:
        return None, None, err.strip()
    total, sec = set(), set()
    for line in out.splitlines():
        if line.startswith("Inst "):
            pkg = line.split()[1]
            total.add(pkg)
            if "-security" in line:
                sec.add(pkg)
    return sorted(total), sorted(sec), None


def dnf_updates():
    tool = "dnf" if which("dnf") else "yum"
    total, sec = set(), set()
    rc, out, err = sh([tool, "-q", "--cacheonly", "check-update"], timeout=180)
    if rc not in (0, 100):
        rc, out, err = sh([tool, "-q", "check-update"], timeout=180)
    if rc not in (0, 100):
        return None, None, (err or out).strip()[-300:]
    for line in out.splitlines():
        cols = line.split()
        if len(cols) == 3 and "." in cols[0] and not line.startswith(" "):
            if cols[0].lower().startswith(("obsoleting", "security:")):
                continue
            total.add(cols[0].rsplit(".", 1)[0])
    rc, out, _ = sh([tool, "-q", "--cacheonly", "updateinfo", "list", "--security"], timeout=180)
    if rc != 0:
        rc, out, _ = sh([tool, "-q", "updateinfo", "list", "--security"], timeout=180)
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 3 and "/Sec" in cols[1]:
            sec.add(re.sub(r"-[^-]+-[^-]+$", "", cols[2]))
    return sorted(total), sorted(sec), None


def reboot_needed():
    if os.path.exists("/var/run/reboot-required"):
        return True, read("/var/run/reboot-required.pkgs").replace("\n", " ").strip()
    if which("rpm"):
        rc, out, _ = sh(["rpm", "-q", "--last", "kernel-core"], timeout=30)
        if rc != 0:
            rc, out, _ = sh(["rpm", "-q", "--last", "kernel"], timeout=30)
        if rc == 0 and out.strip():
            newest = re.sub(r"^kernel(-core)?-", "", out.split()[0])
            running = os.uname().release
            if newest != running:
                return True, "running %s, installed %s" % (running, newest)
    return False, ""


def auto_updates():
    if os_family() == "debian":
        conf = "".join(read(p) for p in glob.glob("/etc/apt/apt.conf.d/*"))
        return bool(re.search(r'Unattended-Upgrade\s+"1"', conf)) and os.path.exists("/usr/bin/unattended-upgrade")
    rc, out, _ = sh(["systemctl", "is-enabled", "dnf-automatic.timer", "dnf-automatic-install.timer"], timeout=10)
    return "enabled" in out


def check_updates(ctx, metrics):
    fam = os_family()
    if fam == "debian":
        total, sec, err = apt_updates()
    elif fam == "redhat":
        total, sec, err = dnf_updates()
    else:
        return [result("updates", AREA, UNKNOWN, "I could not check for updates on this system.")]
    if err:
        return [result("updates", AREA, UNKNOWN, "I could not check for updates.", detail=err)]
    metrics["updates"] = len(total)
    metrics["security_updates"] = len(sec)
    auto = auto_updates()
    first = ctx.state.setdefault("security_pending_since", {})
    for p in list(first):
        if p not in sec:
            del first[p]
    for p in sec:
        first.setdefault(p, ctx.now)
    oldest = max([(ctx.now - t) / 86400 for t in first.values()] or [0])
    out = []
    if sec:
        status = CRIT if oldest >= 14 else WARN
        out.append(result("updates.security", AREA, status, "%s waiting to be installed%s." % (
            plural(len(sec), "security fix", "security fixes"),
            " for %d days" % oldest if oldest >= 3 else ""),
            why="Known holes stay open until the fixes are installed.",
            action="Install the updates (and reboot if asked).",
            detail=", ".join(sec[:30]) + (" ..." if len(sec) > 30 else "")))
    elif total:
        out.append(result("updates", AREA, INFO, "All security fixes installed (%s optional)." % plural(len(total), "update"),
                          detail=", ".join(total[:30])))
    else:
        out.append(result("updates", AREA, OK, "The system is fully up to date."))
    out.append(result("updates.auto", AREA, OK if auto else INFO,
                      "Security updates install automatically." if auto else "Updates are installed by hand, not automatically.",
                      action="" if auto else "Consider automatic security updates (unattended-upgrades / dnf-automatic)."))
    need, why = reboot_needed()
    if need:
        out.append(result("reboot", AREA, WARN, "The server needs a restart to finish installing updates.",
                          why="Until the restart, the server keeps running the old, unpatched version.",
                          action="Plan a short restart at a quiet time.", detail=why))
    return out


# ---------------------------------------------------------------- fail2ban & firewall
def fail2ban_status():
    rc, out, err = sh(["fail2ban-client", "status"], timeout=20)
    if rc == 127:
        return None, "not installed"
    if rc != 0:
        return False, (err or out).strip()
    m = re.search(r"Jail list:\s*(.*)", out)
    jails = [j.strip() for j in (m.group(1) if m else "").split(",") if j.strip()]
    total, current = 0, 0
    for j in jails:
        rc, o, _ = sh(["fail2ban-client", "status", j], timeout=20)
        t = re.search(r"Total banned:\s*(\d+)", o)
        c = re.search(r"Currently banned:\s*(\d+)", o)
        total += int(t.group(1)) if t else 0
        current += int(c.group(1)) if c else 0
    return True, {"jails": jails, "total": total, "current": current}


def check_fail2ban(ctx, metrics):
    ok, info = fail2ban_status()
    required = ctx.cfg.bool("security", "require_fail2ban")
    if ok is None:
        return [result("fail2ban", AREA, WARN if required else INFO, "No automatic blocking of attackers (Fail2ban is not installed).",
                       why="Without it, attackers can keep guessing passwords for as long as they want.",
                       action="Install Fail2ban.")]
    if not ok:
        return [result("fail2ban", AREA, WARN if required else UNKNOWN, "Fail2ban is installed but not running.",
                       why="Attackers are not being blocked.", action="Start Fail2ban.", detail=str(info))]
    prev = ctx.state.get("fail2ban_total")
    total = info["total"]
    new_bans = total if prev is None or total < prev else total - prev   # counter resets when fail2ban restarts
    if prev is None:
        new_bans = info["current"]
    ctx.state["fail2ban_total"] = total
    metrics["bans"] = new_bans
    return [result("fail2ban", AREA, OK, "Fail2ban is protecting the server: %s blocked, %s blocked right now." % (
        plural(new_bans, "address", "addresses"), info["current"]), kind="event",
        detail="jails: %s" % ", ".join(info["jails"]))]


def firewall_state():
    if which("ufw"):
        rc, out, _ = sh(["ufw", "status"], timeout=20)
        if "Status: active" in out:
            return True, "ufw"
    if which("firewall-cmd"):
        rc, out, _ = sh(["firewall-cmd", "--state"], timeout=20)
        if out.strip() == "running":
            return True, "firewalld"
    if which("nft"):
        rc, out, _ = sh(["nft", "list", "ruleset"], timeout=20)
        if rc == 0 and re.search(r"\bhook input\b.*\bpolicy drop\b", out):
            return True, "nftables"
    rc, out, _ = sh(["iptables", "-S", "INPUT"], timeout=20)
    if rc == 0 and ("-P INPUT DROP" in out or " -j DROP" in out or " -j REJECT" in out):
        return True, "iptables"
    return False, ""


def check_firewall(ctx):
    on, name = firewall_state()
    if on:
        return [result("firewall", AREA, OK, "The firewall is on (%s)." % name)]
    req = ctx.cfg.bool("security", "require_firewall")
    return [result("firewall", AREA, WARN if req else INFO, "The firewall is off.",
                   why="Every service on the server can be reached from the internet.",
                   action="Turn on the firewall and allow only the ports you need.")]


def run(ctx):
    metrics = {}
    out = check_ssh(ctx, metrics)
    out += check_fail2ban(ctx, metrics)
    out += check_firewall(ctx)
    out += check_ports(ctx, metrics)
    out += check_users(ctx)
    if not ctx.quick:
        out += check_updates(ctx, metrics)
    return out, metrics
