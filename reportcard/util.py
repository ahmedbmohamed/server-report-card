"""Small helpers shared by the checks. Python 3.6+ and the standard library only."""
import os
import subprocess

OK, INFO, WARN, CRIT, UNKNOWN = "ok", "info", "warn", "crit", "unknown"
SEVERITY = {OK: 0, INFO: 1, UNKNOWN: 2, WARN: 3, CRIT: 4}


def worst(statuses, default=OK):
    statuses = list(statuses)
    if not statuses:
        return default
    return max(statuses, key=lambda s: SEVERITY.get(s, 0))


def result(id, area, status, title, why="", action="", detail="", kind="state", data=None):
    """One finding.

    title  -- one plain-English sentence for the owner
    why    -- why it matters (short), only for problems
    action -- the next step
    detail -- technical detail for the IT person
    kind   -- "state" (latest value counts) or "event" (happened during the week)
    """
    return {"id": id, "area": area, "status": status, "title": title, "why": why,
            "action": action, "detail": detail, "kind": kind, "data": data or {}}


def run(cmd, timeout=60, env=None):
    """Run a command. Returns (returncode, stdout, stderr); 127 if the program is missing."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "%s: not installed" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "%s: timed out after %ss" % (cmd[0], timeout)
    except OSError as exc:
        return 126, "", str(exc)


def which(name):
    for d in os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").split(os.pathsep) + ["/usr/sbin", "/sbin"]:
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def read(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return default


def plural(n, word, many=None):
    return "%s %s" % (fmt_int(n), word if n == 1 else (many or word + "s"))


def fmt_int(n):
    return "{:,}".format(int(n))


def human_age(seconds):
    seconds = max(0, int(seconds))
    if seconds < 3600:
        return plural(max(1, seconds // 60), "minute")
    if seconds < 2 * 86400:
        return plural(seconds // 3600, "hour")
    return plural(seconds // 86400, "day")


def os_family():
    if os.path.exists("/etc/debian_version"):
        return "debian"
    if os.path.exists("/etc/redhat-release") or os.path.exists("/etc/fedora-release"):
        return "redhat"
    return "other"


def os_name():
    for line in read("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "Linux"
