"""Email: SPF, DKIM, DMARC, MX still correct? Did they change? Is the server IP blacklisted?"""
import hashlib

from .. import dnsmini
from ..util import CRIT, INFO, OK, UNKNOWN, WARN, result

AREA = "email"
COMMON_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim",
                    "smtp", "zoho", "protonmail", "mailjet", "sendgrid", "pm", "fm1", "mxvault"]
DNSBLS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "psbl.surriel.com"]


def spf_verdict(records):
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return CRIT, "No SPF record: receiving servers cannot check who may send your emails.", "Add an SPF record."
    if len(spf) > 1:
        return CRIT, "Two SPF records: this breaks SPF and emails can be rejected.", "Merge them into one SPF record."
    r = spf[0].lower()
    tokens = r.split()
    if "+all" in tokens or "all" in tokens:
        return CRIT, "SPF allows the whole internet to send as you (+all).", "Change +all to ~all or -all."
    if "?all" in tokens:
        return WARN, "SPF is too weak (?all): it protects nothing.", "End the SPF record with ~all or -all."
    if r.count("include:") + r.count("a:") + r.count("mx") + r.count("exists:") + r.count("redirect=") > 10:
        return WARN, "SPF has many DNS lookups and may exceed the limit of 10.", "Simplify the SPF record."
    return OK, "SPF is set up.", ""


def dmarc_verdict(records):
    d = [r for r in records if r.lower().replace(" ", "").startswith("v=dmarc1")]
    if not d:
        return WARN, "No DMARC record: Gmail and Yahoo may send your emails to spam.", "Add a DMARC record (start with p=none)."
    tags = dict(t.strip().split("=", 1) for t in d[0].split(";") if "=" in t)
    p = tags.get("p", "").strip().lower()
    if p == "none":
        return INFO, "DMARC is in monitoring mode (p=none): it does not stop fake emails yet.", \
            "After checking the reports, move to p=quarantine."
    if p in ("quarantine", "reject"):
        return OK, "DMARC is set up and enforced (p=%s)." % p, ""
    return WARN, "The DMARC record is invalid.", "Fix the DMARC record."


def check_domain(ctx, domain, metrics):
    out = []
    try:
        mx = dnsmini.query(domain, "MX")
        txt = dnsmini.query(domain, "TXT")
        dmarc = dnsmini.query("_dmarc." + domain, "TXT")
    except dnsmini.DNSError as exc:
        return [result("email:" + domain, AREA, UNKNOWN, "I could not check the email records of %s." % domain, detail=str(exc))]
    selectors = ctx.cfg.list("email_dns", "dkim_selectors")
    dkim = {}
    for sel in selectors or COMMON_SELECTORS:
        try:
            recs = dnsmini.query("%s._domainkey.%s" % (sel, domain), "TXT")
        except dnsmini.DNSError:
            continue
        recs = [r for r in recs if "p=" in r.replace(" ", "")]
        if recs:
            dkim[sel] = recs[0]
        elif selectors:
            dkim[sel] = None

    spf = [r for r in txt if r.lower().startswith("v=spf1")]
    fingerprint = {"mx": sorted("%s %s" % x for x in mx), "spf": spf, "dmarc": dmarc,
                   "dkim": {k: hashlib.sha256((v or "").encode()).hexdigest()[:12] for k, v in sorted(dkim.items())}}
    metrics.setdefault("domains", {})[domain] = fingerprint

    if not mx:
        out.append(result("mx:" + domain, AREA, WARN, "%s has no mail server (MX) record: it cannot receive email." % domain,
                          action="Add MX records if this domain should receive email."))
    for key, (status, title, action) in (("spf", spf_verdict(txt)), ("dmarc", dmarc_verdict(dmarc))):
        out.append(result("%s:%s" % (key, domain), AREA, status, "%s: %s" % (domain, title),
                          why="" if status in (OK, INFO) else "Emails that fail these checks go to spam or are rejected.",
                          action=action, detail=" | ".join(spf if key == "spf" else dmarc)))
    found = sorted(k for k, v in dkim.items() if v)
    missing = sorted(k for k, v in dkim.items() if v is None)
    if missing:
        out.append(result("dkim:" + domain, AREA, CRIT, "%s: DKIM key missing for %s." % (domain, ", ".join(missing)),
                          why="Emails are not signed, so they look fake and go to spam.",
                          action="Publish the DKIM key again in DNS."))
    elif found:
        out.append(result("dkim:" + domain, AREA, OK, "%s: DKIM signing key found (%s)." % (domain, ", ".join(found))))
    else:
        out.append(result("dkim:" + domain, AREA, WARN, "%s: no DKIM key found." % domain,
                          why="Without DKIM, emails are more likely to go to spam.",
                          action="Set up DKIM, or add your DKIM selector to the config if it is already set up."))

    # Changes since last time: the classic "our emails suddenly go to spam" cause
    known = ctx.state.setdefault("email_dns", {})
    prev = known.get(domain)
    if prev and prev.get("fp") != fingerprint:
        what = [k.upper() for k in ("mx", "spf", "dmarc", "dkim") if prev["fp"].get(k) != fingerprint.get(k)]
        out.append(result("emailchange:" + domain, AREA, WARN, "%s: email DNS records changed (%s)." % (domain, ", ".join(what)),
                          why="A wrong change here is the most common reason emails suddenly go to spam.",
                          action="Check that this change was planned.", kind="event",
                          detail="before: %s" % prev["fp"]))
    known[domain] = {"fp": fingerprint, "time": ctx.now if not prev or prev.get("fp") != fingerprint else prev.get("time", ctx.now)}
    return out


def check_blacklists(ctx, metrics):
    out = []
    for ip in ctx.cfg.list("email_dns", "server_ips"):
        rev = ".".join(reversed(ip.split(".")))
        listed, unknown = [], []
        for bl in DNSBLS:
            try:
                ans = dnsmini.query("%s.%s" % (rev, bl), "A")
            except dnsmini.DNSError:
                unknown.append(bl)
                continue
            real = [a for a in ans if a.startswith("127.") and not a.startswith("127.255.255.")]
            if real:
                listed.append(bl)
            elif ans:
                unknown.append(bl)   # 127.255.255.x: the list refuses queries from public DNS resolvers
        metrics.setdefault("blacklists", {})[ip] = listed
        if listed:
            out.append(result("bl:" + ip, AREA, CRIT, "The server address %s is on a spam blacklist (%s)." % (ip, ", ".join(listed)),
                              why="Many companies reject every email from a blacklisted address.",
                              action="Find the cause (hacked account, open relay) and request removal."))
        else:
            out.append(result("bl:" + ip, AREA, OK, "The server address %s is on no spam blacklist." % ip,
                              detail="not checked: %s" % ", ".join(unknown) if unknown else ""))
    return out


def run(ctx):
    metrics = {}
    domains = ctx.cfg.list("email_dns", "domains")
    if not domains and not ctx.cfg.list("email_dns", "server_ips"):
        return [], metrics
    out = []
    for d in domains:
        out += check_domain(ctx, d, metrics)
    out += check_blacklists(ctx, metrics)
    return out, metrics

