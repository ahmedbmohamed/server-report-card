"""Website: is it up, is it fast, when does the SSL certificate and the domain name expire?"""
import json
import os
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from ..util import CRIT, INFO, OK, UNKNOWN, WARN, plural, result

AREA = "website"
CERT_ERRORS = (getattr(ssl, "SSLCertVerificationError", ssl.CertificateError), ssl.CertificateError)  # 3.7+ / 3.6
UA = "server-report-card/0.1 (+https://github.com/ahmedbmohamed/server-report-card)"


def fetch(url, timeout, verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            r.read(65536)
            return r.status, int((time.time() - t0) * 1000), None
    except urllib.error.HTTPError as e:
        return e.code, int((time.time() - t0) * 1000), None
    except Exception as e:  # noqa: BLE001 - any network error means "down"
        reason = getattr(e, "reason", e)
        return None, None, "%s" % reason


def _decode_der(der):
    """Read notAfter from a certificate we could not verify (self-signed, expired)."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(ssl.DER_cert_to_PEM_cert(der))
        name = fh.name
    try:
        return ssl._ssl._test_decode_cert(name)  # noqa: SLF001 - stdlib, no other way without extra packages
    finally:
        os.unlink(name)


def certificate(host, port=443, timeout=15):
    """Returns (days_left, problem, issuer)."""
    ctx = ssl.create_default_context()
    problem = None
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert = t.getpeercert()
    except CERT_ERRORS as e:
        problem = getattr(e, "verify_message", "") or str(e)
        cert = None
    except ssl.SSLError as e:
        if "CERTIFICATE_VERIFY_FAILED" not in str(e):
            return None, "TLS error: %s" % e, ""
        problem, cert = str(e), None
    except OSError as e:
        return None, "could not connect: %s" % e, ""
    if cert is None:
        nctx = ssl.create_default_context()
        nctx.check_hostname = False
        nctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                with nctx.wrap_socket(s, server_hostname=host) as t:
                    cert = _decode_der(t.getpeercert(binary_form=True))
        except Exception as e:  # noqa: BLE001
            return None, problem or str(e), ""
    left = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
    issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
    return left, problem, issuer


def domain_expiry(domain, timeout=15):
    """Registration expiry date from RDAP (the modern WHOIS). None if unknown."""
    req = urllib.request.Request("https://rdap.org/domain/" + domain, headers={"User-Agent": UA,
                                                                            "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - many TLDs have no RDAP: just skip
        return None
    from .backups import parse_time
    for ev in data.get("events", []):
        if ev.get("eventAction") == "expiration":
            try:
                return parse_time(ev["eventDate"])
            except (ValueError, KeyError):
                return None
    return None


def registrable(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def check_url(ctx, url, metrics):
    cfg = ctx.cfg
    timeout = cfg.int("website", "timeout")
    verify = cfg.bool("website", "verify_ssl")
    out = []
    u = urllib.parse.urlparse(url)
    code, ms, err = fetch(url, timeout, verify)
    if err and verify and "CERTIFICATE_VERIFY_FAILED" in err:
        code, ms, err2 = fetch(url, timeout, False)      # site works, certificate problem reported below
        err = err2
    m = metrics.setdefault("sites", {})[url] = {"code": code, "ms": ms, "error": err}
    if err or code is None:
        out.append(result("site:" + url, AREA, CRIT, "%s is DOWN." % u.netloc,
                          why="Customers cannot reach your website.", action="Fix it now.", detail=err))
    elif code >= 500:
        out.append(result("site:" + url, AREA, CRIT, "%s shows an error page (code %s)." % (u.netloc, code),
                          why="Visitors see an error instead of your website.", action="Check the web server and app logs."))
    elif code >= 400:
        out.append(result("site:" + url, AREA, WARN, "%s answers with code %s." % (url, code),
                          action="Check the address is right and the page exists."))
    elif ms > cfg.int("website", "slow_ms"):
        out.append(result("site:" + url, AREA, WARN, "%s is slow (%.1f seconds)." % (u.netloc, ms / 1000.0),
                          why="Slow sites lose visitors and Google ranking.", action="Look at caching and server load."))
    else:
        out.append(result("site:" + url, AREA, OK, "%s is online (%.1f s)." % (u.netloc, ms / 1000.0),
                          detail="HTTP %s in %d ms" % (code, ms)))
    if u.scheme == "https":
        left, problem, issuer = certificate(u.hostname, u.port or 443, timeout)
        m["ssl_days"] = None if left is None else round(left, 1)
        w, c = cfg.int("website", "ssl_warn_days"), cfg.int("website", "ssl_crit_days")
        if left is None:
            out.append(result("ssl:" + u.hostname, AREA, UNKNOWN, "I could not read the SSL certificate of %s." % u.hostname,
                              detail=problem))
        elif left < 0:
            out.append(result("ssl:" + u.hostname, AREA, CRIT, "The SSL certificate of %s has EXPIRED." % u.hostname,
                              why="Browsers show a big security warning and most visitors leave.",
                              action="Renew the certificate now."))
        elif problem and verify:
            out.append(result("ssl:" + u.hostname, AREA, CRIT, "Browsers do not trust the SSL certificate of %s." % u.hostname,
                              why="Visitors see a security warning.", action="Install a valid certificate (for example Let's Encrypt).",
                              detail=problem))
        elif left < w:
            out.append(result("ssl:" + u.hostname, AREA, CRIT if left < c else WARN,
                              "The SSL certificate of %s expires in %s." % (u.hostname, plural(int(left), "day")),
                              why="When it expires, browsers block the site.",
                              action="Renew it now and check that automatic renewal works.",
                              detail="issuer %s" % issuer))
        else:
            out.append(result("ssl:" + u.hostname, AREA, OK, "SSL certificate of %s valid for %s more days." % (u.hostname, int(left)),
                              detail="%s, issuer %s%s" % (u.hostname, issuer, " (not verified)" if problem else "")))
    return out


def check_domains(ctx, metrics):
    cfg = ctx.cfg
    domains = cfg.list("website", "domains")
    if not domains:
        domains = sorted({registrable(urllib.parse.urlparse(u).hostname or "") for u in cfg.list("website", "urls")})
        domains = [d for d in domains if d and "." in d and not d.replace(".", "").isdigit() and not d.endswith((".local", ".lan", ".test"))]
    out = []
    warn = cfg.int("website", "domain_warn_days")
    for d in domains:
        exp = domain_expiry(d)
        if exp is None:
            continue
        left = (exp - ctx.now) / 86400
        metrics.setdefault("domains", {})[d] = round(left)
        if left < warn:
            out.append(result("domain:" + d, AREA, CRIT if left < 7 else WARN,
                              "The domain name %s expires in %s." % (d, plural(int(left), "day")),
                              why="If it expires, the website AND the email stop working, and someone else can buy it.",
                              action="Renew the domain (and turn on auto-renew) at your registrar."))
        else:
            out.append(result("domain:" + d, AREA, OK, "Domain %s is registered for %s more days." % (d, int(left))))
    return out


def run(ctx):
    metrics = {}
    urls = ctx.cfg.list("website", "urls")
    if not urls:
        return [result("website", AREA, INFO, "No website is monitored.", action="Add your website address to the config.")], metrics
    out = []
    for url in urls:
        out += check_url(ctx, url, metrics)
    if not ctx.quick:
        out += check_domains(ctx, metrics)
    return out, metrics
