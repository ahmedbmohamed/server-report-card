"""The checks. Each module has run(ctx) -> (list of results, dict of metrics)."""
import time
import traceback

from ..util import UNKNOWN, result
from . import backups, email_dns, security, system, website

AREAS = [
    ("security", "Security", security),
    ("backups", "Backups", backups),
    ("website", "Website", website),
    ("email", "Email", email_dns),
    ("server", "Server", system),
]


class Context:
    def __init__(self, cfg, state, since, now=None, quick=False):
        self.cfg = cfg
        self.state = state          # persisted between runs (baselines, counters)
        self.since = since          # start of the period this run covers
        self.now = now or time.time()
        self.quick = quick          # hourly alert run: only fast checks


def run_all(ctx, only=None):
    results, metrics = [], {}
    for key, label, mod in AREAS:
        if only and key not in only:
            continue
        try:
            r, m = mod.run(ctx)
        except Exception as exc:  # a broken check must never stop the report
            r = [result(key + ".error", key, UNKNOWN, "The %s check could not run." % label.lower(),
                        action="Ask your administrator to look at the technical details.",
                        detail="%s: %s\n%s" % (exc.__class__.__name__, exc, traceback.format_exc(limit=3)))]
            m = {}
        results.extend(r)
        metrics[key] = m
    return results, metrics
