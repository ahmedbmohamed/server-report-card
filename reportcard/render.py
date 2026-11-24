"""Render the report: an email-safe HTML page and a short plain-text version (Telegram, terminal)."""
import html
import time

from .util import CRIT, INFO, OK, UNKNOWN, WARN

ICON = {OK: "✅", INFO: "ℹ️", WARN: "⚠️", CRIT: "❌", UNKNOWN: "❔"}
COLOR = {OK: "#1a7f37", INFO: "#3b6ea8", WARN: "#b35900", CRIT: "#c62828", UNKNOWN: "#6b7280"}
SOFT = {OK: "#e8f5ec", INFO: "#eaf1f9", WARN: "#fff4e5", CRIT: "#fdecec", UNKNOWN: "#f2f3f5"}
LABEL = {CRIT: "URGENT", WARN: "TO CHECK", UNKNOWN: "UNKNOWN", INFO: "INFO", OK: "OK"}
BIG = {OK: "\U0001F7E2", WARN: "\U0001F7E0", CRIT: "\U0001F534"}
FONT = "-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif"


def e(s):
    return html.escape(str(s or ""), quote=True)


def period_text(rep):
    a, b = rep["period"]
    fa, fb = time.localtime(a), time.localtime(b)
    if fa[:3] == fb[:3]:
        return time.strftime("%-d %B %Y", fb)
    if fa.tm_mon == fb.tm_mon and fa.tm_year == fb.tm_year:
        return "%d–%d %s" % (fa.tm_mday, fb.tm_mday, time.strftime("%B %Y", fb))
    return "%s – %s" % (time.strftime("%-d %b", fa), time.strftime("%-d %b %Y", fb))


def subject(rep):
    word = {OK: "All good", WARN: "Needs a look", CRIT: "ACTION NEEDED"}[rep["overall"]]
    return "%s %s – weekly server report for %s (%s/100)" % (BIG[rep["overall"]], word, rep["server_name"], rep["score"])


def chart(rows):
    if not rows or not any(n for _, n in rows):
        return ""
    top = max(n for _, n in rows) or 1
    cells = []
    for day, n in rows:
        h = max(2, int(70.0 * n / top))
        cells.append(
            '<td valign="bottom" align="center" style="padding:0 4px;font:11px %s;color:#6b7280">'
            '<div style="font-size:11px;color:#374151;margin-bottom:3px">%s</div>'
            '<div style="width:28px;height:%dpx;background:#94a3b8;border-radius:3px 3px 0 0"></div>'
            '<div style="margin-top:4px">%s</div></td>' % (FONT, n, h, e(day)))
    return ('<h3 style="font:600 15px %s;color:#111827;margin:28px 0 8px">Break-in attempts per day</h3>'
            '<table role="presentation" cellpadding="0" cellspacing="0" style="height:110px"><tr>%s</tr></table>'
            '<p style="font:12px %s;color:#6b7280;margin:6px 0 0">This is normal internet noise: bots try every server, '
            'all day. What matters is that none got in.</p>') % (FONT, "".join(cells), FONT)


def pill(status):
    return ('<span style="display:inline-block;padding:2px 8px;border-radius:10px;background:%s;color:%s;'
            'font:700 11px %s;letter-spacing:.5px">%s</span>') % (SOFT[status], COLOR[status], FONT, LABEL[status])


def html_report(rep):
    o = rep["overall"]
    p = []
    w = p.append
    w('<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
      '<title>%s</title></head>' % e(subject(rep)))
    w('<body style="margin:0;padding:0;background:#f3f4f6">')
    w('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6"><tr><td align="center" style="padding:24px 12px">')
    w('<table role="presentation" width="640" cellpadding="0" cellspacing="0" '
      'style="max-width:640px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden">')

    # header
    w('<tr><td style="padding:24px 28px 8px;font-family:%s">' % FONT)
    w('<div style="font:600 12px %s;letter-spacing:1px;color:#6b7280;text-transform:uppercase">Weekly server report · %s</div>'
      % (FONT, e(period_text(rep))))
    w('<div style="font:700 22px %s;color:#111827;margin-top:6px">%s</div>' % (FONT, e(rep["server_name"])))
    if rep["client_name"]:
        w('<div style="font:14px %s;color:#6b7280;margin-top:2px">%s</div>' % (FONT, e(rep["client_name"])))
    w('</td></tr>')

    # status card
    w('<tr><td style="padding:12px 28px 4px">')
    w('<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:%s;border-left:6px solid %s;border-radius:8px">'
      % (SOFT[o], COLOR[o]))
    w('<tr><td style="padding:18px 20px;font-family:%s">' % FONT)
    w('<div style="font:700 20px %s;color:%s">%s %s</div>' % (FONT, COLOR[o], BIG[o], e(rep["headline"])))
    w('<div style="font:14px %s;color:#374151;margin-top:6px">Health score <b>%s/100</b> (grade %s)%s</div>' % (
        FONT, rep["score"], rep["grade"],
        "" if rep["days_of_data"] >= 7 else " · based on %d day%s of data" % (rep["days_of_data"], "" if rep["days_of_data"] == 1 else "s")))
    w('</td></tr></table></td></tr>')

    w('<tr><td style="padding:8px 28px 24px;font-family:%s">' % FONT)
    # highlights
    if rep["highlights"]:
        w('<h3 style="font:600 15px %s;color:#111827;margin:20px 0 8px">Your week in 30 seconds</h3>' % FONT)
        w('<table role="presentation" cellpadding="0" cellspacing="0" width="100%">')
        for _, st, text in rep["highlights"]:
            w('<tr><td width="28" valign="top" style="padding:5px 0;font-size:15px">%s</td>'
              '<td style="padding:5px 0;font:15px %s;color:#111827">%s</td></tr>' % (ICON[st], FONT, e(text)))
        w('</table>')

    # problems
    if rep["problems"]:
        w('<h3 style="font:600 15px %s;color:#111827;margin:28px 0 8px">What needs attention</h3>' % FONT)
        for r in rep["problems"]:
            w('<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:8px;margin-bottom:10px">'
              '<tr><td style="padding:14px 16px;font-family:%s">' % FONT)
            w('%s<div style="font:600 15px %s;color:#111827;margin-top:8px">%s</div>' % (pill(r["status"]), FONT, e(r["title"])))
            if r.get("why"):
                w('<div style="font:14px %s;color:#4b5563;margin-top:4px">%s</div>' % (FONT, e(r["why"])))
            if r.get("action"):
                w('<div style="font:14px %s;color:#111827;margin-top:8px"><b>Next step:</b> %s</div>' % (FONT, e(r["action"])))
            w('</td></tr></table>')

    w(chart(rep["attacks_per_day"]))

    # full check-up
    w('<h3 style="font:600 15px %s;color:#111827;margin:28px 0 4px">Full check-up</h3>' % FONT)
    for s in rep["sections"]:
        w('<div style="font:700 13px %s;color:%s;text-transform:uppercase;letter-spacing:.6px;margin:16px 0 4px;'
          'border-bottom:1px solid #e5e7eb;padding-bottom:4px">%s %s</div>' % (FONT, COLOR[s["status"]], ICON[s["status"]], e(s["label"])))
        w('<table role="presentation" cellpadding="0" cellspacing="0" width="100%">')
        for r in s["items"]:
            w('<tr><td width="26" valign="top" style="padding:4px 0;font-size:13px">%s</td>'
              '<td style="padding:4px 0;font:14px %s;color:#374151">%s</td></tr>' % (ICON[r["status"]], FONT, e(r["title"])))
        w('</table>')

    # technical details
    tech = [(r["id"], r["detail"]) for s in rep["sections"] for r in s["items"] if r.get("detail")]
    if tech:
        w('<h3 style="font:600 13px %s;color:#6b7280;margin:28px 0 6px">Technical details (for your IT person)</h3>' % FONT)
        w('<div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:10px 12px;'
          'font:12px/1.5 SFMono-Regular,Consolas,Menlo,monospace;color:#374151;word-break:break-word">')
        h = rep["host"]
        w('%s · %s · %s<br>' % (e(h.get("hostname")), e(h.get("os")), e(h.get("kernel"))))
        for i, d in tech:
            w('<b>%s</b>: %s<br>' % (e(i), e(d)[:600].replace("\n", "<br>")))
        w('</div>')
    w('</td></tr>')

    # footer
    w('<tr><td style="padding:16px 28px 22px;background:#f9fafb;border-top:1px solid #e5e7eb;font:12px %s;color:#6b7280">' % FONT)
    if rep["provider_name"]:
        w('Your server is looked after by <b style="color:#374151">%s</b>%s. Reply to this email with any question.<br>'
          % (e(rep["provider_name"]), (" · " + e(rep["provider_contact"])) if rep["provider_contact"] else ""))
    w('Generated %s by <a href="https://github.com/ahmedbmohamed/server-report-card" style="color:#6b7280">server-report-card</a>.'
      % e(time.strftime("%d %b %Y %H:%M", time.localtime(rep["generated"]))))
    w('</td></tr></table></td></tr></table></body></html>')
    return "".join(p)


def text_report(rep, limit=None):
    o = rep["overall"]
    lines = ["%s %s" % (BIG[o], rep["headline"]),
             "%s · %s · score %s/100" % (rep["server_name"], period_text(rep), rep["score"]), ""]
    for _, st, t in rep["highlights"]:
        lines.append("%s %s" % (ICON[st], t))
    if rep["problems"]:
        lines += ["", "What needs attention:"]
        for r in rep["problems"]:
            lines.append("%s %s" % (ICON[r["status"]], r["title"]))
            if r.get("action"):
                lines.append("   → %s" % r["action"])
    if rep["provider_name"]:
        lines += ["", "— %s" % rep["provider_name"]]
    txt = "\n".join(lines)
    return txt if not limit or len(txt) <= limit else txt[:limit - 1] + "…"


def terminal(results):
    """Plain list of every result, for `server-report-card check`."""
    out = []
    for r in sorted(results, key=lambda r: (r["area"], r["id"])):
        out.append("%-8s %-9s %s" % (r["area"], r["status"].upper(), r["title"]))
        if r["status"] in (WARN, CRIT) and r.get("action"):
            out.append("%18s-> %s" % ("", r["action"]))
        if r.get("detail") and r["status"] != OK:
            out.append("%18s   %s" % ("", r["detail"].splitlines()[0][:150]))
    return "\n".join(out)
