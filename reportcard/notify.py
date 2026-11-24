"""Send the report or an alert by email (SMTP) and/or Telegram."""
import json
import smtplib
import ssl
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid


def send_email(cfg, subject, text, html=None, alert=False):
    to = cfg.list("email", "alerts_to") if alert and cfg.list("email", "alerts_to") else cfg.list("email", "to")
    if not to:
        raise ValueError("no recipient: set [email] to")
    sender = cfg.get("email", "from") or cfg.get("email", "smtp_user")
    if html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(text, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))
    else:
        msg = MIMEText(text, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender.split("@")[-1] if "@" in sender else None)
    host, port = cfg.get("email", "smtp_host") or "localhost", cfg.int("email", "smtp_port")
    mode = cfg.get("email", "security").lower()
    ctx = ssl.create_default_context()
    if mode == "ssl":
        server = smtplib.SMTP_SSL(host, port, context=ctx, timeout=30)
    else:
        server = smtplib.SMTP(host, port, timeout=30)
        if mode == "starttls":
            server.starttls(context=ctx)
    try:
        if cfg.get("email", "smtp_user"):
            server.login(cfg.get("email", "smtp_user"), cfg.get("email", "smtp_password"))
        server.sendmail(sender, to, msg.as_string())
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            pass


def send_telegram(cfg, text):
    token, chat = cfg.get("telegram", "bot_token"), cfg.get("telegram", "chat_id")
    if not token or not chat:
        raise ValueError("set [telegram] bot_token and chat_id")
    data = urllib.parse.urlencode({"chat_id": chat, "text": text[:4000], "disable_web_page_preview": "true"}).encode()
    req = urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % token, data=data)
    with urllib.request.urlopen(req, timeout=30) as r:
        answer = json.loads(r.read().decode())
    if not answer.get("ok"):
        raise RuntimeError("Telegram: %s" % answer.get("description"))


def send(cfg, subject, text, html=None, alert=False):
    """Send on every enabled channel. Returns a list of (channel, error or None)."""
    done = []
    if cfg.bool("email", "enabled"):
        try:
            send_email(cfg, subject, text, html, alert)
            done.append(("email", None))
        except Exception as exc:  # noqa: BLE001 - report every channel, do not stop at the first error
            done.append(("email", "%s: %s" % (exc.__class__.__name__, exc)))
    if cfg.bool("telegram", "enabled"):
        try:
            send_telegram(cfg, text if html else subject + "\n\n" + text)
            done.append(("telegram", None))
        except Exception as exc:  # noqa: BLE001
            done.append(("telegram", "%s: %s" % (exc.__class__.__name__, exc)))
    return done
