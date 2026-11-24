"""Configuration: one INI file, every value has a sensible default."""
import configparser
import os

DEFAULT_PATH = "/etc/server-report-card/config.ini"

DEFAULTS = {
    "report": {
        "server_name": "",           # shown in the report, e.g. "Shop web server"
        "client_name": "",           # e.g. "Example Shop"
        "provider_name": "",         # who looks after the server, shown in the footer
        "provider_contact": "",
        "data_dir": "/var/lib/server-report-card",
        "days": "7",
    },
    "email": {
        "enabled": "false",
        "smtp_host": "",
        "smtp_port": "587",
        "smtp_user": "",
        "smtp_password": "",
        "security": "starttls",      # starttls | ssl | none
        "from": "",
        "to": "",                    # comma separated
        "alerts_to": "",             # default: same as "to"
    },
    "telegram": {
        "enabled": "false",
        "bot_token": "",
        "chat_id": "",
    },
    "security": {
        "require_fail2ban": "true",
        "require_firewall": "true",
        "ignore_ports": "",          # e.g. 8080/tcp, 51820/udp
    },
    "backups": {
        "required": "true",
        "status_files": "/var/backups/last-backup-*.json",   # written by linux-server-setup-kit
        "restic_env_files": "/etc/restic/*/backup.env",
        "marker_files": "",          # any file your backup job touches after a good run
        "max_age_hours": "26",
        "restore_test_days": "30",
        "restore_test_path": "/etc",
    },
    "website": {
        "urls": "",                  # comma separated
        "domains": "",               # registration expiry (RDAP); default: hosts of the urls
        "timeout": "15",
        "ssl_warn_days": "14",
        "ssl_crit_days": "5",
        "domain_warn_days": "30",
        "slow_ms": "3000",
        "verify_ssl": "true",
    },
    "email_dns": {
        "domains": "",
        "dkim_selectors": "",        # empty: try common selectors
        "server_ips": "",            # sending IPs to check against blacklists
    },
    "server": {
        "disk_warn": "85",
        "disk_crit": "95",
        "memory_warn": "10",         # % available
        "memory_crit": "5",
        "services": "",              # e.g. nginx, postgresql
    },
}


class Config:
    def __init__(self, path=None):
        self.path = path or os.environ.get("REPORTCARD_CONFIG", DEFAULT_PATH)
        self.cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";", "#"))
        self.cp.read_dict(DEFAULTS)
        self.loaded = bool(self.cp.read(self.path, encoding="utf-8"))

    def get(self, section, key):
        return self.cp.get(section, key, fallback="").strip()

    def int(self, section, key):
        try:
            return int(float(self.get(section, key)))
        except ValueError:
            return int(float(DEFAULTS[section][key]))

    def bool(self, section, key):
        return self.get(section, key).lower() in ("1", "yes", "true", "on")

    def list(self, section, key):
        return [x.strip() for x in self.get(section, key).replace("\n", ",").split(",") if x.strip()]

    @property
    def data_dir(self):
        return os.environ.get("REPORTCARD_DATA") or self.get("report", "data_dir")
