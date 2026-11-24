import struct

import pytest

from reportcard import dnsmini
from reportcard.checks import backups, email_dns, security, system
from reportcard.util import CRIT, INFO, OK, WARN

SSH_LOG = """\
2026-11-20T03:12:01+0100 web sshd[1201]: Invalid user admin from 198.51.100.23 port 51234
2026-11-20T03:12:03+0100 web sshd[1201]: Failed password for invalid user admin from 198.51.100.23 port 51234 ssh2
2026-11-20T03:13:10+0100 web sshd[1210]: Failed password for root from 198.51.100.23 port 51300 ssh2
2026-11-20T03:20:44+0100 web sshd[1290]: Connection closed by authenticating user root 192.0.2.77 port 40022 [preauth]
2026-11-20T04:01:00+0100 web sshd-session[1300]: Invalid user oracle from 2001:db8::7 port 4411
2026-11-20T09:15:22+0100 web sshd[2001]: Accepted publickey for deploy from 203.0.113.5 port 60001 ssh2: ED25519 SHA256:abc
2026-11-20T09:20:00+0100 web sshd[2002]: pam_unix(sshd:session): session opened for user deploy(uid=1000) by (uid=0)
"""


def test_parse_ssh_counts_each_attempt_once():
    p = security.parse_ssh(SSH_LOG.splitlines())
    assert p["attempts"] == 4                       # invalid admin, root password, root key, invalid oracle
    assert p["top_ips"][0] == ("198.51.100.23", 2)
    assert p["unique_ips"] == 3
    assert p["logins"] == [{"time": "2026-11-20T09:15:22+0100", "user": "deploy", "ip": "203.0.113.5", "method": "publickey"}]


SS = """\
tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=900,fd=6))
tcp   LISTEN 0      200        127.0.0.1:5432      0.0.0.0:*    users:(("postgres",pid=950,fd=7))
tcp   LISTEN 0      80                 *:3306            *:*    users:(("mariadbd",pid=990,fd=19))
tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=700,fd=14))
udp   UNCONN 0      0       0.0.0.0%ens33:68       0.0.0.0:*    users:(("dhclient",pid=650,fd=7))
tcp   LISTEN 0      4096            [::]:22           [::]:*    users:(("sshd",pid=812,fd=4))
"""


def test_parse_ss_keeps_public_ports_only():
    assert security.parse_ss(SS) == {"22/tcp": "sshd", "80/tcp": "nginx", "3306/tcp": "mariadbd"}


def test_users_and_admins():
    passwd = ("root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n"
              "deploy:x:1000:1000::/home/deploy:/bin/bash\nsvc:x:1001:1001::/opt:/usr/sbin/nologin\n"
              "toor:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/:/bin/sh\n")
    assert security.login_users(passwd) == {"root": 0, "deploy": 1000, "toor": 0}
    assert security.admin_members("wheel:x:10:deploy,maria\nsudo:x:27:\nusers:x:100:bob\n") == {"deploy", "maria"}


def test_mounts_and_meminfo():
    m = ("/dev/sda1 / ext4 rw 0 0\nproc /proc proc rw 0 0\n/dev/sda1 /var/lib/docker/x ext4 rw 0 0\n"
         "/dev/mapper/rhel-home /home xfs rw 0 0\n/dev/loop1 /snap/core/1 squashfs ro 0 0\ntmpfs /run tmpfs rw 0 0\n")
    assert system.mounts(m) == ["/", "/home"]
    mi = system.meminfo("MemTotal:       4000000 kB\nMemAvailable:   1000000 kB\n")
    assert mi["MemAvailable"] * 4 == mi["MemTotal"]


@pytest.mark.parametrize("records,status", [
    ([], CRIT),
    (["v=spf1 include:_spf.google.com ~all"], OK),
    (["v=spf1 -all", "v=spf1 mx ~all"], CRIT),
    (["v=spf1 +all"], CRIT),
    (["v=spf1 a mx all"], CRIT),
    (["v=spf1 mx ?all"], WARN),
    (["google-site-verification=xyz"], CRIT),
])
def test_spf(records, status):
    assert email_dns.spf_verdict(records)[0] == status


@pytest.mark.parametrize("records,status", [
    ([], WARN),
    (["v=DMARC1; p=none; rua=mailto:x@example.com"], INFO),
    (["v=DMARC1; p=reject"], OK),
    (["v=DMARC1;p=quarantine;pct=100"], OK),
    (["v=DMARC1; p=bogus"], WARN),
])
def test_dmarc(records, status):
    assert email_dns.dmarc_verdict(records)[0] == status


def _answer(qid, qtype, rdatas, rcode=0):
    """Build a DNS response the way a server would, with name compression."""
    q = dnsmini.build_query("example.com", qtype, qid)
    hdr = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(rdatas), 0, 0)
    body = q[12:]
    for rd in rdatas:
        body += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 300, len(rd)) + rd
    return hdr + body


def test_dns_parse_txt_mx_a():
    long_txt = b"v=spf1 " + b"include:a.example " * 20 + b"~all"
    chunks = b"".join(struct.pack("B", len(long_txt[i:i + 255])) + long_txt[i:i + 255] for i in range(0, len(long_txt), 255))
    assert dnsmini.parse_response(_answer(7, 16, [chunks]), 7, 16)[2] == [long_txt.decode()]
    mx = struct.pack(">H", 10) + b"\x04mail\xc0\x0c"
    assert dnsmini.parse_response(_answer(8, 15, [mx]), 8, 15)[2] == [(10, "mail.example.com")]
    assert dnsmini.parse_response(_answer(9, 1, [bytes([127, 0, 0, 2])]), 9, 1)[2] == ["127.0.0.2"]
    assert dnsmini.parse_response(_answer(9, 1, [], rcode=3), 9, 1)[0] == 3
    with pytest.raises(dnsmini.DNSError):
        dnsmini.parse_response(_answer(9, 1, []), 10, 1)


@pytest.mark.parametrize("value", ["2026-11-24T02:30:01+01:00", "2026-11-24T01:30:01Z",
                                   "2026-11-24T02:30:01.123456789+01:00", "2026-11-24T01:30:01.5Z"])
def test_parse_time(value):
    assert int(backups.parse_time(value)) == 1795483801
