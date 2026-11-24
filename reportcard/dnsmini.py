"""A tiny DNS client (TXT, MX, A, PTR) so the tool needs no extra package. UDP with TCP fallback."""
import random
import socket
import struct

TYPES = {"A": 1, "PTR": 12, "MX": 15, "TXT": 16, "CNAME": 5}


class DNSError(Exception):
    pass


def nameservers(path="/etc/resolv.conf"):
    out = []
    try:
        with open(path) as fh:
            for line in fh:
                cols = line.split()
                if len(cols) >= 2 and cols[0] == "nameserver":
                    out.append(cols[1])
    except OSError:
        pass
    return out or ["127.0.0.53", "1.1.1.1"]


def build_query(name, qtype, qid):
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)   # recursion desired
    q = b""
    for label in name.strip(".").split("."):
        raw = label.encode("idna") if label else b""
        q += struct.pack("B", len(raw)) + raw
    return header + q + b"\x00" + struct.pack(">HH", qtype, 1)


def read_name(msg, off):
    labels, jumped, end = [], False, off
    for _ in range(128):
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", msg[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped, off = True, ptr
            continue
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def parse_response(msg, qid, qtype):
    """Returns (rcode, truncated, [rdata values of qtype])."""
    if len(msg) < 12:
        raise DNSError("short answer")
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", msg[:12])
    if rid != qid:
        raise DNSError("answer id mismatch")
    rcode, tc = flags & 0xF, bool(flags & 0x0200)
    off = 12
    for _ in range(qd):
        _, off = read_name(msg, off)
        off += 4
    values = []
    for _ in range(an):
        _, off = read_name(msg, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        if rtype == qtype:
            if rtype == 16:
                parts, i = [], 0
                while i < len(rdata):
                    n = rdata[i]
                    parts.append(rdata[i + 1:i + 1 + n])
                    i += 1 + n
                values.append(b"".join(parts).decode("utf-8", "replace"))
            elif rtype == 15:
                pref = struct.unpack(">H", rdata[:2])[0]
                values.append((pref, read_name(msg, off + 2)[0]))
            elif rtype == 1:
                values.append(socket.inet_ntoa(rdata))
            elif rtype in (12, 5):
                values.append(read_name(msg, off)[0])
        off += rdlen
    return rcode, tc, values


def query(name, rtype="TXT", timeout=4.0, servers=None, tries=2):
    """List of answers. [] when the name or record does not exist. DNSError when DNS does not answer."""
    qtype = TYPES[rtype]
    last = None
    for _attempt in range(tries):
        for server in servers or nameservers():
            qid = random.randint(0, 0xFFFF)
            pkt = build_query(name, qtype, qid)
            fam = socket.AF_INET6 if ":" in server else socket.AF_INET
            try:
                s = socket.socket(fam, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                try:
                    s.sendto(pkt, (server, 53))
                    msg = s.recv(4096)
                finally:
                    s.close()
                rcode, tc, values = parse_response(msg, qid, qtype)
                if tc:
                    rcode, tc, values = _tcp(server, pkt, qid, qtype, timeout, fam)
            except (OSError, DNSError, struct.error, IndexError) as exc:
                last = exc
                continue
            if rcode == 3:      # NXDOMAIN
                return []
            if rcode == 0:
                return values
            last = DNSError("rcode %d" % rcode)
    raise DNSError("%s %s: %s" % (name, rtype, last))


def _tcp(server, pkt, qid, qtype, timeout, fam):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server, 53))
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        n = struct.unpack(">H", _recv(s, 2))[0]
        return parse_response(_recv(s, n), qid, qtype)
    finally:
        s.close()


def _recv(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise DNSError("connection closed")
        buf += chunk
    return buf
