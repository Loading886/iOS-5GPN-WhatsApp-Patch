#!/usr/bin/env python3
"""wa-shim — universal WhatsApp no-SNI shim for 5GPN-style DNS+SNI gateways.

WHY THIS EXISTS
  Gateways like 5GPN / privdns-gateway / 5gws make a phone's DNS resolve "proxy" domains to
  the gateway's own IP, then route inbound TCP/443 by the cleartext TLS SNI (via sniproxy /
  sing-box / HAProxy). That works for everything that sends an SNI — including WhatsApp's API
  and media. But WhatsApp's *chat* socket is a Noise-protocol handshake on TCP/443 with no TLS
  layer and therefore no SNI; its first bytes are "ED"(0x45 0x44, multi-device edge) or
  "WA"(0x57 0x41, classic). An SNI router can extract no hostname from it, so it is dropped and
  WhatsApp messages never send (calls/media still work). This is universal across those forks.

WHAT THIS DOES
  wa-shim sits ON :443 in place of the gateway's SNI listener (which the installer relocates to a
  loopback port, the BACKEND). For each inbound connection it peeks the first few bytes:
    * first 2 bytes are "ED"/"WA" AND the source is in the allowed client range -> it is WhatsApp's
      no-SNI chat -> forward to a real WhatsApp edge (default g.whatsapp.net:443).
    * anything else (a TLS ClientHello with SNI, HTTP, an unknown protocol, a slow/short read, an
      out-of-range source, or any error) -> FAIL OPEN: splice to the BACKEND so the gateway's
      normal SNI routing is completely unaffected. wa-shim NEVER drops non-WhatsApp traffic.
  The peeked bytes are replayed to whichever upstream we pick, so nothing is lost and no TLS is
  terminated — the handshake stays end-to-end phone<->WhatsApp (or phone<->backend).

CORRECTNESS / SECURITY NOTES (hardened after an adversarial review)
  * Peek ACCUMULATES bytes (a 1-byte first TCP segment must not misclassify) until it has enough
    to decide or the timeout fires; <2 bytes => fail open, never drop.
  * The WhatsApp edge is resolved via a CLEAN resolver (WA_SHIM_RESOLVER, direct UDP, NOT the
    system/hijacking DNS), the reply is VALIDATED (txid + QR bit + echoed question) and the socket
    is connect()ed so off-path spoofs are dropped, and any answer equal to a gateway IP
    (WA_SHIM_SELF_IPS) is REFUSED — a hard loop guard.
  * The divert path is gated by WA_SHIM_ALLOW_CIDR (default the NPN client range) so the box is not
    an open relay to the WhatsApp edge for the whole internet; out-of-range peers still fail open.
  * Half-close is propagated with write_eof() so a one-directional EOF does not truncate the other
    direction of the long-lived Noise channel.

stdlib only; runs as an unprivileged user with AmbientCapabilities=CAP_NET_BIND_SERVICE for :443.
"""
import asyncio
import ipaddress
import logging
import os
import socket
import struct
import time

LISTEN_HOST = os.environ.get("WA_SHIM_LISTEN", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("WA_SHIM_PORT", "443"))
# Where non-WhatsApp traffic is handed back to (the gateway's relocated SNI listener).
BACKEND = os.environ.get("WA_SHIM_BACKEND", "127.0.0.1:8443")
# Real WhatsApp edge for the no-SNI chat socket (a hostname, or a literal IP to skip DNS).
WA_HOST = os.environ.get("WA_SHIM_WA_HOST", "g.whatsapp.net")
WA_PORT = int(os.environ.get("WA_SHIM_WA_PORT", "443"))
# Clean resolver(s) for the WhatsApp edge (MUST NOT be the local hijacking DNS). Comma-sep, in order.
RESOLVERS = [r.strip() for r in os.environ.get("WA_SHIM_RESOLVER", "1.1.1.1,8.8.8.8").split(",") if r.strip()]
# The gateway's own IPs — if the WhatsApp edge ever resolves to one of these it is a hijack loop; refuse.
SELF_IPS = set(filter(None, (s.strip() for s in os.environ.get("WA_SHIM_SELF_IPS", "").split(","))))
# Only divert connections whose source is in these CIDRs (empty = allow all). Stops open-relay abuse.
ALLOW_CIDR = []
for _c in os.environ.get("WA_SHIM_ALLOW_CIDR", "").split(","):
    _c = _c.strip()
    if _c:
        try:
            ALLOW_CIDR.append(ipaddress.ip_network(_c, strict=False))
        except ValueError:
            pass
# Known exact 4-byte magics, only to LABEL exact vs new-version (forwarding is on the 2-byte prefix).
KNOWN_MAGIC = [bytes.fromhex(h) for h in
               (t.strip() for t in os.environ.get("WA_SHIM_MAGIC", "45440001,57410603").split(",")) if h.strip()]
WA_PREFIXES = (b"ED", b"WA")                       # 0x45 0x44 / 0x57 0x41 — stable WhatsApp protocol id
PEEK_BYTES = 8
PEEK_TIMEOUT = float(os.environ.get("WA_SHIM_PEEK_TIMEOUT", "3.0"))   # short; on timeout we FAIL OPEN to backend
CONNECT_TIMEOUT = float(os.environ.get("WA_SHIM_CONNECT_TIMEOUT", "8.0"))
DNS_TIMEOUT = float(os.environ.get("WA_SHIM_DNS_TIMEOUT", "3.0"))
DNS_TTL = float(os.environ.get("WA_SHIM_DNS_TTL", "60"))
DNS_NEG_TTL = float(os.environ.get("WA_SHIM_DNS_NEG_TTL", "5"))      # negative cache: don't re-storm a failing resolver
MAX_CONN = int(os.environ.get("WA_SHIM_MAXCONN", "8192"))            # DoS backstop only; default ~non-limiting

logging.basicConfig(level=logging.INFO, format="%(asctime)s wa-shim %(message)s")
log = logging.getLogger("wa-shim")

ACTIVE = 0
_dns_cache = {"ips": [], "at": 0.0}


def _parse_hostport(hp, default_port):
    if hp.count(":") == 1:
        h, p = hp.rsplit(":", 1)
        return h, int(p)
    return hp, default_port


BACKEND_HOST, BACKEND_PORT = _parse_hostport(BACKEND, 8443)


def _src_allowed(src):
    if not ALLOW_CIDR:
        return True
    try:
        addr = ipaddress.ip_address(src)
    except ValueError:
        return False
    return any(addr in net for net in ALLOW_CIDR)


# ---------------------------------------------------------------------------- DNS (clean + validated)
def _encode_qname(host):
    return b"".join(bytes([len(lbl)]) + lbl.encode("idna") for lbl in host.rstrip(".").split(".")) + b"\x00"


def _dns_query_a(host, resolver, timeout=DNS_TIMEOUT):
    """A-record query to a specific resolver over a connect()ed UDP socket (off-path replies dropped),
    validating the transaction id + QR bit + echoed question before trusting the answer."""
    tid = int.from_bytes(os.urandom(2), "big")
    qname = _encode_qname(host)
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((resolver, 53))                  # kernel drops datagrams from any other source
        s.send(pkt)
        deadline = time.monotonic() + timeout
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                return []
            s.settimeout(rem)
            try:
                data = s.recv(4096)
            except (socket.timeout, OSError):
                return []
            if _valid_response(data, tid, qname):
                return _parse_a_answers(data)      # discard non-matching (spoof race) and keep waiting
    finally:
        s.close()


def _valid_response(data, tid, qname):
    if len(data) < 12:
        return False
    rid = int.from_bytes(data[0:2], "big")
    flags = int.from_bytes(data[2:4], "big")
    qd = int.from_bytes(data[4:6], "big")
    if rid != tid or not (flags & 0x8000) or qd < 1:        # txid match + QR(response) bit + has a question
        return False
    q = data[12:12 + len(qname)]                            # echoed question name must match what we asked
    return q.lower() == qname.lower()


def _parse_a_answers(data):
    """Extract IPv4 strings from a DNS response (handles name compression). Pure, unit-testable.
    Bails out on any inconsistency rather than skipping past it; caps the answer loop."""
    if len(data) < 12:
        return []
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):                                     # skip questions
        off = _skip_name(data, off) + 4
        if off > len(data):
            return []
    ips = []
    for _ in range(min(an, 64)):                            # RFC A responses have very few records
        off = _skip_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if off + rdlen > len(data):                         # declared rdata runs past the packet -> malformed
            break
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[off:off + 4]))
        off += rdlen
    return ips


def _skip_name(data, off):
    while off < len(data):
        ln = data[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:                               # compression pointer = 2 bytes, name ends here
            return off + 2
        off += 1 + ln
    return off


async def _resolve_wa_edge():
    """Resolve the WhatsApp edge via a CLEAN resolver, cached, with a hard self-IP (loop) guard."""
    try:                                                    # WA_HOST already an IP literal -> skip DNS
        socket.inet_pton(socket.AF_INET, WA_HOST)
        return [] if WA_HOST in SELF_IPS else [WA_HOST]
    except OSError:
        pass
    now = time.time()
    age = now - _dns_cache["at"]
    if _dns_cache["ips"] and age < DNS_TTL:
        return _dns_cache["ips"]
    if not _dns_cache["ips"] and _dns_cache["at"] > 0 and age < DNS_NEG_TTL:
        return []                                          # recently failed -> short-circuit (no resolver storm)
    loop = asyncio.get_running_loop()
    ips = []
    for resolver in RESOLVERS:
        try:
            ips = await loop.run_in_executor(None, _dns_query_a, WA_HOST, resolver)
            if ips:
                break
        except Exception:
            ips = []
    if not ips:                                             # last resort: system resolver (guarded by SELF_IPS)
        try:
            infos = await loop.run_in_executor(None, socket.getaddrinfo, WA_HOST, WA_PORT,
                                               socket.AF_INET, socket.SOCK_STREAM)
            ips = [i[4][0] for i in infos]
        except Exception:
            ips = []
    clean = [ip for ip in ips if ip not in SELF_IPS]        # HARD loop guard: never dial our own IP
    if ips and not clean:
        log.warning("WA edge %s resolved ONLY to gateway IP(s) %s — DNS hijack loop; refusing "
                    "(set WA_SHIM_RESOLVER to a clean resolver)", WA_HOST, ips)
        _dns_cache["ips"], _dns_cache["at"] = [], now
        return []
    _dns_cache["ips"], _dns_cache["at"] = clean, now        # cache positive OR negative (empty) result
    return clean


# ------------------------------------------------------------------------------------- splice (half-close aware)
def _hard_close(writer):
    try:
        writer.close()
    except Exception:
        pass


async def _pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            if writer.can_write_eof():                      # half-close: signal EOF, don't tear the transport
                writer.write_eof()
        except Exception:
            pass


async def _splice(creader, cwriter, ureader, uwriter, first):
    uwriter.write(first)                                    # replay the peeked bytes; nothing lost
    try:
        await uwriter.drain()
    except Exception:
        _hard_close(cwriter); _hard_close(uwriter)
        return
    await asyncio.gather(_pipe(creader, uwriter), _pipe(ureader, cwriter))
    _hard_close(cwriter); _hard_close(uwriter)              # both directions drained -> now close


async def _to_backend(creader, cwriter, first):
    """FAIL-OPEN path: hand the connection to the gateway's real SNI listener, untouched."""
    try:
        ureader, uwriter = await asyncio.wait_for(
            asyncio.open_connection(BACKEND_HOST, BACKEND_PORT), CONNECT_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        log.warning("backend %s:%d unreachable (%s) — closing; gateway SNI listener down?",
                    BACKEND_HOST, BACKEND_PORT, exc)
        _hard_close(cwriter)
        return
    await _splice(creader, cwriter, ureader, uwriter, first)


async def _to_whatsapp(creader, cwriter, first, label, detail, src):
    ips = await _resolve_wa_edge()
    if not ips:
        log.info("WA src=%s magic=%s DROP: no clean WhatsApp edge IP (see warnings)", src, detail)
        _hard_close(cwriter)
        return
    last = None
    for ip in ips:
        try:
            ureader, uwriter = await asyncio.wait_for(
                asyncio.open_connection(ip, WA_PORT), CONNECT_TIMEOUT)
            tag = "WA" if label == "exact" else "WA(new-version)"
            log.info("%s src=%s magic=%s -> %s(%s):%d (active=%d)%s", tag, src, detail, WA_HOST, ip, WA_PORT,
                     ACTIVE, "" if label == "exact" else f" [add {detail} to WA_SHIM_MAGIC to mark known]")
            await _splice(creader, cwriter, ureader, uwriter, first)
            return
        except Exception as exc:  # noqa: BLE001
            last = exc
    log.info("WA src=%s magic=%s DROP: all edge IPs failed (%s)", src, detail, last)
    _hard_close(cwriter)


def _classify(first):
    """('whatsapp', label, detail) for a positive ED/WA prefix, else ('backend', ...). Fail-open by default."""
    if len(first) >= 2 and first[:2] in WA_PREFIXES:
        label = "exact" if first[:4] in KNOWN_MAGIC else "new-version"
        return "whatsapp", label, first[:4].hex()
    return "backend", "", (first[:8].hex() if first else "<empty>")


async def _peek(creader):
    """Accumulate first bytes until we can classify (>=2 bytes, and 4 for the magic label) or the
    timeout fires. A single 1-byte first segment must NOT decide the verdict."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + PEEK_TIMEOUT
    buf = b""
    while len(buf) < PEEK_BYTES:
        if len(buf) >= 2 and (buf[:2] not in WA_PREFIXES or len(buf) >= 4):
            break
        rem = deadline - loop.time()
        if rem <= 0:
            break
        try:
            chunk = await asyncio.wait_for(creader.read(PEEK_BYTES - len(buf)), rem)
        except Exception:                                  # timeout or reader error -> decide on what we have
            break
        if not chunk:                                       # EOF before enough bytes
            break
        buf += chunk
    return buf


async def handle(creader, cwriter):
    global ACTIVE
    peer = cwriter.get_extra_info("peername")
    src = peer[0] if peer else "?"
    if ACTIVE >= MAX_CONN:                                  # DoS backstop (default 8192 ~ non-limiting)
        log.warning("drop src=%s reason=maxconn(%d)", src, MAX_CONN)
        _hard_close(cwriter)
        return
    ACTIVE += 1
    try:
        first = await _peek(creader)
        verdict, label, detail = _classify(first)
        if verdict == "whatsapp" and _src_allowed(src):
            await _to_whatsapp(creader, cwriter, first, label, detail, src)
        else:
            if verdict == "whatsapp":                       # WA-looking but out-of-range source: do not relay
                log.info("src=%s WA-looking but not in WA_SHIM_ALLOW_CIDR -> backend (no relay)", src)
            await _to_backend(creader, cwriter, first)
    finally:
        ACTIVE -= 1


async def main():
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    log.info("listening %s:%d  backend=%s:%d  wa-edge=%s:%d via resolver=%s  magics=%s  self-ips=%s  allow=%s",
             LISTEN_HOST, LISTEN_PORT, BACKEND_HOST, BACKEND_PORT, WA_HOST, WA_PORT,
             ",".join(RESOLVERS), ",".join(m.hex() for m in KNOWN_MAGIC), ",".join(sorted(SELF_IPS)) or "none",
             ",".join(str(n) for n in ALLOW_CIDR) or "any")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
