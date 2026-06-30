#!/usr/bin/env python3
"""Functional tests for wa-shim.py — runs locally, no privilege/network (mocks backend + WA edge)."""
import asyncio
import importlib.util
import ipaddress
import os
import struct
import sys

B_PORT, W_PORT, S_PORT = 18901, 18902, 18900
os.environ.update({
    "WA_SHIM_LISTEN": "127.0.0.1", "WA_SHIM_PORT": str(S_PORT),
    "WA_SHIM_BACKEND": f"127.0.0.1:{B_PORT}",
    "WA_SHIM_WA_HOST": "127.0.0.1", "WA_SHIM_WA_PORT": str(W_PORT),  # IP literal -> skip DNS
    "WA_SHIM_SELF_IPS": "", "WA_SHIM_PEEK_TIMEOUT": "2.0",
})
_here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("wa_shim", os.path.join(_here, "wa-shim.py"))
wa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wa)

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS  {name}")
    else:
        FAIL += 1; print(f"  FAIL  {name}")


def build_dns(ips):
    h = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, len(ips), 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in "g.whatsapp.net".split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
    ans = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes(int(o) for o in ip.split(".")) for ip in ips)
    return h + q + ans


def unit_tests():
    print("unit:")
    check("classify ED exact",        wa._classify(b"ED\x00\x01x")[:2] == ("whatsapp", "exact"))
    check("classify WA exact",        wa._classify(b"WA\x06\x03x")[:2] == ("whatsapp", "exact"))
    check("classify ED new-version",  wa._classify(b"ED\x00\x99x")[:2] == ("whatsapp", "new-version"))
    check("classify WA new-version",  wa._classify(b"WA\x09\x09x")[:2] == ("whatsapp", "new-version"))
    check("classify TLS -> backend",  wa._classify(b"\x16\x03\x01\x00")[0] == "backend")
    check("classify HTTP -> backend", wa._classify(b"GET / ")[0] == "backend")
    check("classify empty -> backend", wa._classify(b"")[0] == "backend")
    check("classify 1 byte -> backend", wa._classify(b"E")[0] == "backend")  # <2 bytes never diverts
    check("dns parse single A",       wa._parse_a_answers(build_dns(["1.2.3.4"])) == ["1.2.3.4"])
    check("dns parse multi A",        wa._parse_a_answers(build_dns(["1.2.3.4", "5.6.7.8"])) == ["1.2.3.4", "5.6.7.8"])
    check("dns parse truncated -> []", wa._parse_a_answers(b"\x00\x00") == [])
    # DNS response validation (spoof resistance): txid + QR + echoed qname
    good, qn = build_dns(["1.2.3.4"]), wa._encode_qname("g.whatsapp.net")
    check("valid_response accepts matching",   wa._valid_response(good, 0x1234, qn))
    check("valid_response rejects bad txid",   not wa._valid_response(good, 0x9999, qn))
    check("valid_response rejects bad qname",  not wa._valid_response(good, 0x1234, wa._encode_qname("evil.example")))
    check("valid_response rejects a query",    not wa._valid_response(struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0), 0x1234, qn))
    # source allowlist (open-relay guard)
    wa.ALLOW_CIDR = [ipaddress.ip_network("172.22.0.0/16")]
    check("src_allowed in-range",     wa._src_allowed("172.22.5.5"))
    check("src_allowed out-of-range", not wa._src_allowed("8.8.8.8"))
    wa.ALLOW_CIDR = []
    check("src_allowed empty=allow-all", wa._src_allowed("8.8.8.8"))
    # loop guard via the IP-literal fast path
    wa.SELF_IPS = {"127.0.0.1"}
    check("loop guard refuses self IP", asyncio.run(wa._resolve_wa_edge()) == [])
    wa.SELF_IPS = set()
    check("resolves IP literal",        asyncio.run(wa._resolve_wa_edge()) == ["127.0.0.1"])


def make_echo(marker):
    async def h(r, w):
        try:
            await asyncio.wait_for(r.read(32), 2)
            w.write(marker); await w.drain()
        except Exception:
            pass
        finally:
            w.close()
    return h


async def probe(payload):
    r, w = await asyncio.open_connection("127.0.0.1", S_PORT)
    w.write(payload); await w.drain()
    try:
        data = await asyncio.wait_for(r.read(64), 5)
    except Exception:
        data = b"<timeout>"
    w.close()
    return data


async def probe_fragmented(chunks, delay=0.04):
    r, w = await asyncio.open_connection("127.0.0.1", S_PORT)
    for ch in chunks:
        w.write(ch); await w.drain(); await asyncio.sleep(delay)
    try:
        data = await asyncio.wait_for(r.read(64), 5)
    except Exception:
        data = b"<timeout>"
    w.close()
    return data


async def integration():
    print("integration:")
    backend = await asyncio.start_server(make_echo(b"BACKEND"), "127.0.0.1", B_PORT)
    wedge = await asyncio.start_server(make_echo(b"WHATSAPP"), "127.0.0.1", W_PORT)
    shim = await asyncio.start_server(wa.handle, "127.0.0.1", S_PORT)
    async with backend, wedge, shim:
        check("ED handshake -> WhatsApp edge",      await probe(b"ED\x00\x01hello-world") == b"WHATSAPP")
        check("WA handshake -> WhatsApp edge",      await probe(b"WA\x06\x03noise-bytes") == b"WHATSAPP")
        check("ED new-version -> WhatsApp edge",    await probe(b"ED\x00\x42future-ver") == b"WHATSAPP")
        check("TLS ClientHello -> backend (open)",  await probe(b"\x16\x03\x01\x00\x05hello") == b"BACKEND")
        check("HTTP -> backend (fail open)",        await probe(b"GET / HTTP/1.1\r\n\r\n") == b"BACKEND")
        check("unknown bytes -> backend (open)",    await probe(b"\x00\x01\x02\x03\x04\x05") == b"BACKEND")
        # fragmented first segment (1 byte 'E', then the rest) must STILL divert — the short-read bug fix
        check("fragmented ED (1B then rest) -> WA",  await probe_fragmented([b"E", b"D\x00\x01rest"]) == b"WHATSAPP")
        # source allowlist gates the divert: a WA handshake from a disallowed src fails open to backend
        wa.ALLOW_CIDR = [ipaddress.ip_network("10.0.0.0/8")]
        check("ED from disallowed src -> backend",   await probe(b"ED\x00\x01x") == b"BACKEND")
        wa.ALLOW_CIDR = []


def main():
    unit_tests()
    asyncio.run(integration())
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
