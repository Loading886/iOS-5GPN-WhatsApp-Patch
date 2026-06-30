# iOS-5GPN-WhatsApp-Patch — 让 5GPN 类网关上的 WhatsApp 正常收发消息

> 🇨🇳 中文说明在前;完整英文文档见下方(**English version below ↓**)。

给"手机只设 DNS 就能上网"的网关(**5GPN / privdns-gateway / 5gws** 这一类)的即插补丁。这类网关能让 WhatsApp 的**通话和媒体**正常,但**消息发不出去**——本补丁修复这个问题,且不改变你使用网关的方式。

## 一键安装

```bash
# 1) 先干跑:只检测你的网关、不做任何改动(推荐先跑这个):
curl -fsSL https://raw.githubusercontent.com/Loading886/iOS-5GPN-WhatsApp-Patch/main/bootstrap.sh | sudo bash -s -- --detect

# 2) 安装补丁:
curl -fsSL https://raw.githubusercontent.com/Loading886/iOS-5GPN-WhatsApp-Patch/main/bootstrap.sh | sudo bash

# 卸载(完整还原):
curl -fsSL https://raw.githubusercontent.com/Loading886/iOS-5GPN-WhatsApp-Patch/main/bootstrap.sh | sudo bash -s -- --uninstall
```

想先看代码再运行?克隆下来检查后:

```bash
git clone https://github.com/Loading886/iOS-5GPN-WhatsApp-Patch && cd iOS-5GPN-WhatsApp-Patch
sudo ./install.sh --detect    # 干跑
sudo ./install.sh             # 安装(全程备份、真实 TLS 握手烟雾测试、失败自动回滚)
sudo ./uninstall.sh           # 完整还原
```

## 为什么 WhatsApp 在这些网关上发不出消息

这些项目的原理都一样:你手机的 **DoT DNS** 把"要代理"的域名解析成**网关自己的 IP**,网关再按 **TCP/443 上明文的 TLS SNI** 来转发(用 sniproxy、sing-box 或 HAProxy)。凡是带 SNI 的流量都能覆盖——包括 WhatsApp 的 API(`*.whatsapp.net`)和媒体。

但 **WhatsApp 的聊天连接根本没有 SNI**。它是直接跑在 TCP/443 上的 Noise 协议握手,没有 TLS 层,所以 SNI 路由器读不到任何主机名。它的首字节是:

```
45 44 00 01   "ED…"   (多设备 edge)
57 41 06 03   "WA…"   (经典)
```

网关看到一个无法分类的 443 连接,只能把它丢掉 → 你的消息一直转圈、发送失败(通话/媒体仍然正常,因为它们**带** SNI)。这个问题在全部五个 fork 上都一模一样。

> 补丁具体怎么修、支持哪些 fork、安全性与自动回滚机制等完整细节,见下方英文文档。

---

# wa-universal-patch — make WhatsApp work on a 5GPN-style DNS+SNI gateway

A drop-on patch for "set your phone's DNS and go" gateways (the **5GPN / privdns-gateway / 5gws**
family). Those gateways make WhatsApp's *calls and media* work but **WhatsApp messages won't send** —
this fixes that, with no change to how you use the gateway.

## One-line install

```bash
# 1) DRY RUN first — detects your gateway, changes nothing (recommended):
curl -fsSL https://raw.githubusercontent.com/Loading886/iOS-5GPN-WhatsApp-Patch/main/bootstrap.sh | sudo bash -s -- --detect

# 2) Install the patch:
curl -fsSL https://raw.githubusercontent.com/Loading886/iOS-5GPN-WhatsApp-Patch/main/bootstrap.sh | sudo bash

# Uninstall (full revert):
curl -fsSL https://raw.githubusercontent.com/Loading886/iOS-5GPN-WhatsApp-Patch/main/bootstrap.sh | sudo bash -s -- --uninstall
```

Prefer to read before you run? Clone and inspect, then:

```bash
git clone https://github.com/Loading886/iOS-5GPN-WhatsApp-Patch && cd iOS-5GPN-WhatsApp-Patch
sudo ./install.sh --detect    # dry run
sudo ./install.sh             # install (backs up everything, smoke-tests, auto-rolls-back on failure)
sudo ./uninstall.sh           # full revert
```

---

## Why WhatsApp breaks on these gateways

All of these projects work the same way: your phone's **DoT DNS** answers "proxy" domains with the
**gateway's own IP**, and the gateway routes inbound **TCP/443 by the cleartext TLS SNI** (using
sniproxy, sing-box, or HAProxy). That covers everything that sends an SNI — including WhatsApp's API
(`*.whatsapp.net`) and media.

But **WhatsApp's chat socket has no SNI at all.** It is a Noise-protocol handshake straight over
TCP/443 with no TLS layer, so there is no hostname for an SNI router to read. Its first bytes are:

```
45 44 00 01   "ED…"   (multi-device edge)
57 41 06 03   "WA…"   (classic)
```

The gateway sees a 443 connection it can't classify and drops it → your messages spin and fail
(calls/media still work because those *do* carry an SNI). This is identical across all five forks.

## What the patch does

It inserts a tiny **peek-shim** in front of the gateway's :443 listener:

```
                       ┌─────────── wa-shim (:443) ───────────┐
 phone ──TCP/443──▶    │  peek first bytes:                   │
                       │   • "ED"/"WA"  ─▶ real WhatsApp edge  │ ─▶ g.whatsapp.net:443
                       │   • anything else ─▶ FAIL OPEN        │ ─▶ 127.0.0.1:<backend>
                       └──────────────────────────────────────┘     (the gateway's own
                                                                      SNI listener, relocated)
```

- Only a **positive `ED`/`WA` match** is diverted to WhatsApp. It matches on the stable 2-byte
  protocol prefix, so it keeps working across WhatsApp version bumps (the trailing version bytes
  change; new ones are still forwarded and just logged).
- **Everything else fails open** — a normal TLS ClientHello, HTTP, an unknown protocol, even a slow
  or failed peek, is spliced straight to the gateway's listener untouched. wa-shim never drops
  normal traffic and never terminates TLS; the handshake stays end-to-end.
- The installer also makes sure **WhatsApp's domains actually resolve to the gateway** so the chat
  socket arrives. It first probes — *sourced from inside the client CIDR* — whether `whatsapp.net`
  already comes back as a gateway IP; if so (e.g. privdns-gateway blackholes all non-CN client queries
  by default) it **skips the DNS change**, and only adds a rule on forks that don't already hijack it.

The shim is ~200 lines of dependency-free Python, runs as an unprivileged user, and `Restart=always`.

## Per-fork compatibility

| Fork | :443 listener | Auto-patch | What the installer does |
|---|---|---|---|
| **Xiuyixx/5GPN-X** | sniproxy | ✅ one-click | relocate sniproxy → loopback; shim on :443. WhatsApp already hijacked. |
| **Jaydooooooo/5GPN** | sniproxy | ✅ one-click | same as above (it's a wrapper over Xiuyixx). |
| **lingchenfs1/5gpn** | sniproxy | ✅ one-click | same; installer **verifies** WhatsApp is hijacked and adds a DNS entry if the deployed GFWList lacks it. |
| **misaka-cpu/privdns-gateway** | sing-box | ✅ one-click · **live-tested** | sing-box keeps the inbound port as the egress port, so it's relocated to loopback **:443** (not a new port) and the shim binds the interface IP. It already blackholes non-CN client queries to the gateway, so WhatsApp is hijacked by default and the **DNS patch is auto-skipped**. |
| **mora1n/5gws** | HAProxy (behind an nft redirect) | ❌ manual only | **redirect-mode**: 5gws never binds :443 — an nft rule redirects `:443 → HAProxy:18443`. There's no :443 listener to relocate, so the installer **detects this and refuses cleanly** (fails safe, nothing changed). See the manual steps below. |

> **Live-tested:** the **sing-box** path (privdns-gateway) and the **sniproxy** path (lingchen/5gpn) were
> installed via the one-liner on a real Debian 12 deployment and verified end-to-end — WhatsApp's no-SNI
> ED/WA handshake is diverted to `g.whatsapp.net`, normal SNI fails open to the gateway, DNS is hijacked
> for clients, and uninstall fully restores the gateway. **mora1n/5gws is redirect-mode** (it never binds
> :443 — nft redirects :443 → HAProxy:18443); the installer detects this topology and refuses cleanly, so
> 5gws is **manual-only** (see below), not auto-patched.

> The mechanism is universal; the *integration* is per-host, so the installer **detects then adapts**.

## Safety

This patch sits in front of all of your :443, so it is built to be reversible and self-checking:

1. **`--detect`** shows everything it found and changes nothing.
2. Every file it edits is **backed up** under `/etc/wa-universal-patch/backups/`.
3. After patching it runs an **end-to-end smoke test** — a real TLS handshake for `web.whatsapp.com`
   through shim→backend (proves normal SNI routing still works) and a synthetic `ED` connection
   (proves the WhatsApp divert works).
4. **If the smoke fails, it auto-rolls-back** to the exact prior state and aborts. A failed install
   leaves your gateway exactly as it was.
5. **`fail-open`** in the daemon: if the shim can't classify or the peek times out, it forwards to
   the backend rather than dropping.

## Caveats (read these)

- **It does not fix WhatsApp-over-QUIC (UDP/443).** It doesn't need to — when UDP/443 is blocked or
  unhandled, WhatsApp falls back to TCP, which this patch covers. The patch does **not** block
  UDP/443; leave your gateway's QUIC handling as-is.
- **Source scoping (not an open relay).** The divert path is gated by `WA_SHIM_ALLOW_CIDR` — the
  installer sets it to your gateway's client range (auto-detected, default `172.22.0.0/16`), so only
  your own clients' `ED`/`WA` connections are forwarded to the WhatsApp edge; anyone else who reaches
  `:443` just fails open to the backend. If your clients use a different range, pass
  `WA_SHIM_ALLOW_CIDR=<your/cidr>` to the installer.
- **DNS spoof resistance.** The WhatsApp edge is resolved over a `connect()`ed UDP socket and the reply
  is validated (transaction-id + response bit + echoed question), so off-path spoofs on the hostile
  client network can't redirect the chat socket.
- **Egress IP / multi-hop.** WhatsApp chat exits via the gateway's own default route. On a
  single-server gateway (the default for all five) that's the same IP as everything else — fine. If
  you run a **multi-hop exit**, the shim's WhatsApp egress may differ from your other traffic's exit
  and WhatsApp can churn sessions; the installer warns when it detects this. Route the shim through
  your exit if needed (set `WA_SHIM_RESOLVER`/policy routing for the `wa-shim` user).
- **DNS loop guard.** The shim resolves the WhatsApp edge through a **clean resolver**
  (`WA_SHIM_RESOLVER`, default `1.1.1.1,8.8.8.8`) and **refuses any answer equal to the gateway's own
  IP** — otherwise the box's own hijacking DNS could point it back at itself. If your box can't reach
  a public resolver on :53, set `WA_SHIM_RESOLVER` to one it can.
- **Rule-refresh timers.** The DNS entry is written with a unique marker (`# wa-universal-patch:whatsapp`)
  to each project's *local supplement* file (`gfwlist-extra-local.txt` / `unlock.txt` / `rules.toml`) so
  re-running is idempotent and the project's weekly list refresh appends rather than clobbers it. If your
  fork regenerates that file wholesale, re-add the entry (or re-run the patch — it's idempotent).
- **Honesty:** the daemon logic is unit-tested (28 cases) and the **sing-box and sniproxy paths are
  live-tested** end-to-end (install → verify → uninstall) on a real deployment; the HAProxy/5gws path
  is code-reviewed but not yet live-tested. The installer self-validates with a real TLS handshake and
  auto-rolls-back, so an unforeseen difference on your box fails safe instead of breaking your HTTPS.

## Redirect-mode gateways (mora1n/5gws)

5gws is **redirect-mode**: it never binds :443. An nft rule in `table inet fivegws` does
`iifname <iface> ip saddr <client-cidr> tcp/udp dport 443 redirect to :18443`, where HAProxy actually
listens (tcp-mode, `reject unless has_sni`). There is **no :443 listener to relocate**, so the installer
detects this and **fails safe** (`exit 2`, nothing changed) — it does not try to auto-patch it. Wire it
up by hand (HAProxy stays on :18443; the shim takes the redirect's place on :443):

1. **DNS** — make WhatsApp resolve to the gateway so the chat socket arrives. Add to `/etc/5gws/rules.toml`:
   ```toml
   [[rules]]
   name = "whatsapp"
   exit = "gateway"            # whatever your "send to gateway" action is named
   domain_suffix = ["whatsapp.net", "whatsapp.com"]
   ```
   then `systemctl restart 5gws-smartdns`.
2. **Remove the :443 redirect** so client :443 reaches the shim instead of HAProxy directly:
   ```bash
   nft -a list chain inet fivegws prerouting          # find the handle of each tcp/udp dport 443 redirect rule
   nft delete rule inet fivegws prerouting handle <N> # repeat for the tcp and udp :443 rules
   ```
3. **Run the shim on :443**, forwarding non-WhatsApp to HAProxy's real port (18443). The installer refuses
   redirect-mode, so run the daemon directly (wrap it in a systemd unit for persistence):
   ```bash
   sudo WA_SHIM_PORT=443 WA_SHIM_BACKEND=127.0.0.1:18443 \
        WA_SHIM_ALLOW_CIDR=<client-cidr>,127.0.0.0/8 WA_SHIM_SELF_IPS=<gateway-ip> \
        python3 wa-shim.py
   ```
   5gws's input chain is `policy accept`, so the shim on :443 gets client traffic with no extra firewall rule.

> Native redirect-mode auto-support may come later; for now the installer fails safe on 5gws and points here.

> **Note:** there is also an experimental `--force-haproxy` path, but it is for the *different* case of a
> gateway that binds **HAProxy directly on :443** (none of the five forks does this; it's untested). It is
> **not** for 5gws — 5gws is redirect-mode, handled by the manual steps above.

## Files

| File | Purpose |
|---|---|
| `bootstrap.sh` | the one-line `curl … | sudo bash` entry point (downloads + runs the installer) |
| `wa-shim.py` | the peek-shim daemon (stdlib only) |
| `install.sh` | detect-then-adapt installer (`--detect`, `--force-haproxy`) |
| `uninstall.sh` | full revert from the recorded rollback log |
| `test_wa_shim.py` | functional tests for the daemon (28 cases) |

## Tuning (env on the `wa-shim.service` unit)

| Var | Default | Meaning |
|---|---|---|
| `WA_SHIM_BACKEND` | `127.0.0.1:<auto>` | where non-WhatsApp traffic is handed back |
| `WA_SHIM_WA_HOST` | `g.whatsapp.net` | WhatsApp edge for the chat socket |
| `WA_SHIM_RESOLVER` | `1.1.1.1,8.8.8.8` | clean resolver for the edge (must not be the local hijacker) |
| `WA_SHIM_SELF_IPS` | gateway IPs | loop guard — edge answers equal to these are refused |
| `WA_SHIM_ALLOW_CIDR` | client range `,127.0.0.0/8` | only these sources are diverted (open-relay guard); others fail open |
| `WA_SHIM_MAGIC` | `45440001,57410603` | known magics (labels exact vs new-version; matching is on the 2-byte prefix) |
| `WA_SHIM_PEEK_TIMEOUT` | `3.0` | seconds to wait for first bytes before failing open |
