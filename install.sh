#!/usr/bin/env bash
# wa-universal-patch installer — make WhatsApp chat work on a 5GPN-style DNS+SNI gateway.
#
# It DETECTS the gateway's TCP/443 SNI listener (sniproxy / sing-box / HAProxy), relocates it to a
# loopback port, and puts the tiny `wa-shim` daemon on :443. wa-shim diverts only WhatsApp's no-SNI
# chat (first bytes ED/WA, from the allowed client range) to a real WhatsApp edge and FAILS OPEN for
# everything else (normal SNI traffic is spliced straight to the relocated listener, untouched). It
# also ensures WhatsApp's domains resolve to the gateway (some forks don't hijack them).
#
# SAFETY: every file/firewall change is backed up; after applying it runs a real TLS handshake smoke
# test and, if it fails, AUTO-ROLLS-BACK atomically (config restore + service reload as one step) and
# asserts a listener is back on :443. Run `--detect` first to preview with zero changes.
set -euo pipefail

# ---- config (override via env) ------------------------------------------------------------------
SHIM_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wa-shim.py"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIM_DST="/usr/local/sbin/wa-shim.py"
SHIM_USER="${WA_SHIM_USER:-wa-shim}"
STATE_DIR="/etc/wa-universal-patch"
STATE_FILE="$STATE_DIR/state.env"
ROLLBACK_FILE="$STATE_DIR/rollback.sh"
BACKUP_DIR="$STATE_DIR/backups"
WA_HOST="${WA_SHIM_WA_HOST:-g.whatsapp.net}"
WA_RESOLVER="${WA_SHIM_RESOLVER:-}"          # auto -> 1.1.1.1,8.8.8.8 if empty
RELOC_PORT="${WA_SHIM_BACKEND_PORT:-}"       # auto-picked free loopback port if empty
CLIENT_CIDR_OVERRIDE="${WA_SHIM_ALLOW_CIDR:-}"
WA_MARK="# wa-universal-patch:whatsapp"
DETECT_ONLY=0
FORCE_HAPROXY=0
for a in "$@"; do
  case "$a" in
    --detect) DETECT_ONLY=1 ;;
    --force-haproxy) FORCE_HAPROXY=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

c_red=$'\e[31m'; c_grn=$'\e[32m'; c_yel=$'\e[33m'; c_cyn=$'\e[36m'; c_off=$'\e[0m'
info(){ echo "${c_cyn}[*]${c_off} $*"; }
ok(){   echo "${c_grn}[ok]${c_off} $*"; }
warn(){ echo "${c_yel}[warn]${c_off} $*" >&2; }
die(){  echo "${c_red}[FAIL]${c_off} $*" >&2; exit 1; }

# ---- rollback bookkeeping -----------------------------------------------------------------------
# Each step appends ONE atomic undo command; rollback runs them in REVERSE. Persisted for uninstall.sh.
add_undo(){ echo "$*" >> "$ROLLBACK_FILE"; }
# backup_restore_undo <path> <reload-cmd> : back up <path> and register a SINGLE undo that restores it
# AND reruns <reload-cmd> together (so a partial rollback can never leave a restored file un-reloaded,
# or a relocated listener stuck on loopback). If <path> did not exist, the undo REMOVES it.
backup_restore_undo(){
  local f="$1" reload="${2:-true}"
  if [ -f "$f" ]; then
    local b="$BACKUP_DIR/$(echo "$f" | tr '/' '_').$$"
    cp -a "$f" "$b"
    add_undo "cp -a '$b' '$f'; { $reload ; } >/dev/null 2>&1 || true"
  else
    add_undo "rm -f '$f'; { $reload ; } >/dev/null 2>&1 || true"
  fi
}
do_rollback(){
  trap - ERR                                   # never let a failing undo re-enter the rollback
  warn "rolling back all changes…"
  [ -f "$ROLLBACK_FILE" ] || return 0
  while IFS= read -r line; do
    [ -n "$line" ] && { eval "$line" || warn "undo step failed: $line"; }
  done < <(tac "$ROLLBACK_FILE")
  if systemctl is-active --quiet wa-shim 2>/dev/null; then
    die "ROLLBACK INCOMPLETE: wa-shim is still active on :443 — run 'systemctl disable --now wa-shim', then restart your SNI listener (${LISTENER_SVC:-sniproxy|sing-box|haproxy})."
  fi
  local up=0 i
  for i in 1 2 3 4 5 6 7 8 9 10; do                # a Type=simple listener can take a moment to re-bind :443
    ss -ltnH 'sport = :443' 2>/dev/null | grep -q . && { up=1; break; }
    sleep 1
  done
  if [ "$up" = 1 ]; then
    rm -f "$ROLLBACK_FILE"
    warn "rollback complete — a listener is back on :443; gateway restored."
  else
    die "ROLLBACK INCOMPLETE: nothing is listening on :443! Manually restart your SNI listener (e.g. systemctl restart ${LISTENER_SVC:-sniproxy|sing-box|haproxy}). Backups: $BACKUP_DIR ; undo log kept: $ROLLBACK_FILE"
  fi
}

[ "$(id -u)" = 0 ] || die "must run as root."
[ -f "$SHIM_SRC" ] || die "wa-shim.py not found next to this installer ($SHIM_SRC)."
command -v ss >/dev/null || die "need 'ss' (iproute2)."
command -v python3 >/dev/null || die "need python3."
command -v tac >/dev/null || die "need 'tac' (coreutils)."

# clean up the transient DNS-probe address (added to lo in check_wa_dns) on ANY exit/interruption
PROBE_TMP_IP=""
_cleanup_probe(){ [ -n "${PROBE_TMP_IP:-}" ] && ip addr del "$PROBE_TMP_IP" dev lo 2>/dev/null || true; }
trap _cleanup_probe EXIT

# ---- detection ----------------------------------------------------------------------------------
LISTENER="" LISTENER_SVC="" LISTENER_CFG="" LISTENER_PID=""
detect_listener443(){
  local line pid pname
  line="$(ss -ltnpH 2>/dev/null | awk '$4 ~ /:443$/ {print; exit}' || true)"
  [ -n "$line" ] || { warn "nothing is listening on TCP/443."; return 0; }
  pid="$(sed -n 's/.*pid=\([0-9]\+\).*/\1/p' <<<"$line")"
  LISTENER_PID="$pid"
  pname="$(sed -n 's/.*users:((\"\([^"]\+\)\".*/\1/p' <<<"$line")"
  case "$pname" in
    sniproxy)  LISTENER=sniproxy ;;
    sing-box)  LISTENER=singbox ;;
    haproxy)   LISTENER=haproxy ;;
    nginx)     LISTENER=nginx ;;
    *)         LISTENER="other:$pname" ;;
  esac
  if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
    LISTENER_CFG="$(tr '\0' '\n' < "/proc/$pid/cmdline" | awk 'p{print;exit} /^-(c|f|--config)$/{p=1}' || true)"
  fi
  case "$LISTENER" in
    sniproxy) LISTENER_SVC=sniproxy ;;
    singbox)  LISTENER_SVC=sing-box ;;
    haproxy)  for u in 5gws-haproxy haproxy; do systemctl list-unit-files "$u.service" >/dev/null 2>&1 && LISTENER_SVC=$u && break; done || true ;;
  esac
}

FW=""
detect_firewall(){
  local nft=0
  command -v nft >/dev/null && [ -n "$(nft list ruleset 2>/dev/null)" ] && nft=1
  if [ "$nft" = 1 ]; then FW=nft
  elif command -v iptables >/dev/null; then iptables --version 2>/dev/null | grep -q nf_tables && FW=iptables-nft || FW=iptables-legacy
  else FW=none; fi
}

REDIRECT_MODE="" REDIRECT_TARGET=""
detect_redirect_mode(){
  # "redirect-mode" gateways (e.g. mora1n/5gws) do NOT bind :443 — an nft/iptables rule redirects
  # :443 to a hidden backend (HAProxy on :18443). Detect that so we can refuse with the right pointer.
  [ -z "$LISTENER" ] || return 0
  local line
  line="$(nft list ruleset 2>/dev/null | grep -iE 'dport 443[^0-9].*(redirect|dnat)' | head -1 || true)"
  [ -n "$line" ] || line="$(iptables -t nat -S 2>/dev/null | grep -iE 'dport 443 .*(REDIRECT|DNAT)' | head -1 || true)"
  if [ -n "$line" ]; then
    REDIRECT_MODE=1
    REDIRECT_TARGET="$(printf '%s' "$line" | grep -oE '(:|to-ports )[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)"
  fi
}

DNS_SYS="" DNS_RULEFILE="" DNS_RELOAD=""
detect_dns(){
  if systemctl is-active --quiet dnsdist 2>/dev/null; then
    DNS_SYS=dnsdist; DNS_RELOAD="systemctl reload dnsdist || systemctl restart dnsdist"
    DNS_RULEFILE=/etc/dnsdist/gfwlist-extra-local.txt
  elif systemctl is-active --quiet mosdns 2>/dev/null; then
    DNS_SYS=mosdns; DNS_RULEFILE=/etc/mosdns/rules/unlock.txt; DNS_RELOAD="systemctl reload mosdns || systemctl restart mosdns"
  elif systemctl is-active --quiet 5gws-smartdns 2>/dev/null || systemctl is-active --quiet smartdns 2>/dev/null; then
    DNS_SYS=smartdns; DNS_RULEFILE=/etc/5gws/rules.toml; DNS_RELOAD="systemctl restart 5gws-smartdns 2>/dev/null || systemctl restart smartdns"
  else
    DNS_SYS=unknown
  fi
}

SELF_IPS="" PUB_IP=""
detect_self_ips(){
  SELF_IPS="$(ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd, - || true)"
  PUB_IP="$(timeout 4 curl -fsS https://api.ipify.org 2>/dev/null || true)"
  [ -n "$PUB_IP" ] && SELF_IPS="${SELF_IPS:+$SELF_IPS,}$PUB_IP" || true
}

CLIENT_CIDR=""
detect_client_cidr(){
  # the NPN client range the gateway scopes :443 to (the 5GPN family uses 172.22.0.0/16). Prefer an
  # explicit override; else sniff a private CIDR from the firewall; else default to 172.22.0.0/16.
  if [ -n "$CLIENT_CIDR_OVERRIDE" ]; then CLIENT_CIDR="$CLIENT_CIDR_OVERRIDE"; return; fi
  CLIENT_CIDR="$(nft list ruleset 2>/dev/null | grep -oE '(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]+\.[0-9]+/[0-9]+' | head -1 || true)"
  CLIENT_CIDR="${CLIENT_CIDR:-172.22.0.0/16}"
}

MULTIHOP=no
detect_multihop(){
  ip rule show 2>/dev/null | grep -qiE 'fwmark|uidrange' && MULTIHOP=maybe || true
  ip link show 2>/dev/null | grep -qiE 'wg[0-9]|tun[0-9]' && MULTIHOP=maybe || true
  nft list ruleset 2>/dev/null | grep -qiE 'meta mark set 0x1|skuid' && MULTIHOP=maybe || true
  systemctl list-units --type=service --state=running 2>/dev/null | grep -qiE '5gws-ssrust|proxy-gateway-exit' && MULTIHOP=maybe || true
}

WA_DNS_OK=unknown
check_wa_dns(){
  # Resolve whatsapp.net AS A CLIENT would — sourced from inside the client CIDR — because the gateway's
  # DNS hijack is client-scoped (the box's own resolver view differs). If it already comes back as a
  # gateway IP, WhatsApp already reaches the gateway and the DNS patch is unnecessary (several forks, e.g.
  # privdns-gateway, blackhole ALL non-CN client A-queries to the gateway by default).
  command -v dig >/dev/null || return 0
  local gw="${SELF_IPS%%,*}" base ip ans
  [ -n "$gw" ] || return 0
  base="${CLIENT_CIDR%/*}"
  ip="$(printf '%s' "$base" | awk -F. 'NF==4{printf "%s.%s.%s.222",$1,$2,$3}')"
  [ -n "$ip" ] || return 0
  ip addr add "$ip/32" dev lo 2>/dev/null || true; PROBE_TMP_IP="$ip/32"
  ans="$(dig +short +time=2 +tries=1 -b "$ip" @"$gw" whatsapp.net A 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)"
  ip addr del "$ip/32" dev lo 2>/dev/null || true; PROBE_TMP_IP=""
  if [ -n "$ans" ] && grep -qw "$ans" <<<"${SELF_IPS//,/ }"; then WA_DNS_OK=yes; else WA_DNS_OK=no; fi
}

pick_free_port(){
  local p; for p in $(seq 8443 8480); do ss -ltnH "sport = :$p" 2>/dev/null | grep -q . || { echo "$p"; return; }; done
  echo 18443
}

print_detection(){
  echo "────────── detection ──────────"
  printf '  %-18s %s\n' ":443 listener"  "${LISTENER:-NONE}${LISTENER_PID:+ (pid $LISTENER_PID)}"
  [ -n "$REDIRECT_MODE" ] && printf '  %-18s %s\n' "redirect-mode"   "nft/ipt :443 -> :${REDIRECT_TARGET:-?} (no direct :443 listener — 5gws-style; NOT auto-patchable)"
  printf '  %-18s %s\n' "listener cfg"    "${LISTENER_CFG:-?}"
  printf '  %-18s %s\n' "listener svc"    "${LISTENER_SVC:-?}"
  printf '  %-18s %s\n' "firewall"        "${FW:-?}"
  printf '  %-18s %s\n' "DNS system"      "${DNS_SYS:-?}${DNS_RULEFILE:+  (rules: $DNS_RULEFILE)}"
  printf '  %-18s %s\n' "gateway IPs"     "${SELF_IPS:-?}"
  printf '  %-18s %s\n' "client range"    "$CLIENT_CIDR"
  printf '  %-18s %s\n' "WhatsApp hijack" "$WA_DNS_OK (client-sourced; 'yes' => DNS patch skipped)"
  printf '  %-18s %s\n' "multi-hop exit"  "$MULTIHOP"
  printf '  %-18s %s\n' "shim listen"     "${SHIM_LISTEN:-0.0.0.0}:443"
  printf '  %-18s %s\n' "backend"         "127.0.0.1:${RELOC_PORT:-?}"
  printf '  %-18s %s\n' "wa-edge resolver" "${WA_RESOLVER:-(auto 1.1.1.1,8.8.8.8)}"
  echo "───────────────────────────────"
}

# ---- listener relocation ------------------------------------------------------------------------
relocate_sniproxy(){
  local cfg="$LISTENER_CFG"; [ -f "$cfg" ] || die "sniproxy config not found ($cfg)."
  local n; n="$(grep -cE '^[[:space:]]*listener[^#]*\b443\b.*\{' "$cfg" || true)"
  [ "$n" = 1 ] || die "found $n one-line ':443' listener lines in $cfg (dual-stack/multi-listener or multi-line form) — needs manual relocation; see README."
  local reload="systemctl restart '$LISTENER_SVC'"
  backup_restore_undo "$cfg" "$reload"
  sed -i -E "s@^([[:space:]]*)listener[^#]*\b443\b.*\{@\1listener 127.0.0.1:$RELOC_PORT {@" "$cfg"
  systemctl restart "$LISTENER_SVC"
}
relocate_singbox(){
  local cfg="$LISTENER_CFG"; [ -f "$cfg" ] || cfg=/etc/sing-box/config.json
  [ -f "$cfg" ] || die "sing-box config not found."
  backup_restore_undo "$cfg" "systemctl restart '$LISTENER_SVC'"
  RELOC_PORT="$RELOC_PORT" python3 - "$cfg" <<'PY'
import json,os,re,sys
cfg=sys.argv[1]; port=int(os.environ["RELOC_PORT"])
raw=open(cfg).read()
# tolerate //-line and /* */ block comments (sing-box accepts JSONC)
raw=re.sub(r'/\*.*?\*/','',raw,flags=re.S)
raw="\n".join(re.sub(r'(^|[^:])//.*$',r'\1',ln) for ln in raw.splitlines())
d=json.loads(raw); n=0
for ib in d.get("inbounds",[]):
    if int(ib.get("listen_port",0))==443:
        ib["listen"]="127.0.0.1"; ib["listen_port"]=port; n+=1
if n!=1: sys.exit("expected exactly one :443 inbound, found %d"%n)
json.dump(d,open(cfg,"w"),indent=2)
PY
  systemctl restart "$LISTENER_SVC"
}
relocate_haproxy(){
  [ "$FORCE_HAPROXY" = 1 ] || die "HAProxy/5gws-style gateway detected (it manages its own nft REDIRECT on :443). Re-run with --force-haproxy to attempt (experimental; full nft snapshot + auto-rollback on smoke failure), or follow the manual steps in README.md."
  local cfg="$LISTENER_CFG"; [ -f "$cfg" ] || die "haproxy config not found ($cfg)."
  local n; n="$(grep -cE '^[[:space:]]*bind[[:space:]]+[^#]*:443([[:space:]]|$)' "$cfg" || true)"
  [ "$n" = 1 ] || die "found $n ':443' bind lines in $cfg (dual-stack / multi-bind) — needs manual relocation; see README."
  backup_restore_undo "$cfg" "systemctl restart '$LISTENER_SVC'"
  # move only the first whitespace-delimited :443 bind address to loopback; trailing options (ssl …) survive
  sed -i -E "s@^([[:space:]]*bind[[:space:]]+)[^[:space:]#]*:443([[:space:]]|\$)@\1127.0.0.1:$RELOC_PORT\2@" "$cfg"
  if [ "$FW" = nft ]; then
    local snap="$BACKUP_DIR/nft.ruleset.$$" jsonf="$BACKUP_DIR/nft.json.$$"
    nft list ruleset > "$snap" 2>/dev/null || true
    nft -j list ruleset > "$jsonf" 2>/dev/null || true
    add_undo "nft flush ruleset 2>/dev/null; nft -f '$snap' 2>/dev/null || true"   # full revert of all nft edits below
    # parse the ruleset from a FILE (passed via argv) — never pipe into 'python3 -', whose stdin is the heredoc
    local plan; plan="$(python3 - "$jsonf" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(0)
items=d.get("nftables",[])
def dport443(expr):
    for e in expr:
        if not isinstance(e,dict): continue
        m=e.get("match")
        if not m: continue
        l=m.get("left",{}); r=m.get("right")
        if isinstance(l,dict) and l.get("payload",{}).get("field") in ("dport",):
            vals=r.get("set",[r]) if isinstance(r,dict) else (r if isinstance(r,list) else [r])
            if any(str(v)=="443" for v in vals): return True
    return False
def acts(expr):
    s=json.dumps(expr); return ('"redirect"' in s) or ('"dnat"' in s)
for it in items:                                   # delete prerouting :443 redirect/dnat (shim must see :443)
    r=it.get("rule")
    if r and dport443(r.get("expr",[])) and acts(r.get("expr",[])):
        print("DELETE %s %s %s %s"%(r["family"],r["table"],r["chain"],r["handle"]))
for it in items:                                   # the inet/ip filter input base chain to open for :443
    c=it.get("chain")
    if c and c.get("type")=="filter" and c.get("hook")=="input":
        print("INPUT %s %s %s"%(c["family"],c["table"],c["name"])); break
PY
)"
    while read -r kind fam tbl chain hnd; do
      [ "${kind:-}" = DELETE ] || continue
      nft delete rule "$fam" "$tbl" "$chain" handle "$hnd" 2>/dev/null || warn "could not delete a :443 redirect (handle $hnd)."
    done <<<"$plan"
    # open INPUT for :443 (the redirect used to deliver to the backend port; the shim is on :443 now)
    local irow; irow="$(grep '^INPUT' <<<"$plan" | head -1 || true)"
    if [ -n "$irow" ]; then
      read -r _k ifam itbl ichain <<<"$irow"
      nft insert rule "$ifam" "$itbl" "$ichain" tcp dport 443 accept 2>/dev/null || warn "could not open nft INPUT for :443 — shim may be starved (policy drop)."
    fi
    # the self-origin smoke probe can't traverse nat-prerouting, so VERIFY here that no :443 redirect/dnat
    # survives (any leftover would still divert real external clients to the now-empty backend port).
    nft -j list ruleset > "$jsonf" 2>/dev/null || true
    if ! python3 - "$jsonf" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(0)
for it in d.get("nftables",[]):
    r=it.get("rule")
    if not r: continue
    s=json.dumps(r.get("expr",[]))
    if '"dport"' in s and '443' in s and ('"redirect"' in s or '"dnat"' in s):
        sys.exit(1)
sys.exit(0)
PY
    then
      warn "a prerouting :443 redirect/dnat still diverts traffic after deletion — refusing (it would black-hole external :443); see README manual steps."
      return 1
    fi
  fi
  systemctl restart "$LISTENER_SVC"
}

ensure_wa_dns(){
  if [ "$WA_DNS_OK" = yes ]; then
    ok "WhatsApp already resolves to the gateway for clients ($DNS_SYS) — no DNS change needed."; return
  fi
  local appended=0
  case "$DNS_SYS" in
    dnsdist)
      grep -qF "$WA_MARK" "$DNS_RULEFILE" 2>/dev/null && { ok "WhatsApp DNS entry already present ($DNS_RULEFILE)."; return; }
      backup_restore_undo "$DNS_RULEFILE" "$DNS_RELOAD"
      printf '%s\nwhatsapp.net\nwhatsapp.com\n' "$WA_MARK" >> "$DNS_RULEFILE"; appended=1
      ;;
    mosdns)
      [ -f "$DNS_RULEFILE" ] || { warn "mosdns unlock list $DNS_RULEFILE missing; skipping DNS patch."; return; }
      grep -qF "$WA_MARK" "$DNS_RULEFILE" 2>/dev/null && { ok "WhatsApp DNS entry already present ($DNS_RULEFILE)."; return; }
      backup_restore_undo "$DNS_RULEFILE" "$DNS_RELOAD"
      printf '%s\ndomain:whatsapp.net\ndomain:whatsapp.com\n' "$WA_MARK" >> "$DNS_RULEFILE"; appended=1   # mosdns domain-set convention
      ;;
    smartdns)
      [ -f "$DNS_RULEFILE" ] || { warn "5gws rules $DNS_RULEFILE missing; skipping DNS patch."; return; }
      grep -qF "$WA_MARK" "$DNS_RULEFILE" 2>/dev/null && { ok "WhatsApp DNS entry already present ($DNS_RULEFILE)."; return; }
      backup_restore_undo "$DNS_RULEFILE" "$DNS_RELOAD"
      cat >> "$DNS_RULEFILE" <<TOML

$WA_MARK
[[rules]]
domain_suffix = "whatsapp.net"
action = "gateway"
[[rules]]
domain_suffix = "whatsapp.com"
action = "gateway"
TOML
      appended=1
      ;;
    *) warn "unknown DNS system; CANNOT auto-point WhatsApp at the gateway. Ensure whatsapp.net/whatsapp.com resolve to ${SELF_IPS%%,*} for your clients."; return ;;
  esac
  [ "$appended" = 1 ] || return 0
  eval "$DNS_RELOAD" >/dev/null 2>&1 || warn "DNS reload failed; reload $DNS_SYS manually."
  # VERIFY the edit actually points WhatsApp at the gateway for clients — never ship an inert/wrong DNS edit.
  sleep 2; check_wa_dns
  if [ "$WA_DNS_OK" = yes ]; then
    ok "pointed WhatsApp at the gateway ($DNS_RULEFILE) — verified resolving to the gateway for clients."
  elif [ "$WA_DNS_OK" = no ]; then
    warn "the DNS edit did NOT take effect (wrong file/format for this $DNS_SYS, or rules not reloaded) — rolling back the DNS change and aborting."
    return 1
  else
    warn "pointed WhatsApp at the gateway ($DNS_RULEFILE) but could NOT verify it (install dig/dnsutils to enable) — if WhatsApp chat fails, confirm whatsapp.net resolves to ${SELF_IPS%%,*} for your clients."
  fi
}

install_shim(){
  id "$SHIM_USER" >/dev/null 2>&1 || { useradd --system --no-create-home --shell /usr/sbin/nologin "$SHIM_USER"; add_undo "userdel '$SHIM_USER' 2>/dev/null || true"; }
  install -m 0755 "$SHIM_SRC" "$SHIM_DST"; add_undo "rm -f '$SHIM_DST'"
  install -m 0755 "$SRC_DIR/uninstall.sh" /usr/local/sbin/wa-patch-uninstall 2>/dev/null || true
  local resolver="${WA_RESOLVER:-1.1.1.1,8.8.8.8}"
  cat > /etc/systemd/system/wa-shim.service <<UNIT
[Unit]
Description=wa-universal-patch WhatsApp no-SNI shim (:443 -> WhatsApp edge / backend)
After=network-online.target ${LISTENER_SVC:-network}.service
Wants=network-online.target

[Service]
Type=simple
User=$SHIM_USER
AmbientCapabilities=CAP_NET_BIND_SERVICE
Environment=WA_SHIM_LISTEN=$SHIM_LISTEN
Environment=WA_SHIM_PORT=443
Environment=WA_SHIM_BACKEND=127.0.0.1:$RELOC_PORT
Environment=WA_SHIM_WA_HOST=$WA_HOST
Environment=WA_SHIM_RESOLVER=$resolver
Environment=WA_SHIM_SELF_IPS=$SELF_IPS
Environment=WA_SHIM_ALLOW_CIDR=$CLIENT_CIDR,127.0.0.0/8
ExecStart=$(command -v python3) $SHIM_DST
Restart=always
RestartSec=1
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
  add_undo "systemctl disable --now wa-shim 2>/dev/null || true; rm -f /etc/systemd/system/wa-shim.service /usr/local/sbin/wa-patch-uninstall; systemctl daemon-reload"
  systemctl daemon-reload
  systemctl enable --now wa-shim
}

# real TLS handshake (SNI=web.whatsapp.com, a domain the gateway proxies) THROUGH the shim->backend.
# stdlib python -> no openssl dependency, so this proof is mandatory (never silently skipped).
_tls_probe(){
  python3 - "$1" <<'PY'
import socket,ssl,sys
host=sys.argv[1]
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
try:
    with socket.create_connection((host,443),timeout=12) as s:
        with ctx.wrap_socket(s,server_hostname="web.whatsapp.com") as ss:
            sys.exit(0 if ss.getpeercert(binary_form=True) else 2)
except Exception:
    sys.exit(3)
PY
}

smoke_test(){
  info "smoke test…"
  sleep 2
  systemctl is-active --quiet wa-shim || { warn "wa-shim not active"; journalctl -u wa-shim -n 15 --no-pager; return 1; }
  journalctl -u wa-shim -n 5 --no-pager 2>/dev/null | grep -qi Traceback && { warn "wa-shim crashed (traceback)"; return 1; }
  ss -ltnH 'sport = :443' | grep -q . || { warn ":443 not listening after install"; return 1; }
  ss -ltnH | grep -q "127.0.0.1:$RELOC_PORT " || { warn "relocated backend not on 127.0.0.1:$RELOC_PORT"; return 1; }
  # (a) MANDATORY: normal SNI still routes phone->shim->backend->origin (real TLS handshake, stdlib).
  #     Retry a few times — a Type=simple listener may still be warming up right after its restart.
  local ok_a=0 i
  for i in 1 2 3; do _tls_probe "$SMOKE_TARGET" && { ok_a=1; break; }; sleep 2; done
  if [ "$ok_a" = 1 ]; then
    ok "SNI fail-open path works (web.whatsapp.com handshakes through shim->backend)."
  else
    warn "SNI handshake through the shim ($SMOKE_TARGET:443) FAILED — backend routing is broken; rolling back."
    return 1
  fi
  # (a2) for HAProxy/5gws: prove external :443 isn't INPUT-dropped (loopback can pass while public drops)
  if [ "$LISTENER" = haproxy ]; then
    local gip="${PUB_IP:-${SELF_IPS%%,*}}"
    if [ -n "$gip" ] && ! _tls_probe "$gip"; then
      warn "external :443 ($gip) handshake FAILED — nft INPUT may be dropping :443; rolling back."
      return 1
    fi
  fi
  # (b) BEST-EFFORT: a no-SNI ED connection is diverted (depends on outbound resolver reachability,
  #     which is orthogonal to whether the shim safely fronts :443 — so a miss only WARNS, never rolls back)
  printf 'ED\x00\x01smoke' | timeout 5 bash -c "cat >/dev/tcp/$SMOKE_TARGET/443" 2>/dev/null || true
  sleep 1
  if journalctl -u wa-shim --since '20 sec ago' --no-pager 2>/dev/null | grep -qE 'WA(\(new-version\))? src='; then
    ok "no-SNI WhatsApp divert works (ED handshake routed to $WA_HOST)."
    DIVERT_VERIFIED=1
  else
    warn "ED divert not observed locally (resolver/SELF_IPS/egress?) — fail-open path is fine; verify on the phone."
    DIVERT_VERIFIED=0
  fi
  return 0
}

write_state(){
  cat > "$STATE_FILE" <<EOF
# wa-universal-patch state — used by uninstall.sh
LISTENER=$LISTENER
LISTENER_SVC=$LISTENER_SVC
LISTENER_CFG=$LISTENER_CFG
RELOC_PORT=$RELOC_PORT
DNS_SYS=$DNS_SYS
DNS_RULEFILE=$DNS_RULEFILE
SHIM_USER=$SHIM_USER
CLIENT_CIDR=$CLIENT_CIDR
INSTALLED_AT=$(date -u +%FT%TZ)
EOF
}

# ================================ main ===========================================================
detect_listener443
detect_firewall
detect_redirect_mode
detect_dns
detect_self_ips
detect_client_cidr
detect_multihop
check_wa_dns
[ -n "$RELOC_PORT" ] || RELOC_PORT="$(pick_free_port)"
SHIM_LISTEN="0.0.0.0"; SMOKE_TARGET="127.0.0.1"
if [ "$LISTENER" = singbox ]; then
  # sing-box's sniff_override keeps the INBOUND port as the egress port (1.12 removed the inbound
  # override_port field), so relocating it to a different port makes it dial <host>:<that-port>.
  # Instead keep it on :443 (loopback) and bind the shim to the interface IP traffic arrives on.
  if [ -n "${WA_SHIM_BIND:-}" ]; then
    IFACE_IP="$WA_SHIM_BIND"
  else
    IFACE_IP="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
    N_IP4="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | sort -u | wc -l | tr -d ' ')"
    [ "${N_IP4:-0}" -le 1 ] || die "this box has multiple global IPv4 addresses ($(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd, -)); the sing-box shim must bind the IP your clients actually reach — re-run with WA_SHIM_BIND=<that-ip>."
  fi
  [ -n "$IFACE_IP" ] || die "could not determine the interface IPv4 for the sing-box relocation; set WA_SHIM_BIND=<ip>."
  RELOC_PORT=443; SHIM_LISTEN="$IFACE_IP"; SMOKE_TARGET="$IFACE_IP"
fi
print_detection

# guard rails
case "$LISTENER" in
  sniproxy|singbox) : ;;
  haproxy) [ "$FORCE_HAPROXY" = 1 ] || warn "HAProxy is bound directly on :443 — needs --force-haproxy (experimental). NOTE: mora1n/5gws is NOT this case — it is redirect-mode (handled below)." ;;
  nginx)   die "a TLS-terminating nginx is on :443, not an SNI router — this patch would break it. Aborting." ;;
  "" )     if [ -n "$REDIRECT_MODE" ]; then
             warn "redirect-mode gateway detected: nft/iptables redirects :443 -> :${REDIRECT_TARGET:-?} to a hidden backend (e.g. mora1n/5gws -> HAProxy:18443). There is no :443 listener to relocate, so wa-universal-patch does NOT auto-patch this topology — see README -> 'Redirect-mode gateways (mora1n/5gws)' for the manual steps. (Failing safe: nothing changed.)"
             [ "$DETECT_ONLY" = 1 ] && exit 0
             exit 2
           fi
           die "no listener on :443 — refusing to install a shim with no backend to fall open to." ;;
  *)       die "unrecognized :443 listener ($LISTENER); refusing rather than risk black-holing all HTTPS." ;;
esac
if [ "$FW" = nft ] && nft list ruleset 2>/dev/null | grep -qi tproxy; then
  die "a TPROXY rule is present; the relocate shim can conflict with TPROXY. Aborting."
fi
[ "$MULTIHOP" = no ] || warn "multi-hop/policy-routed egress may be active: WhatsApp chat will exit via the gateway's own route (${SELF_IPS%%,*}), which can differ from your SNI traffic's exit. If WhatsApp re-auth loops, route the wa-shim user through the same exit (see README)."

if [ "$DETECT_ONLY" = 1 ]; then ok "--detect only: no changes made."; exit 0; fi
[ -f "$STATE_FILE" ] && die "already installed (per $STATE_FILE). Run ./uninstall.sh first, then re-install."

mkdir -p "$STATE_DIR" "$BACKUP_DIR"   # only once we're actually going to install (refusals leave nothing behind)
: > "$ROLLBACK_FILE"
trap 'do_rollback; die "install failed; rolled back."' ERR

info "relocating the :443 listener to 127.0.0.1:$RELOC_PORT and installing wa-shim on :443…"
case "$LISTENER" in
  sniproxy) relocate_sniproxy ;;
  singbox)  relocate_singbox ;;
  haproxy)  relocate_haproxy ;;
esac
ensure_wa_dns
install_shim

if smoke_test; then
  trap - ERR
  write_state
  if [ "${DIVERT_VERIFIED:-0}" = 1 ]; then
    ok "wa-universal-patch installed — WhatsApp no-SNI divert VERIFIED working (and normal HTTPS still routes)."
  else
    ok "wa-universal-patch installed — normal HTTPS verified through the shim."
    warn "⚠️  WhatsApp divert could NOT be auto-verified on this box (commonly: the local test source isn't in the client CIDR, or the box can't reach the edge resolver). Usually fine — but CONFIRM by sending a WhatsApp message from a phone behind the gateway, and watch: journalctl -u wa-shim -f"
  fi
  echo
  echo "  verify on the phone:     send a WhatsApp message (no full-VPN)."
  echo "  watch diverts:           journalctl -u wa-shim -f"
  echo "  uninstall (full revert): sudo wa-patch-uninstall"
else
  do_rollback
  trap - ERR
  die "smoke test failed — rolled back; your gateway is unchanged. Re-run with --detect and see README.md troubleshooting."
fi
