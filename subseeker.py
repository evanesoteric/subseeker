#!/usr/bin/env python3
"""subseeker — multi-mode DNS reconnaissance tool (Python port).

A port of the Zig subseeker. Speaks DNS through dnspython, which (unlike a
getaddrinfo-style call) keeps full visibility into CNAME chains, multi-record
answers, arbitrary record types, choice of resolver, and its own
timeouts/retries — plus a Certificate Transparency mode that reads crt.sh.

Authorized use only. Every mode performs active reconnaissance (and CT/AXFR/
snoop can be considered hostile). Run it only against domains and networks you
own or have explicit permission to assess.

Requires: Python 3.9+, dnspython  (pip install dnspython)
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import cycle

try:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.name
    import dns.query
    import dns.rdatatype
    import dns.resolver
    import dns.reversename
    import dns.zone
except ImportError:
    sys.stderr.write("error: dnspython is required — install it with:\n    pip install dnspython\n")
    sys.exit(2)

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"]
PTR_CAP = 65536  # /16, matches the Zig buildPtrCandidates cap

# Representative subsets, exactly like the Zig tld_list / srv_list — extend freely.
TLD_LIST = [
    "com", "net", "org", "io", "co", "info", "biz", "dev", "app", "xyz",
    "us", "uk", "ca", "de", "fr", "nl", "eu", "au", "jp", "ch",
    "me", "tv", "cc", "ai", "cloud", "online", "site", "tech", "store", "gg",
]
SRV_LIST = [
    "_sip._tcp", "_sip._udp", "_sips._tcp", "_xmpp-client._tcp", "_xmpp-server._tcp",
    "_ldap._tcp", "_kerberos._tcp", "_kerberos._udp", "_kpasswd._tcp", "_gc._tcp",
    "_http._tcp", "_https._tcp", "_ftp._tcp", "_imap._tcp", "_imaps._tcp",
    "_pop3._tcp", "_pop3s._tcp", "_smtp._tcp", "_submission._tcp", "_caldav._tcp",
    "_carddav._tcp", "_autodiscover._tcp", "_minecraft._tcp", "_matrix._tcp",
    "_vlmcs._tcp", "_ts3._udp", "_teamspeak._tcp", "_stun._udp", "_turn._udp",
]


# ---------------------------------------------------------------------------
# Output — results to stdout, diagnostics/progress to stderr (so `-o json`
# stays a clean, pipeable NDJSON stream on stdout).
# ---------------------------------------------------------------------------
class Emitter:
    def __init__(self, fmt: str, outfile):
        self.fmt = fmt
        self.outfile = outfile
        self._lock = threading.Lock()

    def record(self, name: str, rtype: str, value: str, wildcard: bool = False):
        if self.fmt == "json":
            obj = {"name": name, "type": rtype, "value": value}
            if wildcard:
                obj["wildcard"] = True
            line = json.dumps(obj, separators=(",", ":"))
        else:
            line = f"{name}\t{rtype}\t{value}"
        with self._lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
            if self.outfile:
                self.outfile.write(line + "\n")
                self.outfile.flush()

    def raw(self, text: str):
        """Emit a bare line (used by ct listing to produce a clean wordlist)."""
        with self._lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            if self.outfile:
                self.outfile.write(text + "\n")
                self.outfile.flush()


def log(cfg, *args):
    sys.stderr.write(" ".join(str(a) for a in args) + "\n")
    sys.stderr.flush()


def vlog(cfg, *args):
    if cfg.verbose:
        log(cfg, *args)


# ---------------------------------------------------------------------------
# Core DNS query, with resolver rotation, timeout, and retries.
# ---------------------------------------------------------------------------
def make_resolver(nameserver: str, timeout_ms: int) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [nameserver]
    secs = max(timeout_ms / 1000.0, 0.1)
    r.timeout = secs
    r.lifetime = secs
    return r


def query(cfg, name: str, rdtype: str, rd: bool = True):
    """Resolve `name`/`rdtype`, rotating resolvers and retrying. Returns a
    dnspython Answer, or None on failure/NXDOMAIN/empty."""
    rdt = dns.rdatatype.from_text(rdtype)
    attempts = cfg.retries + 1
    for attempt in range(attempts):
        ns = next(cfg._resolver_cycle)
        try:
            if rd:
                r = make_resolver(ns, cfg.timeout)
                return r.resolve(name, rdt, raise_on_no_answer=False)
            # rd=False: hand-build so we can clear the RD flag (cache snooping).
            q = dns.message.make_query(name, rdt)
            q.flags &= ~dns.flags.RD
            resp = dns.query.udp(q, ns, timeout=max(cfg.timeout / 1000.0, 0.1))
            return resp
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError) as e:
            vlog(cfg, f"[!] {name} {rdtype} via {ns}: {e} (attempt {attempt + 1}/{attempts})")
            continue
    return None


def a_values(answer) -> list[str]:
    out = []
    if answer is None:
        return out
    rrset = getattr(answer, "rrset", None)
    if rrset is None:
        return out
    for rr in rrset:
        out.append(rr.to_text())
    return out


# ---------------------------------------------------------------------------
# Wildcard detection (brt) — resolve a couple of random labels; anything that
# comes back is a wildcard address we suppress unless --show-wildcard.
# ---------------------------------------------------------------------------
def detect_wildcard(cfg, domain: str) -> set[str]:
    if not cfg.detect_wildcard:
        return set()
    probes = ["zz--wildcard-probe--1", "qq--wildcard-probe--2", "xx--nope--3"]
    ips: set[str] = set()
    for p in probes:
        for rt in ("A", "AAAA") if cfg.ipv6 else ("A",):
            ans = query(cfg, f"{p}.{domain}", rt)
            for v in a_values(ans):
                ips.add(v)
    if ips:
        log(cfg, f"[brt] wildcard DNS detected ({len(ips)} address(es)); matching hits suppressed"
                 f"{' (shown, not suppressed)' if cfg.show_wildcard else ''}")
    return ips


# ---------------------------------------------------------------------------
# Threaded resolve of a list of full hostnames (shared by brt / tld / ct).
# ---------------------------------------------------------------------------
def resolve_names(cfg, emit: Emitter, names, wildcard_ips: set[str], label_wildcard=True):
    total = len(names)
    done = 0
    prog_lock = threading.Lock()

    def work(name: str):
        found = []
        rtypes = ("A", "AAAA") if cfg.ipv6 else ("A",)
        for rt in rtypes:
            ans = query(cfg, name, rt)
            for v in a_values(ans):
                is_wild = v in wildcard_ips
                if is_wild and not cfg.show_wildcard:
                    continue
                found.append((name, rt, v, is_wild))
        # CNAME visibility (a name can be a CNAME with no A of its own).
        cans = query(cfg, name, "CNAME")
        for v in a_values(cans):
            found.append((name, "CNAME", v, False))
        return found

    with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
        futs = {ex.submit(work, n): n for n in names}
        for fut in as_completed(futs):
            for (name, rt, val, is_wild) in fut.result():
                emit.record(name, rt, val, wildcard=is_wild and label_wildcard)
            with prog_lock:
                done += 1
                if total >= 20 and done % max(total // 20, 1) == 0:
                    log(cfg, f"[.] {done}/{total}")


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
def mode_std(cfg, emit: Emitter):
    d = cfg.domain
    for rt in ("SOA", "NS", "A", "AAAA", "MX", "TXT"):
        ans = query(cfg, d, rt)
        for v in a_values(ans):
            emit.record(d, rt, v)
    log(cfg, "[std] attempting zone transfer…")
    _try_axfr(cfg, emit, standalone=False)


def mode_brt(cfg, emit: Emitter):
    labels = read_wordlist(cfg.wordlist)
    if labels is None:
        return
    if not labels:
        log(cfg, f"[brt] wordlist '{cfg.wordlist}' is empty — nothing to brute-force.")
        return
    names = [f"{lab}.{cfg.domain}" for lab in labels]
    log(cfg, f"[brt] {len(names)} candidate(s) against {cfg.domain}")
    wc = detect_wildcard(cfg, cfg.domain)
    resolve_names(cfg, emit, names, wc)


def _try_axfr(cfg, emit: Emitter, standalone: bool):
    ns_ans = query(cfg, cfg.domain, "NS")
    ns_names = a_values(ns_ans)
    if not ns_names:
        log(cfg, f"[axfr] no NS records for {cfg.domain}")
        return
    log(cfg, f"[axfr] {len(ns_names)} nameserver(s) for {cfg.domain}:")
    any_ok = False
    for ns in ns_names:
        ns = ns.rstrip(".")
        ip_ans = query(cfg, ns, "A")
        ips = a_values(ip_ans)
        if not ips:
            log(cfg, f"    {ns}: could not resolve to IPv4 — skipping")
            continue
        ns_ip = ips[0]
        try:
            log(cfg, f"    {ns} ({ns_ip}): ", )
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, cfg.domain, timeout=max(cfg.timeout / 1000.0, 1.0)))
            any_ok = True
            for (name, node) in z.nodes.items():
                owner = str(name.derelativize(z.origin)).rstrip(".")
                for rdataset in node.rdatasets:
                    rt = dns.rdatatype.to_text(rdataset.rdtype)
                    for rd in rdataset:
                        emit.record(owner, rt, rd.to_text())
            log(cfg, f"    {ns}: SUCCESS — zone transfer allowed (this is a finding to fix)")
        except Exception as e:
            log(cfg, f"    {ns}: refused/failed ({e.__class__.__name__})")
    if not any_ok and standalone:
        log(cfg, "[axfr] No nameserver allowed a zone transfer (this is the secure default).")


def mode_axfr(cfg, emit: Emitter):
    _try_axfr(cfg, emit, standalone=True)


def mode_srv(cfg, emit: Emitter):
    names = [f"{svc}.{cfg.domain}" for svc in SRV_LIST]
    log(cfg, f"[srv] probing {len(names)} SRV service(s) under {cfg.domain}")

    def work(name):
        out = []
        ans = query(cfg, name, "SRV")
        for v in a_values(ans):
            out.append((name, v))
        return out

    with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
        for fut in as_completed({ex.submit(work, n): n for n in names}):
            for (name, val) in fut.result():
                emit.record(name, "SRV", val)


def mode_tld(cfg, emit: Emitter):
    base = cfg.domain.split(".")[0]
    names = [f"{base}.{tld}" for tld in TLD_LIST]
    log(cfg, f"[tld] expanding '{base}' across {len(names)} TLD(s)")
    resolve_names(cfg, emit, names, set(), label_wildcard=False)


def mode_ptr(cfg, emit: Emitter):
    addrs = build_ptr_candidates(cfg.range)
    if addrs is None:
        return
    log(cfg, f"[ptr] reverse-looking up {len(addrs)} address(es)")

    def work(ip):
        rev = dns.reversename.from_address(ip)
        ans = query(cfg, rev.to_text(), "PTR")
        return [(rev.to_text().rstrip("."), v) for v in a_values(ans)]

    with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
        for fut in as_completed({ex.submit(work, ip): ip for ip in addrs}):
            for (owner, val) in fut.result():
                emit.record(owner, "PTR", val)


def mode_snoop(cfg, emit: Emitter):
    hosts = read_wordlist(cfg.wordlist)  # full hostnames, one per line
    if hosts is None:
        return
    if not hosts:
        log(cfg, f"[snoop] wordlist '{cfg.wordlist}' is empty — nothing to snoop"
                 " (did an upstream `ct`/curl produce no hosts?).")
        return
    resolver = cfg.resolvers[0]
    log(cfg, f"[snoop] cache-snooping {len(hosts)} host(s) against {resolver} (RD=0)")

    def work(name):
        out = []
        resp = query(cfg, name, "A", rd=False)
        if resp is not None and getattr(resp, "answer", None):
            for rrset in resp.answer:
                for rr in rrset:
                    out.append((name, rr.to_text()))
        return out

    with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
        for fut in as_completed({ex.submit(work, n): n for n in hosts}):
            for (name, val) in fut.result():
                emit.record(name, "CACHED", val)


# ---------------------------------------------------------------------------
# CT mode — queries multiple CT sources so a single flaky one (crt.sh, hi) can't
# sink the run. Network fetch tries certspotter then crt.sh and merges; the
# --infile / stdin paths still take crt.sh's output=json.
# ---------------------------------------------------------------------------
def _http_get(cfg, url, source, headers=None, timeout_floor=5.0):
    """GET url with retry/backoff. Returns (body_text, "") or (None, last_err)."""
    attempts = max(cfg.retries + 1, 1)
    backoff = 2.0
    last = "unknown error"
    hdrs = {"User-Agent": "subseeker-ct/1.0", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    for i in range(attempts):
        # urlopen's timeout doesn't cover name resolution; bound getaddrinfo too
        # so a stalled resolver can't hang the whole run.
        old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(max(cfg.timeout / 1000.0, timeout_floor))
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=max(cfg.timeout / 1000.0, timeout_floor)) as resp:
                body = resp.read().decode("utf-8", "replace")
            if body.lstrip()[:1] in ("[", "{"):
                return body, ""
            last = f"non-JSON response ({len(body)} bytes)"
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = str(e)
        finally:
            socket.setdefaulttimeout(old_to)
        if i + 1 < attempts:
            log(cfg, f"[ct] {source} {last}; retry {i + 1}/{attempts - 1} in {backoff:.0f}s")
            time.sleep(backoff)
            backoff *= 1.7
    return None, last


def fetch_certspotter(cfg, domain: str):
    """certspotter issuances API — cleaner and more reliable than crt.sh.
    Returns a name list on success, or None if the source failed (so the caller
    can fall back). Set CERTSPOTTER_TOKEN to raise the anonymous rate limit."""
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names")
    headers = {}
    token = os.environ.get("CERTSPOTTER_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    log(cfg, f"[ct] querying certspotter for {domain}")
    body, err = _http_get(cfg, url, "certspotter", headers=headers)
    if body is None:
        log(cfg, f"[ct] certspotter unavailable ({err})")
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        log(cfg, "[ct] certspotter returned unparseable JSON")
        return None
    apex = domain.strip(" \t\r\n.").lower()
    names = []
    for entry in data:
        for dn in entry.get("dns_names") or []:
            n = normalize_ct_name(dn)
            if n and under_apex(n, apex):
                names.append(n)
    return names


def fetch_crtsh(cfg, domain: str):
    """crt.sh output=json. Returns a name list on success, None on failure."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    log(cfg, f"[ct] querying crt.sh for {domain}")
    body, err = _http_get(cfg, url, "crt.sh")
    if body is None:
        log(cfg, f"[ct] crt.sh unavailable ({err})")
        return None
    return parse_ct(body, domain)


def fetch_ct_names(cfg, domain: str):
    """Query every CT source, merge and dedupe. Returns an ordered name list,
    or None only if *every* source failed."""
    seen: dict[str, None] = {}
    any_ok = False
    for source in (fetch_certspotter, fetch_crtsh):
        res = source(cfg, domain)
        if res is None:
            continue  # this source failed; try the next
        any_ok = True
        for n in res:
            seen.setdefault(n, None)
    if not any_ok:
        log(cfg, "[ct] all CT sources failed — they rate-limit/time out; try again shortly.")
        return None
    return list(seen.keys())


def parse_ct(json_text: str, apex: str) -> list[str]:
    apex = apex.strip(" \t\r\n.").lower()
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return []
    seen: dict[str, None] = {}  # ordered dedupe
    for entry in data:
        for key in ("name_value", "common_name"):
            raw = entry.get(key)
            if not raw:
                continue
            for piece in str(raw).split("\n"):
                name = normalize_ct_name(piece)
                if name and under_apex(name, apex):
                    seen.setdefault(name, None)
    return list(seen.keys())


_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def normalize_ct_name(raw: str) -> str | None:
    s = raw.strip().lower()
    if s.startswith("*."):
        s = s[2:]
    s = s.rstrip(".")
    if not s or "@" in s:
        return None
    # Whitelist per label: rejects '*', spaces, and stray junk like markdown
    # brackets/slashes ('[www.x](https://www.x)') that blacklisting missed, and
    # enforces real label structure (no empty or dash-edged labels).
    labels = s.split(".")
    if len(labels) < 2:
        return None
    for lab in labels:
        if not lab or lab.startswith("-") or lab.endswith("-"):
            return None
        if any(c not in _LABEL_CHARS for c in lab):
            return None
    return s


def under_apex(name: str, apex: str) -> bool:
    return name == apex or name.endswith("." + apex)


def mode_ct(cfg, emit: Emitter):
    if cfg.fetch or (cfg.infile is None and sys.stdin.isatty()):
        names = fetch_ct_names(cfg, cfg.domain)
        if names is None:
            return
    else:
        if cfg.infile is not None:
            try:
                with open(cfg.infile, "r", encoding="utf-8", errors="replace") as f:
                    src = f.read()
            except OSError as e:
                log(cfg, f"Error: cannot read CT JSON file '{cfg.infile}': {e}")
                return
        else:
            src = sys.stdin.read()
        if not src.strip():
            log(cfg, "Error: no CT JSON on input. Use --fetch, --infile <file>, or pipe crt.sh JSON in.")
            return
        names = parse_ct(src, cfg.domain)

    log(cfg, f"[ct] {len(names)} unique name(s) at/under {cfg.domain} from CT logs.")
    if not names:
        return

    if not cfg.resolve:
        # Bare list = a clean wordlist you can pipe into snoop/brt. JSON keeps
        # the uniform record shape.
        for h in names:
            if cfg.output == "json":
                emit.record(h, "CT", "crt.sh")
            else:
                emit.raw(h)
        return

    resolve_names(cfg, emit, names, set(), label_wildcard=False)


# ---------------------------------------------------------------------------
# Helpers: wordlist + PTR candidate expansion
# ---------------------------------------------------------------------------
def read_wordlist(path):
    if not path:
        log(None, "Error: this mode needs -w/--wordlist")
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            out = []
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    out.append(s)
            return out
    except OSError as e:
        log(None, f"Error: cannot read wordlist '{path}': {e}")
        return None


def build_ptr_candidates(rng):
    if not rng:
        log(None, "Error: ptr mode needs --range <cidr|a-b>")
        return None
    try:
        if "/" in rng:
            net = ipaddress.ip_network(rng, strict=False)
            hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        elif "-" in rng:
            lo_s, hi_s = rng.split("-", 1)
            lo = int(ipaddress.IPv4Address(lo_s.strip()))
            hi = int(ipaddress.IPv4Address(hi_s.strip()))
            if hi < lo:
                log(None, "Error: range end precedes start")
                return None
            hosts = [ipaddress.IPv4Address(i) for i in range(lo, hi + 1)]
        else:
            hosts = [ipaddress.IPv4Address(rng.strip())]
    except ValueError as e:
        log(None, f"Error: bad --range '{rng}': {e}")
        return None
    if len(hosts) > PTR_CAP:
        log(None, f"Error: range has {len(hosts)} addresses (> {PTR_CAP} cap). Narrow it, or raise PTR_CAP.")
        return None
    return [str(h) for h in hosts]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
MODES = {
    "std": mode_std, "brt": mode_brt, "axfr": mode_axfr, "srv": mode_srv,
    "tld": mode_tld, "ptr": mode_ptr, "snoop": mode_snoop, "ct": mode_ct,
}
NEEDS_DOMAIN = {"std", "brt", "axfr", "srv", "tld", "ct"}


def build_parser():
    p = argparse.ArgumentParser(
        prog="subseeker",
        description="multi-mode DNS reconnaissance tool. Authorized use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""modes:
  std    General records (SOA/NS/A/AAAA/MX/TXT) + zone-transfer attempt
  brt    Brute-force subdomains from a wordlist (A/AAAA/CNAME) + wildcard check
  axfr   Attempt a zone transfer (AXFR) against every nameserver
  srv    Enumerate common SRV service records under the domain
  tld    Top-level-domain expansion of the domain's name
  ptr    Reverse-lookup (PTR) an IPv4 range or CIDR
  snoop  DNS cache snooping (RD=0) of hosts against a resolver
  ct     Certificate Transparency (crt.sh) — fetch/--infile/stdin, optional --resolve

examples:
  subseeker std   -d example.com
  subseeker brt   -d example.com -w words.txt -o json
  subseeker ptr   --range 192.0.2.0/24
  subseeker ct    -d example.com                 # fetches crt.sh natively
  subseeker ct    -d example.com --resolve -o json
""",
    )
    p.add_argument("mode", choices=list(MODES.keys()))
    p.add_argument("-d", "--domain")
    p.add_argument("-w", "--wordlist")
    p.add_argument("--range", dest="range")
    p.add_argument("-r", "--resolver", action="append", dest="resolvers")
    p.add_argument("-t", "--threads", type=int, default=50)
    p.add_argument("--timeout", type=int, default=3000, help="per-query timeout (ms)")
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("-o", "--output", choices=("text", "json"), default="text")
    p.add_argument("--outfile")
    p.add_argument("-6", "--ipv6", action="store_true")
    p.add_argument("--no-wildcard", action="store_false", dest="detect_wildcard")
    p.add_argument("--show-wildcard", action="store_true")
    p.add_argument("--resolve", action="store_true", help="resolve CT names (ct)")
    p.add_argument("--infile", help="read CT JSON from a file (ct)")
    p.add_argument("--fetch", action="store_true", help="force native crt.sh fetch (ct)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv=None):
    cfg = build_parser().parse_args(argv)

    if not cfg.resolvers:
        cfg.resolvers = list(DEFAULT_RESOLVERS)
    cfg._resolver_cycle = cycle(cfg.resolvers)

    if cfg.mode in NEEDS_DOMAIN and not cfg.domain:
        sys.stderr.write(f"error: mode '{cfg.mode}' requires -d/--domain\n")
        return 2
    if cfg.mode == "ptr" and not cfg.range:
        sys.stderr.write("error: ptr mode requires --range\n")
        return 2
    if cfg.mode in ("brt", "snoop") and not cfg.wordlist:
        sys.stderr.write(f"error: mode '{cfg.mode}' requires -w/--wordlist\n")
        return 2

    log(cfg, f"subseeker — mode: {cfg.mode}")
    log(cfg, f"  resolvers: {', '.join(cfg.resolvers)}   timeout: {cfg.timeout}ms   retries: {cfg.retries}\n")

    outfile = None
    if cfg.outfile:
        try:
            outfile = open(cfg.outfile, "w", encoding="utf-8")
        except OSError as e:
            sys.stderr.write(f"error: cannot open --outfile '{cfg.outfile}': {e}\n")
            return 2

    emit = Emitter(cfg.output, outfile)
    try:
        MODES[cfg.mode](cfg, emit)
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130
    finally:
        if outfile:
            outfile.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
