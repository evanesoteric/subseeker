# subseeker

`subseeker` is a single-file, multi-mode DNS reconnaissance tool. It speaks DNS
through [dnspython](https://www.dnspython.org/), which — unlike a
`getaddrinfo`-style call — keeps full visibility into CNAME chains, multi-record
answers, arbitrary record types, choice of resolver, and its own
timeouts/retries. It also has a **Certificate Transparency** mode that pulls
hostnames from CT logs, surfacing names that were never discoverable by querying
the apex or guessing with a generic wordlist.

> **Authorized use only.** Every mode performs active DNS reconnaissance. Run it
> only against domains and networks you own or have explicit permission to
> assess. Zone-transfer, cache-snooping, and CT probes in particular can be
> disruptive or considered hostile if run without authorization.

This is the Python port of the original Zig implementation. The Python version
trades the zero-dependency static binary for one dependency (`dnspython`) and
the huge simplification that HTTPS/TLS — needed for CT log fetching — is a
solved problem in the standard library.

---

## Requirements

- **Python 3.9+**
- **dnspython** (`pip install dnspython`)

---

## Install

```sh
pip install -r requirements.txt      # or: pip install dnspython
chmod +x subseeker.py
./subseeker.py --help
```

No build step — it is a single script. Drop it anywhere on your `PATH` if you
want it available as `subseeker`.

---

## Usage

```
subseeker <mode> [options]
```

### Modes

| Mode    | What it does                                                                 |
|---------|------------------------------------------------------------------------------|
| `std`   | General records (SOA, NS, A, AAAA, MX, TXT) + an automatic zone-transfer try |
| `brt`   | Brute-force subdomains from a wordlist (A/AAAA/CNAME) with wildcard detection |
| `axfr`  | Attempt a full zone transfer (AXFR) against every nameserver                  |
| `srv`   | Enumerate common SRV service records under the domain                         |
| `tld`   | Top-level-domain expansion: try the domain's base name across many TLDs       |
| `ptr`   | Reverse-lookup (PTR) an IPv4 range or CIDR                                    |
| `snoop` | DNS cache snooping (RD=0): ask a resolver whether hosts are cached            |
| `ct`    | Certificate Transparency: pull names from CT logs (certspotter + crt.sh)      |

### Options

| Flag                     | Meaning                                                              |
|--------------------------|---------------------------------------------------------------------|
| `-d, --domain <domain>`  | Target domain (std/brt/axfr/srv/tld/ct)                             |
| `-w, --wordlist <file>`  | Wordlist of labels (brt) or full hostnames (snoop)                 |
| `--range <cidr\|a-b>`    | IPv4 range or CIDR for `ptr` (e.g. `192.0.2.0/24`, `a.b.c.d-e.f.g.h`) |
| `-r, --resolver <ip>`    | IPv4 resolver, repeatable and rotated. `snoop` uses the first.      |
| `-t, --threads <n>`      | Concurrent workers (default 50)                                     |
| `--timeout <ms>`         | Per-query timeout in milliseconds (default 3000)                    |
| `--retries <n>`          | Retries per query on failure (default 2)                           |
| `-o, --output <fmt>`     | Output format: `text` (default) or `json` (NDJSON)                 |
| `--outfile <file>`       | Also write results to a file, in the chosen format                |
| `-6, --ipv6`             | Also query AAAA where relevant (brt/tld/ct)                        |
| `--no-wildcard`          | Disable wildcard detection (brt)                                   |
| `--show-wildcard`        | Report wildcard hits instead of suppressing them (brt)            |
| `--resolve`              | Resolve CT names through the worker pool (ct)                      |
| `--infile <file>`        | Read crt.sh JSON from a file instead of the network (ct)          |
| `--fetch`                | Force a network CT fetch even when stdin is a pipe (ct)           |
| `-v, --verbose`          | Verbose diagnostics on stderr                                     |
| `-h, --help`             | Show help                                                          |

Default resolvers (when no `-r` is given): `1.1.1.1`, `8.8.8.8`, `9.9.9.9`,
`8.8.4.4`.

The banner and live progress go to **stderr**; results go to **stdout**, so
`-o json` on stdout stays a clean, pipeable NDJSON stream.

---

## Concurrency

Every scanning mode (`brt`, `srv`, `tld`, `ptr`, `snoop`, and `ct --resolve`)
runs its lookups through a thread pool — up to `--threads` in flight at once
(default 50). DNS is I/O-bound and Python releases the GIL while waiting on the
network, so the workers genuinely overlap.

Effective concurrency is also capped by your resolvers: all workers rotate
across the resolvers you give (four public ones by default), so very high
`--threads` against public resolvers can trigger rate-limiting, timeouts, and
retries that make a scan *slower*. For large wordlists, prefer pointing `-r` at
resolvers that tolerate volume over simply raising `-t`.

---

## Certificate Transparency (`ct`)

CT logs record every TLS certificate ever issued, which leaks hostnames that
plain DNS queries never reveal. `ct` reads them from two sources and merges the
results, so a single flaky provider can't sink the run:

1. **certspotter** (`api.certspotter.com`) — queried first; cleaner and more
   reliable. Set `CERTSPOTTER_TOKEN` in your environment to raise the anonymous
   rate limit.
2. **crt.sh** — queried second; frequently returns 502s/timeouts, which is
   tolerated because certspotter usually already answered.

Names are stripped of wildcards (`*.ei.example.com` → `ei.example.com`),
lowercased, filtered to the target domain, and deduplicated across both sources.
It runs as a single command with **no cache file to manage**:

```sh
./subseeker.py ct -d example.com                 # list names from CT logs
./subseeker.py ct -d example.com --resolve       # list + resolve which still answer
./subseeker.py ct -d example.com --resolve -o json
```

Text output is one bare hostname per line — a clean wordlist you can pipe
straight into other modes:

```sh
./subseeker.py ct -d example.com | ./subseeker.py snoop -w /dev/stdin -r 8.8.8.8
```

Offline / cached input is still supported for reproducibility or when both
sources are down — feed crt.sh's `output=json` in via a file or stdin:

```sh
curl -s 'https://crt.sh/?q=%25.example.com&output=json' > ct.json
./subseeker.py ct -d example.com --infile ct.json --resolve
```

---

## Output formats

Text (default) is one tab-separated record per line:

```
example.com	A	192.0.2.10
www.example.com	CNAME	example.com.
```

`--output json` emits **NDJSON** — one JSON object per line, uniform across every
mode (`name`, `type`, `value`, plus an optional `wildcard: true` on brute-mode
wildcard hits):

```json
{"name":"www.example.com","type":"A","value":"192.0.2.10"}
{"name":"dev.example.com","type":"A","value":"192.0.2.11","wildcard":true}
```

NDJSON streams as results land. To collect it into one JSON document, slurp with
`jq`:

```sh
./subseeker.py brt -d example.com -w words.txt -o json | jq -s .
```

---

## Examples

```sh
# General records + zone-transfer attempt
./subseeker.py std   -d example.com

# Brute-force subdomains, save NDJSON to a file
./subseeker.py brt   -d example.com -w words.txt -o json --outfile found.json

# Zone transfer against every NS (a SUCCESS here is a finding to fix)
./subseeker.py axfr  -d example.com

# SRV service discovery, piped through jq
./subseeker.py srv   -d example.com -o json | jq .

# TLD expansion of the base name
./subseeker.py tld   -d example.com

# Reverse DNS over a CIDR
./subseeker.py ptr   --range 192.0.2.0/24

# Cache snooping against a specific resolver
./subseeker.py snoop -w hosts.txt -r 8.8.8.8

# Certificate Transparency, native, no cache
./subseeker.py ct    -d example.com --resolve
```

Wordlists are plain text, one entry per line; blank lines and lines starting
with `#` are ignored. For `brt` each line is a label (e.g. `www`, `dev`); for
`snoop` each line is a full hostname.

---

## Notes, limits, and extension points

- **TLD and SRV lists are representative subsets**, not the full IANA/service
  registries. They are plain lists near the top of `subseeker.py` (`TLD_LIST`,
  `SRV_LIST`) — add entries freely.
- **`ptr` ranges are capped at 65,536 addresses** (a `/16`) to avoid accidental
  huge scans. Widen `PTR_CAP` if you need to.
- **`snoop` is a point-in-time probe.** An empty result usually just means the
  name isn't currently cached by that resolver, not that the mode failed. Large
  shared resolvers are anycast, so different backends hold different caches.
- **crt.sh is flaky.** That is why `ct` queries certspotter first and only falls
  back to crt.sh; if both are down the run reports it and you simply retry.

---

## License

MIT License
