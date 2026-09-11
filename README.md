# subseeker

![Subseeker Banner](assets/subseeker-banner.jpg)

`subseeker` is a single-binary, multi-mode DNS reconnaissance tool written in **Zig 0.16.0**.
It speaks DNS on the wire — hand-building query packets and parsing wire
responses byte by byte — rather than leaning on a resolver library, which gives
it real concurrency, its own timeouts and retries, choice of resolvers, and full
visibility into CNAME chains, multi-record answers, and record types a
`getaddrinfo`-style call hides.

> **Authorized use only.** Every mode performs active DNS reconnaissance. Run it
> only against domains and networks you own or have explicit permission to
> assess. Zone-transfer and cache-snooping probes in particular can be
> disruptive or considered hostile if run without authorization.

---

## Requirements

- **Zig 0.16.0** (the code targets 0.16 idioms exactly and will not build on
  older/newer releases without changes).
- **Linux** (x86_64 or aarch64).

Zig 0.16 moved its blocking socket/file/clock wrappers behind the new `Io`
abstraction. Rather than adopt that plumbing, subseeker talks to the kernel
directly through `std.os.linux` syscalls (`socket`, `connect`, `sendto`,
`recvfrom`, `poll`, `read`, `write`, `open`, `close`, `clock_gettime`,
`nanosleep`, `getrandom`). The upside is zero dependencies — no libc, no `Io`.
The trade-off is that it is **Linux-only** by design.

---

## Build

```sh
zig build                            # -> zig-out/bin/subseeker (Debug)
zig build -Doptimize=ReleaseSafe      # optimized, safety checks on (recommended)
zig build -Doptimize=ReleaseFast      # optimized, fewer checks (large scans)
zig build run -- std -d example.com   # build then run; args after `--` go to the tool
```

A bare `zig build` produces a Debug binary. For real use pass
`-Doptimize=ReleaseSafe` — it optimizes while keeping the runtime safety checks
on, a sensible default for a tool parsing untrusted packets off the network; use
`-Doptimize=ReleaseFast` for large scans once you trust your inputs. Because
subseeker links no libc (it uses raw Linux syscalls), the resulting binary is
**statically linked** and portable across distributions with no runtime
dependencies.

Cross-compiling to another Linux target is a one-flag change, e.g.
`zig build -Doptimize=ReleaseSafe -Dtarget=aarch64-linux`.

### Project layout

```
subseeker/
├── build.zig          # exe-only build script (points at src/main.zig)
├── build.zig.zon      # package manifest (keep the auto-generated fingerprint)
├── .gitignore
├── README.md
└── src/
    └── main.zig       # the entire tool (single file)
```

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
| `axfr`  | Attempt a full zone transfer (AXFR, over TCP) against every nameserver        |
| `srv`   | Enumerate common SRV service records under the domain                         |
| `tld`   | Top-level-domain expansion: try the domain's name across many TLDs            |
| `ptr`   | Reverse-lookup (PTR) an IPv4 range or CIDR                                    |
| `snoop` | DNS cache snooping (RD=0): ask a resolver whether hosts are cached            |

### Options

| Flag                     | Meaning                                                              |
|--------------------------|---------------------------------------------------------------------|
| `-d, --domain <domain>`  | Target domain (std/brt/axfr/srv/tld)                                 |
| `-w, --wordlist <file>`  | Wordlist of labels (brt) or full hostnames (snoop)                  |
| `--range <cidr\|a-b>`    | IPv4 range or CIDR for `ptr` mode (e.g. `192.0.2.0/24`, `a.b.c.d-e.f.g.h`) |
| `-r, --resolver <ip>`    | IPv4 resolver, repeatable and rotated. `snoop` uses the first.       |
| `-t, --threads <n>`      | Concurrent workers (default 50)                                      |
| `--timeout <ms>`         | Per-query timeout in milliseconds (default 3000)                     |
| `--retries <n>`          | Retries per query on failure (default 2)                             |
| `-o, --output <fmt>`     | Output format: `text` (default) or `json` (NDJSON)                   |
| `--outfile <file>`       | Also write results to a file, in the chosen format                  |
| `-6, --ipv6`             | Also query AAAA where relevant (brt/tld/snoop)                       |
| `--no-wildcard`          | Disable wildcard detection (brt)                                     |
| `--show-wildcard`        | Report wildcard hits instead of suppressing them (brt)              |
| `-v, --verbose`          | Verbose diagnostics on stderr                                       |
| `-h, --help`             | Show help                                                           |

Default resolvers (when no `-r` is given): `1.1.1.1`, `8.8.8.8`, `9.9.9.9`,
`8.8.4.4`.

The banner and live progress go to **stderr**; results go to **stdout**, so
`-o json` on stdout stays clean and pipeable.

---

## Output formats

Text (default) is one tab-separated record per line:

```
zone.test	SOA	ns1.zone.test hostmaster.zone.test serial=... refresh=... ...
www.zone.test	A	192.0.2.10
```

`--output json` (or `-o json`) emits **NDJSON** — one JSON object per line:

```json
{"name":"www.zone.test","type":"A","value":"192.0.2.10"}
{"name":"dev.zone.test","type":"A","value":"192.0.2.11","wildcard":true}
```

Every mode emits the same uniform shape — `name`, `type`, `value`, plus an
optional `wildcard: true` on brute-mode wildcard hits — so downstream parsing
never has to special-case the mode. NDJSON was chosen over a single array so
results stream out of the concurrent workers as they land. To collect them into
one JSON document, slurp with `jq`:

```sh
subseeker brt -d example.com -w words.txt -o json | jq -s .
```

---

## Examples

```sh
# General records + zone-transfer attempt
subseeker std   -d example.com

# Brute-force subdomains, save NDJSON to a file
subseeker brt   -d example.com -w words.txt -o json --outfile found.json

# Zone transfer against every NS (a SUCCESS here is a finding to fix)
subseeker axfr  -d example.com

# SRV service discovery, piped through jq
subseeker srv   -d example.com -o json | jq .

# TLD expansion of the base name
subseeker tld   -d example.com

# Reverse DNS over a CIDR
subseeker ptr   --range 192.0.2.0/24

# Cache snooping against a specific resolver
subseeker snoop -w hosts.txt -r 8.8.8.8
```

Wordlists are plain text, one entry per line; blank lines and lines starting
with `#` are ignored. For `brt` each line is a label (e.g. `www`, `dev`); for
`snoop` each line is a full hostname.

---

## Notes, limits, and extension points

This is a foundation meant to be built on. Some deliberate boundaries:

- **Resolvers are IPv4** at the socket layer. AAAA *record* queries still work
  over that transport, so IPv6 discovery is unaffected — only the resolver's own
  address must be IPv4.
- **`ptr` ranges are capped at 65,536 addresses** (a `/16`) to avoid accidental
  huge scans. Widen the cap in `buildPtrCandidates` if you need to.
- **The TLD and SRV lists are representative subsets**, not the full IANA/service
  registries. They're plain arrays near the top of `src/main.zig`
  (`tld_list`, `srv_list`) — add entries freely.
- **`ptr` prints the `in-addr.arpa` owner name** rather than reformatting back to
  a dotted quad.

---

## License

MIT License
