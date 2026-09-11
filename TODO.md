# Todo

adding a new record type is mostly a new arm
in `formatRR` (and `parseTyped` if brute/tld/snoop should react to it); the
DNS-over-TCP transport (`tcpConnect` / `tcpRecvMsg`) already exists for AXFR and
could back a general truncation (TC=1) fallback.
