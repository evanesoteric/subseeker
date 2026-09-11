//! subseeker — a multi-mode DNS reconnaissance tool.
//! ===========================================================================
//! Target: Zig 0.16.0 on Linux (x86_64 / aarch64).
//!
//! A single self-contained binary that speaks DNS on the wire (it hand-builds
//! query packets and parses wire responses byte by byte), inspired by the
//! feature set of dnsrecon. Because Zig 0.16 moved blocking socket/file/clock
//! wrappers behind the new `Io` abstraction, everything here talks to the
//! kernel directly through `std.os.linux` syscalls (socket, connect, sendto,
//! recvfrom, poll, read, write, open, close, clock_gettime, nanosleep,
//! getrandom). No libc, no Io plumbing — and, as a consequence, Linux-only.
//!
//! MODES
//!   std     General records for a domain (SOA, NS, A, AAAA, MX, TXT) and an
//!           automatic zone-transfer attempt against each NS.
//!   brt     Brute-force subdomains from a wordlist (A/AAAA/CNAME) with
//!           wildcard-response detection.
//!   axfr    Attempt a full zone transfer (AXFR, over TCP) against every NS.
//!   srv     Enumerate common SRV service records under the domain.
//!   tld     Top-level-domain expansion: try the domain's name across many TLDs.
//!   ptr     Reverse-lookup (PTR) an IPv4 range or CIDR.
//!   snoop   DNS cache snooping: ask a resolver (RD=0) whether it has given
//!           host records cached, without recursing.
//!
//! USAGE
//!   subseeker <mode> [options]
//!   subseeker std   -d example.com
//!   subseeker brt   -d example.com -w words.txt --output json
//!   subseeker axfr  -d example.com
//!   subseeker srv   -d example.com
//!   subseeker tld   -d example.com
//!   subseeker ptr   --range 192.0.2.0/24
//!   subseeker snoop -w hosts.txt -r 8.8.8.8
//!
//! ETHICS / SCOPE
//!   This performs active DNS reconnaissance. Run it only against domains and
//!   networks you own or are explicitly authorized to assess.
//! ===========================================================================

const std = @import("std");
const linux = std.os.linux;

// ===========================================================================
// Small syscall / time / io helpers
// ===========================================================================

/// Returns the syscall return value on success, or null on error. The Linux
/// syscall ABI packs errors as small negative return values; `linux.errno`
/// decodes them, with `.SUCCESS` meaning "no error".
fn sysOk(rc: usize) ?usize {
    return if (linux.errno(rc) == .SUCCESS) rc else null;
}

/// Monotonic milliseconds — used for query deadlines and elapsed timing.
fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}

fn sleepMs(ms: u64) void {
    var req = linux.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = linux.nanosleep(&req, null);
}

/// Write every byte of `bytes` to fd, looping over partial writes / EINTR.
fn writeAllFd(fd: i32, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => off += rc,
            .INTR => continue,
            else => return,
        }
    }
}

const STDOUT: i32 = 1;

/// Seed a PRNG from the kernel CSPRNG (getrandom), falling back to the clock.
/// Zig 0.16 removed `std.crypto.random`; each thread gets its own PRNG so no
/// locking is needed. Query IDs only need to be unpredictable enough to reject
/// stale/foreign datagrams, not cryptographic.
fn seedRng() std.Random.DefaultPrng {
    var seed: u64 = undefined;
    const rc = linux.getrandom(@ptrCast(&seed), @sizeOf(u64), 0);
    if (sysOk(rc) == null or rc != @sizeOf(u64)) seed = @bitCast(nowMs());
    return std.Random.DefaultPrng.init(seed);
}

/// A minimal compare-and-swap spinlock. `std.Thread.Mutex` moved under `Io` in
/// 0.16; our only contended section is emitting an occasional result line, so a
/// spinlock is simpler and dependency-free. Contention is low, so spinning is
/// effectively free.
const SpinLock = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    fn lock(self: *SpinLock) void {
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }
    fn unlock(self: *SpinLock) void {
        self.state.store(0, .release);
    }
};

// ===========================================================================
// DNS protocol constants
// ===========================================================================
// A DNS message (RFC 1035): a 12-byte header, then Question / Answer /
// Authority / Additional sections of resource records (RRs).

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const TYPE_AXFR: u16 = 252; // "transfer of an entire zone" — TCP only
const CLASS_IN: u16 = 1;

const RCODE_NXDOMAIN: u4 = 3;
const RCODE_SERVFAIL: u4 = 2;
const RCODE_REFUSED: u4 = 5;

const MAX_A = 16;
const MAX_AAAA = 16;
const MAX_CNAME = 8;
const MAX_NAME = 256; // a DNS name is at most 255 octets
const MAX_MSG = 4096; // UDP answers cap ~1500; TCP messages can be larger

// ===========================================================================
// IPv4 parsing and socket addresses
// ===========================================================================

/// Parse a dotted-quad IPv4 string into four octets, or null if invalid.
fn parseIpv4(s: []const u8) ?[4]u8 {
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return null;
        const v = std.fmt.parseInt(u16, part, 10) catch return null;
        if (v > 255) return null;
        octets[i] = @intCast(v);
        i += 1;
    }
    if (i != 4) return null;
    return octets;
}

/// A u32 in host order (a<<24|b<<16|c<<8|d) — handy for range iteration.
fn ipv4ToU32(o: [4]u8) u32 {
    return (@as(u32, o[0]) << 24) | (@as(u32, o[1]) << 16) | (@as(u32, o[2]) << 8) | o[3];
}
fn u32ToIpv4(v: u32) [4]u8 {
    return .{ @intCast((v >> 24) & 0xff), @intCast((v >> 16) & 0xff), @intCast((v >> 8) & 0xff), @intCast(v & 0xff) };
}

/// Build a `sockaddr.in`. The address u32's in-memory bytes must be the
/// network-order octets; `@bitCast` from [4]u8 preserves that layout on any host.
fn makeSockaddr(octets: [4]u8, port: u16) linux.sockaddr.in {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(octets) };
}

fn udpSocket() ?i32 {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, linux.IPPROTO.UDP);
    if (sysOk(rc) == null) return null;
    return @intCast(rc);
}

// ===========================================================================
// DNS query construction
// ===========================================================================

/// Encode a DNS query into `buf`, returning its length.
///   [0..2]  ID      — random; lets us match replies to this query
///   [2..4]  flags   — RD bit set when `rd` is true (0x0100)
///   [4..6]  QDCOUNT = 1, rest of the counts = 0
///   [12..]  QNAME (length-prefixed labels, 0-terminated), QTYPE, QCLASS
fn encodeQuery(buf: []u8, id: u16, fqdn: []const u8, qtype: u16, rd: bool) !usize {
    if (buf.len < 12) return error.BufferTooSmall;
    std.mem.writeInt(u16, buf[0..2], id, .big);
    std.mem.writeInt(u16, buf[2..4], if (rd) 0x0100 else 0x0000, .big);
    std.mem.writeInt(u16, buf[4..6], 1, .big);
    std.mem.writeInt(u16, buf[6..8], 0, .big);
    std.mem.writeInt(u16, buf[8..10], 0, .big);
    std.mem.writeInt(u16, buf[10..12], 0, .big);

    var pos: usize = 12;
    var it = std.mem.splitScalar(u8, fqdn, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue;
        if (label.len > 63) return error.LabelTooLong;
        if (pos + 1 + label.len + 1 > buf.len) return error.BufferTooSmall;
        buf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buf[pos .. pos + label.len], label);
        pos += label.len;
    }
    buf[pos] = 0;
    pos += 1;

    if (pos + 4 > buf.len) return error.BufferTooSmall;
    std.mem.writeInt(u16, buf[pos..][0..2], qtype, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], CLASS_IN, .big);
    pos += 2;
    return pos;
}

// ===========================================================================
// DNS name decoding (with compression-pointer handling)
// ===========================================================================

const NameResult = struct { written: usize, consumed: usize };

/// Decode a DNS name at `start`, following compression pointers (a 2-byte value
/// whose top bits are 11 points to an earlier offset). `consumed` counts the
/// bytes used *before the first jump*, so callers keep walking the record stream
/// correctly.
fn decodeName(msg: []const u8, start: usize, out: []u8) !NameResult {
    var pos = start;
    var written: usize = 0;
    var consumed: usize = 0;
    var jumped = false;
    var jumps: usize = 0;

    while (true) {
        if (pos >= msg.len) return error.Truncated;
        const len = msg[pos];
        if (len & 0xC0 == 0xC0) {
            if (pos + 1 >= msg.len) return error.Truncated;
            const ptr = (@as(usize, len & 0x3F) << 8) | msg[pos + 1];
            if (!jumped) consumed = pos + 2 - start;
            jumped = true;
            pos = ptr;
            jumps += 1;
            if (jumps > 32) return error.PointerLoop;
            continue;
        }
        if (len == 0) {
            pos += 1;
            if (!jumped) consumed = pos - start;
            break;
        }
        pos += 1;
        if (pos + len > msg.len) return error.Truncated;
        if (written != 0) {
            if (written + 1 > out.len) return error.NameTooLong;
            out[written] = '.';
            written += 1;
        }
        if (written + len > out.len) return error.NameTooLong;
        @memcpy(out[written .. written + len], msg[pos .. pos + len]);
        written += len;
        pos += len;
    }
    return .{ .written = written, .consumed = consumed };
}

// ===========================================================================
// Output buffer
// ===========================================================================
// Modes accumulate formatted lines into a growable buffer, then flush once to
// stdout (and an optional file). Threaded modes format each hit into a small
// per-worker buffer and flush it under a lock.

const Fmt = enum { text, json };

const Out = struct {
    buf: *std.ArrayList(u8),
    a: std.mem.Allocator,
    fmt: Fmt = .text,

    fn put(self: Out, s: []const u8) void {
        self.buf.appendSlice(self.a, s) catch {};
    }
    fn putFmt(self: Out, comptime f: []const u8, args: anytype) void {
        var tmp: [2048]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, f, args) catch return;
        self.put(s);
    }

    /// Diagnostic/header line — emitted only in text mode (it would otherwise
    /// break the one-object-per-line NDJSON contract).
    fn comment(self: Out, comptime f: []const u8, args: anytype) void {
        if (self.fmt == .text) self.putFmt(f, args);
    }

    /// Append a JSON string literal (surrounding quotes included) with the
    /// escaping required by RFC 8259 — important for TXT records, which can
    /// carry quotes, backslashes, and control bytes.
    fn jsonString(self: Out, s: []const u8) void {
        self.put("\"");
        for (s) |c| switch (c) {
            '"' => self.put("\\\""),
            '\\' => self.put("\\\\"),
            '\n' => self.put("\\n"),
            '\r' => self.put("\\r"),
            '\t' => self.put("\\t"),
            else => {
                if (c < 0x20) self.putFmt("\\u{x:0>4}", .{c}) else self.put(&[_]u8{c});
            },
        };
        self.put("\"");
    }

    /// Emit one resource record in the selected format. `value` is the same
    /// canonical string in both modes; JSON just wraps it in an object.
    fn record(self: Out, name: []const u8, rtype: []const u8, value: []const u8, wildcard: bool) void {
        switch (self.fmt) {
            .text => self.putFmt("{s}\t{s}\t{s}{s}\n", .{ name, rtype, value, if (wildcard) "\t(wildcard)" else "" }),
            .json => {
                self.put("{\"name\":");
                self.jsonString(name);
                self.put(",\"type\":\"");
                self.put(rtype);
                self.put("\",\"value\":");
                self.jsonString(value);
                if (wildcard) self.put(",\"wildcard\":true");
                self.put("}\n");
            },
        }
    }
};

/// Render an IPv6 address (RFC 4291 full form) into `buf`, returning the slice.
fn ipv6Str(buf: []u8, ip: [16]u8) []const u8 {
    var w: usize = 0;
    var g: usize = 0;
    while (g < 16) : (g += 2) {
        const hextet = (@as(u16, ip[g]) << 8) | ip[g + 1];
        const s = std.fmt.bufPrint(buf[w..], "{s}{x}", .{ if (g == 0) "" else ":", hextet }) catch break;
        w += s.len;
    }
    return buf[0..w];
}

// ===========================================================================
// Generic resource-record formatting
// ===========================================================================

/// Format a single RR's RDATA (by type) as human-readable text appended to
/// `out`, prefixed by its owner name. Names embedded in RDATA (NS/CNAME/PTR/MX/
/// SOA/SRV targets) may be compressed, so we decode against the whole message.
fn formatRR(msg: []const u8, out: Out, owner: []const u8, rtype: u16, rdata: usize, rdlen: usize, soa_seen: *usize) void {
    var nb: [MAX_NAME]u8 = undefined;
    var vb: [1024]u8 = undefined; // the record's value, rendered once for either format
    switch (rtype) {
        TYPE_A => if (rdlen == 4) {
            const v = std.fmt.bufPrint(&vb, "{d}.{d}.{d}.{d}", .{ msg[rdata], msg[rdata + 1], msg[rdata + 2], msg[rdata + 3] }) catch return;
            out.record(owner, "A", v, false);
        },
        TYPE_AAAA => if (rdlen == 16) {
            var ip: [16]u8 = undefined;
            @memcpy(&ip, msg[rdata..][0..16]);
            out.record(owner, "AAAA", ipv6Str(&vb, ip), false);
        },
        TYPE_NS => if (decodeName(msg, rdata, &nb)) |n| out.record(owner, "NS", nb[0..n.written], false) else |_| {},
        TYPE_CNAME => if (decodeName(msg, rdata, &nb)) |n| out.record(owner, "CNAME", nb[0..n.written], false) else |_| {},
        TYPE_PTR => if (decodeName(msg, rdata, &nb)) |n| out.record(owner, "PTR", nb[0..n.written], false) else |_| {},
        TYPE_MX => if (rdlen >= 3) {
            const pref = std.mem.readInt(u16, msg[rdata..][0..2], .big);
            if (decodeName(msg, rdata + 2, &nb)) |n| {
                const v = std.fmt.bufPrint(&vb, "{d} {s}", .{ pref, nb[0..n.written] }) catch return;
                out.record(owner, "MX", v, false);
            } else |_| {}
        },
        TYPE_TXT => {
            // Concatenate the record's character-strings into one value.
            var w: usize = 0;
            var p = rdata;
            const end = rdata + rdlen;
            while (p < end) {
                const l = msg[p];
                p += 1;
                if (p + l > end) break;
                if (w + l <= vb.len) {
                    @memcpy(vb[w .. w + l], msg[p .. p + l]);
                    w += l;
                }
                p += l;
            }
            out.record(owner, "TXT", vb[0..w], false);
        },
        TYPE_SOA => {
            soa_seen.* += 1;
            var nb2: [MAX_NAME]u8 = undefined;
            const mname = decodeName(msg, rdata, &nb) catch return;
            const rname = decodeName(msg, rdata + mname.consumed, &nb2) catch return;
            const nums = rdata + mname.consumed + rname.consumed;
            if (nums + 20 > msg.len) return;
            const serial = std.mem.readInt(u32, msg[nums..][0..4], .big);
            const refresh = std.mem.readInt(u32, msg[nums + 4 ..][0..4], .big);
            const retry = std.mem.readInt(u32, msg[nums + 8 ..][0..4], .big);
            const expire = std.mem.readInt(u32, msg[nums + 12 ..][0..4], .big);
            const minimum = std.mem.readInt(u32, msg[nums + 16 ..][0..4], .big);
            const v = std.fmt.bufPrint(&vb, "{s} {s} serial={d} refresh={d} retry={d} expire={d} minimum={d}", .{ nb[0..mname.written], nb2[0..rname.written], serial, refresh, retry, expire, minimum }) catch return;
            out.record(owner, "SOA", v, false);
        },
        TYPE_SRV => if (rdlen >= 7) {
            const pri = std.mem.readInt(u16, msg[rdata..][0..2], .big);
            const weight = std.mem.readInt(u16, msg[rdata + 2 ..][0..2], .big);
            const port = std.mem.readInt(u16, msg[rdata + 4 ..][0..2], .big);
            if (decodeName(msg, rdata + 6, &nb)) |n| {
                const v = std.fmt.bufPrint(&vb, "{d} {d} {d} {s}", .{ pri, weight, port, nb[0..n.written] }) catch return;
                out.record(owner, "SRV", v, false);
            } else |_| {}
        },
        else => {},
    }
}

/// Walk `count` RRs starting at `pos.*`, formatting each into `out` and
/// advancing `pos.*`. Returns how many SOA records were seen (AXFR uses this to
/// find the closing SOA).
fn walkRRs(msg: []const u8, pos: *usize, count: usize, out: Out) usize {
    var soa: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var nb: [MAX_NAME]u8 = undefined;
        const nm = decodeName(msg, pos.*, &nb) catch return soa;
        pos.* += nm.consumed;
        if (pos.* + 10 > msg.len) return soa;
        const rtype = std.mem.readInt(u16, msg[pos.*..][0..2], .big);
        const rdlen = std.mem.readInt(u16, msg[pos.* + 8 ..][0..2], .big);
        pos.* += 10;
        if (pos.* + rdlen > msg.len) return soa;
        formatRR(msg, out, nb[0..nm.written], rtype, pos.*, rdlen, &soa);
        pos.* += rdlen;
    }
    return soa;
}

/// Skip `count` questions, advancing `pos.*`.
fn skipQuestions(msg: []const u8, pos: *usize, count: usize) bool {
    var nb: [MAX_NAME]u8 = undefined;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const nm = decodeName(msg, pos.*, &nb) catch return false;
        pos.* += nm.consumed + 4; // QTYPE + QCLASS
        if (pos.* > msg.len) return false;
    }
    return true;
}

/// Format all answer records in a standard response into `out`. Returns the
/// number of answer records.
fn formatAnswers(msg: []const u8, out: Out) usize {
    if (msg.len < 12) return 0;
    const qd = std.mem.readInt(u16, msg[4..6], .big);
    const an = std.mem.readInt(u16, msg[6..8], .big);
    var pos: usize = 12;
    if (!skipQuestions(msg, &pos, qd)) return 0;
    _ = walkRRs(msg, &pos, an, out);
    return an;
}

/// Extract the names carried by answer records of a given type (used to read NS
/// targets for AXFR). Appends decoded names (owned copies) to `list`.
fn extractAnswerNames(msg: []const u8, want_type: u16, list: *std.ArrayList([]const u8), a: std.mem.Allocator) void {
    if (msg.len < 12) return;
    const qd = std.mem.readInt(u16, msg[4..6], .big);
    const an = std.mem.readInt(u16, msg[6..8], .big);
    var pos: usize = 12;
    if (!skipQuestions(msg, &pos, qd)) return;
    var i: usize = 0;
    while (i < an) : (i += 1) {
        var nb: [MAX_NAME]u8 = undefined;
        const nm = decodeName(msg, pos, &nb) catch return;
        pos += nm.consumed;
        if (pos + 10 > msg.len) return;
        const rtype = std.mem.readInt(u16, msg[pos..][0..2], .big);
        const rdlen = std.mem.readInt(u16, msg[pos + 8 ..][0..2], .big);
        pos += 10;
        if (pos + rdlen > msg.len) return;
        if (rtype == want_type) {
            var tb: [MAX_NAME]u8 = undefined;
            if (decodeName(msg, pos, &tb)) |t| {
                const copy = a.dupe(u8, tb[0..t.written]) catch return;
                list.append(a, copy) catch {};
            } else |_| {}
        }
        pos += rdlen;
    }
}

// ===========================================================================
// Typed response parsing (for brute / tld / snoop wildcard logic)
// ===========================================================================

const Outcome = enum { ok, no_answer, nxdomain, servfail, refused, bad };

const QueryResult = struct {
    a: [MAX_A][4]u8 = undefined,
    a_len: usize = 0,
    aaaa: [MAX_AAAA][16]u8 = undefined,
    aaaa_len: usize = 0,
    cname: [MAX_CNAME][MAX_NAME]u8 = undefined,
    cname_len: [MAX_CNAME]usize = undefined,
    cname_count: usize = 0,

    fn reset(self: *QueryResult) void {
        self.a_len = 0;
        self.aaaa_len = 0;
        self.cname_count = 0;
    }
    fn hasRecords(self: *const QueryResult) bool {
        return self.a_len > 0 or self.aaaa_len > 0 or self.cname_count > 0;
    }
};

fn parseTyped(msg: []const u8, expected_id: u16, out: *QueryResult) Outcome {
    out.reset();
    if (msg.len < 12) return .bad;
    if (std.mem.readInt(u16, msg[0..2], .big) != expected_id) return .bad;
    const flags = std.mem.readInt(u16, msg[2..4], .big);
    const rcode: u4 = @intCast(flags & 0x000F);
    const qd = std.mem.readInt(u16, msg[4..6], .big);
    const an = std.mem.readInt(u16, msg[6..8], .big);
    switch (rcode) {
        RCODE_NXDOMAIN => return .nxdomain,
        RCODE_SERVFAIL => return .servfail,
        RCODE_REFUSED => return .refused,
        0 => {},
        else => return .bad,
    }
    var pos: usize = 12;
    if (!skipQuestions(msg, &pos, qd)) return .bad;

    var i: usize = 0;
    while (i < an) : (i += 1) {
        var nb: [MAX_NAME]u8 = undefined;
        const nm = decodeName(msg, pos, &nb) catch return .bad;
        pos += nm.consumed;
        if (pos + 10 > msg.len) return .bad;
        const rtype = std.mem.readInt(u16, msg[pos..][0..2], .big);
        const rdlen = std.mem.readInt(u16, msg[pos + 8 ..][0..2], .big);
        pos += 10;
        if (pos + rdlen > msg.len) return .bad;
        switch (rtype) {
            TYPE_A => if (rdlen == 4 and out.a_len < MAX_A) {
                @memcpy(&out.a[out.a_len], msg[pos..][0..4]);
                out.a_len += 1;
            },
            TYPE_AAAA => if (rdlen == 16 and out.aaaa_len < MAX_AAAA) {
                @memcpy(&out.aaaa[out.aaaa_len], msg[pos..][0..16]);
                out.aaaa_len += 1;
            },
            TYPE_CNAME => if (out.cname_count < MAX_CNAME) {
                if (decodeName(msg, pos, &out.cname[out.cname_count])) |cn| {
                    out.cname_len[out.cname_count] = cn.written;
                    out.cname_count += 1;
                } else |_| {}
            },
            else => {},
        }
        pos += rdlen;
    }
    return if (out.hasRecords()) .ok else .no_answer;
}

// ===========================================================================
// UDP exchange (send + receive matching reply, with retries and rotation)
// ===========================================================================

const Exchange = struct { len: usize, id: u16 };

fn queryRawUDP(sock: i32, dest: *const linux.sockaddr.in, fqdn: []const u8, qtype: u16, rd: bool, timeout_ms: i32, rand: std.Random, out_buf: []u8) ?Exchange {
    var qbuf: [MAX_MSG]u8 = undefined;
    const id = rand.int(u16);
    const qlen = encodeQuery(&qbuf, id, fqdn, qtype, rd) catch return null;
    const alen: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (sysOk(linux.sendto(sock, &qbuf, qlen, 0, @ptrCast(dest), alen)) == null) return null;

    const deadline = nowMs() + timeout_ms;
    while (true) {
        const remaining = deadline - nowMs();
        if (remaining <= 0) return null;
        var fds = [_]linux.pollfd{.{ .fd = sock, .events = linux.POLL.IN, .revents = 0 }};
        const prc = linux.poll(&fds, 1, @intCast(remaining));
        switch (linux.errno(prc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return null,
        }
        if (prc == 0) return null;
        const rrc = linux.recvfrom(sock, out_buf.ptr, out_buf.len, 0, null, null);
        switch (linux.errno(rrc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return null,
        }
        if (rrc < 12) continue;
        if (std.mem.readInt(u16, out_buf[0..2], .big) != id) continue; // stale/foreign
        return .{ .len = rrc, .id = id };
    }
}

/// Rotate resolvers across retries. Returns the raw response (id already
/// validated).
fn exchange(sock: i32, resolvers: []const linux.sockaddr.in, rotation: usize, fqdn: []const u8, qtype: u16, rd: bool, cfg: *const Config, rand: std.Random, out_buf: []u8) ?Exchange {
    var attempt: usize = 0;
    while (attempt <= cfg.retries) : (attempt += 1) {
        const dest = &resolvers[(rotation + attempt) % resolvers.len];
        if (queryRawUDP(sock, dest, fqdn, qtype, rd, cfg.timeout_ms, rand, out_buf)) |ex| return ex;
    }
    return null;
}

// ===========================================================================
// TCP transport (for AXFR zone transfers)
// ===========================================================================

/// Non-blocking connect with a bounded timeout. Returns a connected fd or null.
fn tcpConnect(dest: *const linux.sockaddr.in, timeout_ms: i32) ?i32 {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.NONBLOCK, linux.IPPROTO.TCP);
    if (sysOk(rc) == null) return null;
    const fd: i32 = @intCast(rc);
    const alen: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    const crc = linux.connect(fd, @ptrCast(dest), alen);
    switch (linux.errno(crc)) {
        .SUCCESS => return fd, // connected instantly (e.g. loopback)
        .INPROGRESS, .AGAIN => {},
        else => {
            _ = linux.close(fd);
            return null;
        },
    }
    var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    const prc = linux.poll(&fds, 1, timeout_ms);
    if (sysOk(prc) == null or prc == 0 or (fds[0].revents & (linux.POLL.ERR | linux.POLL.HUP)) != 0) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

fn tcpWriteAll(fd: i32, bytes: []const u8, timeout_ms: i32) bool {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => off += rc,
            .INTR => continue,
            .AGAIN => {
                var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
                const prc = linux.poll(&fds, 1, timeout_ms);
                if (sysOk(prc) == null or prc == 0) return false;
            },
            else => return false,
        }
    }
    return true;
}

fn tcpReadN(fd: i32, dst: []u8, timeout_ms: i32) bool {
    var off: usize = 0;
    while (off < dst.len) {
        var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        const prc = linux.poll(&fds, 1, timeout_ms);
        if (sysOk(prc) == null or prc == 0) return false;
        const rc = linux.read(fd, dst[off..].ptr, dst.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return false; // peer closed
                off += rc;
            },
            .INTR, .AGAIN => continue,
            else => return false,
        }
    }
    return true;
}

/// DNS-over-TCP frames each message with a 2-byte length prefix. Send one query.
fn tcpSendQuery(fd: i32, q: []const u8, timeout_ms: i32) bool {
    const lb = [2]u8{ @intCast((q.len >> 8) & 0xff), @intCast(q.len & 0xff) };
    if (!tcpWriteAll(fd, &lb, timeout_ms)) return false;
    return tcpWriteAll(fd, q, timeout_ms);
}

/// Read one length-prefixed TCP message into `buf`; returns its length or null.
fn tcpRecvMsg(fd: i32, buf: []u8, timeout_ms: i32) ?usize {
    var lb: [2]u8 = undefined;
    if (!tcpReadN(fd, &lb, timeout_ms)) return null;
    const n = (@as(usize, lb[0]) << 8) | lb[1];
    if (n == 0 or n > buf.len) return null;
    if (!tcpReadN(fd, buf[0..n], timeout_ms)) return null;
    return n;
}

// ===========================================================================
// Wildcard detection (brute mode)
// ===========================================================================
const WildcardSet = struct {
    active: bool = false,
    a: [MAX_A][4]u8 = undefined,
    a_len: usize = 0,
    aaaa: [MAX_AAAA][16]u8 = undefined,
    aaaa_len: usize = 0,

    fn addA(self: *WildcardSet, ip: [4]u8) void {
        for (self.a[0..self.a_len]) |e| if (std.mem.eql(u8, &e, &ip)) return;
        if (self.a_len < MAX_A) {
            self.a[self.a_len] = ip;
            self.a_len += 1;
        }
    }
    fn addAAAA(self: *WildcardSet, ip: [16]u8) void {
        for (self.aaaa[0..self.aaaa_len]) |e| if (std.mem.eql(u8, &e, &ip)) return;
        if (self.aaaa_len < MAX_AAAA) {
            self.aaaa[self.aaaa_len] = ip;
            self.aaaa_len += 1;
        }
    }
    fn containsA(self: *const WildcardSet, ip: [4]u8) bool {
        for (self.a[0..self.a_len]) |e| if (std.mem.eql(u8, &e, &ip)) return true;
        return false;
    }
    fn containsAAAA(self: *const WildcardSet, ip: [16]u8) bool {
        for (self.aaaa[0..self.aaaa_len]) |e| if (std.mem.eql(u8, &e, &ip)) return true;
        return false;
    }
};

fn randomLabel(buf: []u8, rand: std.Random) []u8 {
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (buf) |*c| c.* = alphabet[rand.intRangeLessThan(usize, 0, alphabet.len)];
    return buf;
}

fn detectWildcard(sock: i32, resolvers: []const linux.sockaddr.in, domain: []const u8, cfg: *const Config, rand: std.Random) WildcardSet {
    var set = WildcardSet{};
    var fqdn_buf: [MAX_NAME]u8 = undefined;
    var label_buf: [20]u8 = undefined;
    var msg: [MAX_MSG]u8 = undefined;
    var typed: QueryResult = .{};

    var probe: usize = 0;
    while (probe < 3) : (probe += 1) {
        const label = randomLabel(&label_buf, rand);
        const fqdn = std.fmt.bufPrint(&fqdn_buf, "{s}.{s}", .{ label, domain }) catch continue;
        if (exchange(sock, resolvers, probe, fqdn, TYPE_A, true, cfg, rand, &msg)) |ex| {
            if (parseTyped(msg[0..ex.len], ex.id, &typed) == .ok) {
                set.active = true;
                for (typed.a[0..typed.a_len]) |ip| set.addA(ip);
            }
        }
        if (cfg.want_aaaa) {
            if (exchange(sock, resolvers, probe, fqdn, TYPE_AAAA, true, cfg, rand, &msg)) |ex| {
                if (parseTyped(msg[0..ex.len], ex.id, &typed) == .ok) {
                    set.active = true;
                    for (typed.aaaa[0..typed.aaaa_len]) |ip| set.addAAAA(ip);
                }
            }
        }
    }
    return set;
}

fn isWildcardHit(res: *const QueryResult, set: *const WildcardSet) bool {
    if (!set.active) return false;
    if (res.cname_count > 0) return false;
    if (res.a_len == 0 and res.aaaa_len == 0) return false;
    for (res.a[0..res.a_len]) |ip| if (!set.containsA(ip)) return false;
    for (res.aaaa[0..res.aaaa_len]) |ip| if (!set.containsAAAA(ip)) return false;
    return true;
}

fn appendTypedRecords(out: Out, fqdn: []const u8, res: *const QueryResult, wildcard: bool) void {
    var vb: [64]u8 = undefined;
    for (res.cname[0..res.cname_count], 0..) |cn, idx| out.record(fqdn, "CNAME", cn[0..res.cname_len[idx]], wildcard);
    for (res.a[0..res.a_len]) |ip| {
        const v = std.fmt.bufPrint(&vb, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch continue;
        out.record(fqdn, "A", v, wildcard);
    }
    for (res.aaaa[0..res.aaaa_len]) |ip| out.record(fqdn, "AAAA", ipv6Str(&vb, ip), wildcard);
}

// ===========================================================================
// Configuration and modes
// ===========================================================================
const Mode = enum { std, brt, axfr, srv, tld, ptr, snoop };

const Config = struct {
    mode: Mode = .std,
    domain: []const u8 = "",
    wordlist_path: []const u8 = "",
    range: []const u8 = "",
    threads: usize = 50,
    timeout_ms: i32 = 3000,
    retries: usize = 2,
    format: Fmt = .text,
    outfile_path: ?[]const u8 = null,
    want_aaaa: bool = false,
    verbose: bool = false,
    detect_wildcard: bool = true,
    show_wildcard: bool = false,
};

const default_resolvers = [_][]const u8{ "1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4" };

// A compact TLD list for `tld` expansion (a representative subset, not the full
// IANA registry — extend as needed).
const tld_list = [_][]const u8{
    "com",    "net",    "org",  "info", "biz",    "io",  "co",   "us",
    "uk",     "co.uk",  "ca",   "de",   "fr",     "nl",  "eu",   "ru",
    "jp",     "cn",     "au",   "com.au", "br",   "it",  "es",   "se",
    "ch",     "at",     "be",   "dk",   "no",     "fi",  "pl",   "cz",
    "in",     "me",     "tv",   "cc",   "xyz",    "app", "dev",  "online",
    "site",   "tech",   "store","shop", "cloud",  "ai",  "sh",   "gg",
};

// Common SRV service labels (prefixed to the domain).
const srv_list = [_][]const u8{
    "_sip._tcp",             "_sip._udp",           "_sips._tcp",
    "_sipfederationtls._tcp","_ldap._tcp",          "_ldaps._tcp",
    "_kerberos._tcp",        "_kerberos._udp",      "_kpasswd._tcp",
    "_kpasswd._udp",         "_gc._tcp",            "_xmpp-client._tcp",
    "_xmpp-server._tcp",     "_jabber._tcp",        "_imap._tcp",
    "_imaps._tcp",           "_pop3._tcp",          "_pop3s._tcp",
    "_smtp._tcp",            "_submission._tcp",    "_caldav._tcp",
    "_caldavs._tcp",         "_carddav._tcp",       "_carddavs._tcp",
    "_autodiscover._tcp",    "_http._tcp",          "_https._tcp",
    "_ftp._tcp",             "_ssh._tcp",           "_ntp._udp",
    "_minecraft._tcp",       "_matrix._tcp",        "_stun._udp",
    "_turn._udp",            "_h323cs._tcp",
};

// ===========================================================================
// Threaded engine — shared by brt / srv / tld / ptr / snoop
// ===========================================================================
const Shared = struct {
    cfg: *const Config,
    candidates: []const []const u8,
    next: std.atomic.Value(usize),
    done: std.atomic.Value(usize),
    found: std.atomic.Value(usize),
    resolvers: []const linux.sockaddr.in,
    wildcard: *const WildcardSet,
    out_lock: SpinLock,
    out_fd: i32,
};

fn reverseName(buf: []u8, ip: [4]u8) ![]u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}.in-addr.arpa", .{ ip[3], ip[2], ip[1], ip[0] });
}

fn emitLocked(shared: *Shared, bytes: []const u8) void {
    shared.out_lock.lock();
    defer shared.out_lock.unlock();
    writeAllFd(STDOUT, bytes);
    if (shared.out_fd >= 0) writeAllFd(shared.out_fd, bytes);
}

fn worker(shared: *Shared, worker_index: usize) void {
    const sock = udpSocket() orelse return;
    defer _ = linux.close(sock);

    var prng = seedRng();
    const rand = prng.random();

    var msg: [MAX_MSG]u8 = undefined;
    var name_buf: [MAX_NAME]u8 = undefined;
    var typed: QueryResult = .{};

    const cfg = shared.cfg;

    var linebuf: std.ArrayList(u8) = .empty;
    defer linebuf.deinit(std.heap.smp_allocator);
    const out = Out{ .buf = &linebuf, .a = std.heap.smp_allocator, .fmt = cfg.format };

    while (true) {
        const idx = shared.next.fetchAdd(1, .monotonic);
        if (idx >= shared.candidates.len) break;
        const cand = shared.candidates[idx];

        var qtype: u16 = TYPE_A;
        var rd = true;
        const name: []const u8 = switch (cfg.mode) {
            .brt, .srv => blk: {
                if (cfg.mode == .srv) qtype = TYPE_SRV;
                break :blk std.fmt.bufPrint(&name_buf, "{s}.{s}", .{ cand, cfg.domain }) catch {
                    _ = shared.done.fetchAdd(1, .monotonic);
                    continue;
                };
            },
            .tld => cand,
            .snoop => cand,
            .ptr => blk: {
                qtype = TYPE_PTR;
                const octets = parseIpv4(cand) orelse {
                    _ = shared.done.fetchAdd(1, .monotonic);
                    continue;
                };
                break :blk reverseName(&name_buf, octets) catch {
                    _ = shared.done.fetchAdd(1, .monotonic);
                    continue;
                };
            },
            else => unreachable,
        };
        if (cfg.mode == .snoop) rd = false; // cache snoop: do not recurse

        linebuf.clearRetainingCapacity();

        switch (cfg.mode) {
            .brt, .tld, .snoop => {
                var outcome: Outcome = .bad;
                if (exchange(sock, shared.resolvers, worker_index, name, TYPE_A, rd, cfg, rand, &msg)) |ex|
                    outcome = parseTyped(msg[0..ex.len], ex.id, &typed);

                if (cfg.want_aaaa) {
                    var v6: QueryResult = .{};
                    if (exchange(sock, shared.resolvers, worker_index + 1, name, TYPE_AAAA, rd, cfg, rand, &msg)) |ex| {
                        if (parseTyped(msg[0..ex.len], ex.id, &v6) == .ok) {
                            for (v6.aaaa[0..v6.aaaa_len]) |ip| if (typed.aaaa_len < MAX_AAAA) {
                                typed.aaaa[typed.aaaa_len] = ip;
                                typed.aaaa_len += 1;
                            };
                            outcome = .ok;
                        }
                    }
                }

                if (outcome == .ok and typed.hasRecords()) {
                    var suppress = false;
                    var wc_hit = false;
                    if (cfg.mode == .brt) {
                        const wc = isWildcardHit(&typed, shared.wildcard);
                        if (wc) {
                            if (cfg.show_wildcard) wc_hit = true else suppress = true;
                        }
                    }
                    if (!suppress) {
                        _ = shared.found.fetchAdd(1, .monotonic);
                        appendTypedRecords(out, name, &typed, wc_hit);
                        emitLocked(shared, linebuf.items);
                    }
                }
            },
            .srv, .ptr => {
                if (exchange(sock, shared.resolvers, worker_index, name, qtype, rd, cfg, rand, &msg)) |ex| {
                    const n = formatAnswers(msg[0..ex.len], out);
                    if (n > 0 and linebuf.items.len > 0) {
                        _ = shared.found.fetchAdd(1, .monotonic);
                        emitLocked(shared, linebuf.items);
                    }
                }
            },
            else => unreachable,
        }

        _ = shared.done.fetchAdd(1, .monotonic);
    }
}

fn runThreaded(allocator: std.mem.Allocator, cfg: *const Config, candidates: []const []const u8, resolvers: []const linux.sockaddr.in, wildcard: *const WildcardSet, out_fd: i32) !void {
    var nthreads = cfg.threads;
    if (nthreads == 0) nthreads = 1;
    if (nthreads > candidates.len) nthreads = candidates.len;
    if (nthreads > 512) nthreads = 512;

    var shared = Shared{
        .cfg = cfg,
        .candidates = candidates,
        .next = std.atomic.Value(usize).init(0),
        .done = std.atomic.Value(usize).init(0),
        .found = std.atomic.Value(usize).init(0),
        .resolvers = resolvers,
        .wildcard = wildcard,
        .out_lock = .{},
        .out_fd = out_fd,
    };

    const start = nowMs();
    const threads = try allocator.alloc(std.Thread, nthreads);
    defer allocator.free(threads);
    for (threads, 0..) |*t, k| t.* = try std.Thread.spawn(.{}, worker, .{ &shared, k });

    while (true) {
        const done = shared.done.load(.monotonic);
        const found = shared.found.load(.monotonic);
        if (done >= candidates.len) break;
        std.debug.print("\r  progress: {d}/{d}  found: {d}   ", .{ done, candidates.len, found });
        sleepMs(150);
    }
    for (threads) |t| t.join();

    const elapsed = nowMs() - start;
    std.debug.print("\r{s}\r", .{" " ** 52});
    std.debug.print("\nDone. Checked {d} in {d:.2}s — {d} result(s).\n", .{
        candidates.len, @as(f64, @floatFromInt(elapsed)) / 1000.0, shared.found.load(.monotonic),
    });
}

// ===========================================================================
// Sequential modes: std (general records) and axfr (zone transfer)
// ===========================================================================

fn queryToOut(sock: i32, resolvers: []const linux.sockaddr.in, cfg: *const Config, rand: std.Random, name: []const u8, qtype: u16, label: []const u8, out: Out) void {
    var msg: [MAX_MSG]u8 = undefined;
    if (exchange(sock, resolvers, 0, name, qtype, true, cfg, rand, &msg)) |ex| {
        const before = out.buf.items.len;
        _ = formatAnswers(msg[0..ex.len], out);
        if (out.buf.items.len == before) out.comment("; no {s} records\n", .{label});
    } else {
        out.comment("; {s} query failed (timeout)\n", .{label});
    }
}

fn runStd(allocator: std.mem.Allocator, cfg: *const Config, resolvers: []const linux.sockaddr.in, out_fd: i32) !void {
    const sock = udpSocket() orelse return;
    defer _ = linux.close(sock);
    var prng = seedRng();
    const rand = prng.random();

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    const out = Out{ .buf = &buf, .a = allocator, .fmt = cfg.format };

    out.comment("; General records for {s}\n", .{cfg.domain});
    queryToOut(sock, resolvers, cfg, rand, cfg.domain, TYPE_SOA, "SOA", out);
    queryToOut(sock, resolvers, cfg, rand, cfg.domain, TYPE_NS, "NS", out);
    queryToOut(sock, resolvers, cfg, rand, cfg.domain, TYPE_A, "A", out);
    queryToOut(sock, resolvers, cfg, rand, cfg.domain, TYPE_AAAA, "AAAA", out);
    queryToOut(sock, resolvers, cfg, rand, cfg.domain, TYPE_MX, "MX", out);
    queryToOut(sock, resolvers, cfg, rand, cfg.domain, TYPE_TXT, "TXT", out);

    writeAllFd(STDOUT, buf.items);
    if (out_fd >= 0) writeAllFd(out_fd, buf.items);

    // dnsrecon's std also attempts a zone transfer; do the same.
    std.debug.print("\n", .{});
    try attemptAxfr(allocator, cfg, resolvers, out_fd, false);
}

/// Resolve the domain's NS names, resolve each NS to IPv4, and try AXFR (TCP)
/// against each. On success the whole zone is printed.
fn attemptAxfr(allocator: std.mem.Allocator, cfg: *const Config, resolvers: []const linux.sockaddr.in, out_fd: i32, standalone: bool) !void {
    const sock = udpSocket() orelse return;
    defer _ = linux.close(sock);
    var prng = seedRng();
    const rand = prng.random();

    var msg: [MAX_MSG]u8 = undefined;

    var ns_names: std.ArrayList([]const u8) = .empty;
    defer ns_names.deinit(allocator);
    if (exchange(sock, resolvers, 0, cfg.domain, TYPE_NS, true, cfg, rand, &msg)) |ex|
        extractAnswerNames(msg[0..ex.len], TYPE_NS, &ns_names, allocator);

    if (ns_names.items.len == 0) {
        std.debug.print("[axfr] No NS records found for {s}.\n", .{cfg.domain});
        return;
    }
    std.debug.print("[axfr] {d} nameserver(s) for {s}:\n", .{ ns_names.items.len, cfg.domain });

    var any_ok = false;
    for (ns_names.items) |ns| {
        var typed: QueryResult = .{};
        var ns_ip: ?[4]u8 = null;
        if (exchange(sock, resolvers, 0, ns, TYPE_A, true, cfg, rand, &msg)) |ex| {
            if (parseTyped(msg[0..ex.len], ex.id, &typed) == .ok and typed.a_len > 0) ns_ip = typed.a[0];
        }
        if (ns_ip == null) {
            std.debug.print("    {s}: could not resolve to IPv4 — skipping\n", .{ns});
            continue;
        }
        const ip = ns_ip.?;
        std.debug.print("    {s} ({d}.{d}.{d}.{d}): ", .{ ns, ip[0], ip[1], ip[2], ip[3] });
        if (transferZone(allocator, cfg, ip, out_fd)) any_ok = true;
    }
    if (!any_ok and standalone) std.debug.print("[axfr] No nameserver allowed a zone transfer (this is the secure default).\n", .{});
}

/// Perform the actual AXFR against one nameserver IP over TCP. Returns true on
/// success (records received).
fn transferZone(allocator: std.mem.Allocator, cfg: *const Config, ns_ip: [4]u8, out_fd: i32) bool {
    var dest = makeSockaddr(ns_ip, 53);
    const fd = tcpConnect(&dest, cfg.timeout_ms) orelse {
        std.debug.print("connect failed\n", .{});
        return false;
    };
    defer _ = linux.close(fd);

    var prng = seedRng();
    const rand = prng.random();
    var qbuf: [MAX_MSG]u8 = undefined;
    const qlen = encodeQuery(&qbuf, rand.int(u16), cfg.domain, TYPE_AXFR, false) catch return false;
    if (!tcpSendQuery(fd, qbuf[0..qlen], cfg.timeout_ms)) {
        std.debug.print("send failed\n", .{});
        return false;
    }

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    const out = Out{ .buf = &buf, .a = allocator, .fmt = cfg.format };

    var msg: [MAX_MSG]u8 = undefined;
    var soa_total: usize = 0;
    var rr_total: usize = 0;

    // A zone transfer arrives as one or more messages; it begins and ends with
    // the zone's SOA. Read until we've seen the closing SOA.
    while (tcpRecvMsg(fd, &msg, cfg.timeout_ms)) |n| {
        if (n < 12) break;
        const rcode: u4 = @intCast(std.mem.readInt(u16, msg[2..4], .big) & 0x000F);
        if (rcode == RCODE_REFUSED) {
            std.debug.print("REFUSED (transfer not allowed)\n", .{});
            return false;
        }
        const qd = std.mem.readInt(u16, msg[4..6], .big);
        const an = std.mem.readInt(u16, msg[6..8], .big);
        var pos: usize = 12;
        if (!skipQuestions(msg[0..n], &pos, qd)) break;
        soa_total += walkRRs(msg[0..n], &pos, an, out);
        rr_total += an;
        if (soa_total >= 2) break; // closing SOA reached
    }

    if (rr_total == 0) {
        std.debug.print("no records (refused or empty)\n", .{});
        return false;
    }

    std.debug.print("ZONE TRANSFER SUCCEEDED — {d} records:\n", .{rr_total});
    writeAllFd(STDOUT, buf.items);
    if (out_fd >= 0) writeAllFd(out_fd, buf.items);
    return true;
}

// ===========================================================================
// Candidate list builders
// ===========================================================================

/// Split file bytes into trimmed, comment-stripped lines (slices into `bytes`).
fn splitLines(allocator: std.mem.Allocator, bytes: []const u8) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r\n");
        if (line.len == 0 or line[0] == '#') continue;
        try list.append(allocator, line);
    }
    return list.toOwnedSlice(allocator);
}

/// Build "<base>.<tld>" for every TLD, where base is the domain minus its final
/// label (e.g. "arcanesolutions.io" -> base "arcanesolutions").
fn buildTldCandidates(allocator: std.mem.Allocator, domain: []const u8) ![][]const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, domain, '.') orelse domain.len;
    const base = domain[0..dot];
    var list: std.ArrayList([]const u8) = .empty;
    for (tld_list) |tld| {
        const s = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ base, tld });
        try list.append(allocator, s);
    }
    return list.toOwnedSlice(allocator);
}

fn srvCandidates(allocator: std.mem.Allocator) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    for (srv_list) |s| try list.append(allocator, s);
    return list.toOwnedSlice(allocator);
}

/// Expand a CIDR ("a.b.c.d/n") or a range ("a.b.c.d-e.f.g.h") into IP strings.
fn buildPtrCandidates(allocator: std.mem.Allocator, range: []const u8) ![][]const u8 {
    var start: u32 = 0;
    var end: u32 = 0;

    if (std.mem.indexOfScalar(u8, range, '/')) |slash| {
        const ip = parseIpv4(range[0..slash]) orelse return error.BadRange;
        const prefix = std.fmt.parseInt(u6, range[slash + 1 ..], 10) catch return error.BadRange;
        if (prefix > 32) return error.BadRange;
        const base = ipv4ToU32(ip);
        const mask: u32 = if (prefix == 0) 0 else (~@as(u32, 0)) << @intCast(32 - prefix);
        start = base & mask;
        end = start | ~mask;
    } else if (std.mem.indexOfScalar(u8, range, '-')) |dash| {
        const a = parseIpv4(range[0..dash]) orelse return error.BadRange;
        const b = parseIpv4(range[dash + 1 ..]) orelse return error.BadRange;
        start = ipv4ToU32(a);
        end = ipv4ToU32(b);
        if (end < start) return error.BadRange;
    } else {
        const a = parseIpv4(range) orelse return error.BadRange;
        start = ipv4ToU32(a);
        end = start;
    }

    const count: u64 = @as(u64, end - start) + 1;
    if (count > 65536) return error.RangeTooLarge;

    var list: std.ArrayList([]const u8) = .empty;
    var v = start;
    while (true) {
        const o = u32ToIpv4(v);
        const s = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ o[0], o[1], o[2], o[3] });
        try list.append(allocator, s);
        if (v == end) break;
        v += 1;
    }
    return list.toOwnedSlice(allocator);
}

// ===========================================================================
// File loading (raw syscalls)
// ===========================================================================
fn readFileAll(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    const ofd = linux.open(path_z.ptr, .{}, 0);
    if (sysOk(ofd) == null) return error.OpenFailed;
    const fd: i32 = @intCast(ofd);
    defer _ = linux.close(fd);

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var chunk: [65536]u8 = undefined;
    while (true) {
        const rc = linux.read(fd, &chunk, chunk.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (rc == 0) break;
        try list.appendSlice(allocator, chunk[0..rc]);
    }
    return list.toOwnedSlice(allocator);
}

// ===========================================================================
// Argument parsing
// ===========================================================================
fn printUsage() void {
    const usage =
        \\subseeker — multi-mode DNS reconnaissance tool (Zig 0.16.0, Linux)
        \\
        \\USAGE:
        \\  subseeker <mode> [options]
        \\
        \\MODES:
        \\  std     General records (SOA, NS, A, AAAA, MX, TXT) + zone-transfer attempt
        \\  brt     Brute-force subdomains from a wordlist (A/AAAA/CNAME) + wildcard check
        \\  axfr    Attempt a zone transfer (AXFR, over TCP) against every NS
        \\  srv     Enumerate common SRV service records under the domain
        \\  tld     Top-level-domain expansion of the domain's name
        \\  ptr     Reverse-lookup (PTR) an IPv4 range or CIDR
        \\  snoop   DNS cache snooping (RD=0) of hosts against a specific resolver
        \\
        \\OPTIONS:
        \\  -d, --domain <domain>   Target domain (std/brt/axfr/srv/tld)
        \\  -w, --wordlist <file>   Wordlist of labels (brt) or full hosts (snoop)
        \\      --range <cidr|a-b>   IPv4 range/CIDR for ptr mode
        \\  -r, --resolver <ip>      IPv4 resolver (repeatable; rotated). snoop uses the first.
        \\                           Default: 1.1.1.1, 8.8.8.8, 9.9.9.9, 8.8.4.4
        \\  -t, --threads <n>        Concurrent workers (default 50)
        \\      --timeout <ms>       Per-query timeout in ms (default 3000)
        \\      --retries <n>        Retries per query on failure (default 2)
        \\  -o, --output <fmt>       Output format: text (default) or json (NDJSON, one object/line)
        \\      --outfile <file>     Also write results to this file (in the chosen format)
        \\  -6, --ipv6               Also query AAAA where relevant (brt/tld/snoop)
        \\      --no-wildcard        Disable wildcard detection (brt)
        \\      --show-wildcard      Report wildcard hits instead of suppressing (brt)
        \\  -v, --verbose            Verbose diagnostics on stderr
        \\  -h, --help               Show this help
        \\
        \\EXAMPLES:
        \\  subseeker std   -d example.com
        \\  subseeker brt   -d example.com -w words.txt --output json
        \\  subseeker brt   -d example.com -w words.txt --outfile found.json -o json
        \\  subseeker axfr  -d example.com
        \\  subseeker srv   -d example.com --output json | jq .
        \\  subseeker tld   -d example.com
        \\  subseeker ptr   --range 192.0.2.0/24
        \\  subseeker snoop -w hosts.txt -r 8.8.8.8
        \\
        \\Only run against domains and networks you are authorized to assess.
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
fn nextVal(args: []const []const u8, i: *usize) ![]const u8 {
    if (i.* + 1 >= args.len) return error.MissingValue;
    i.* += 1;
    return args[i.*];
}
fn parseUsize(s: []const u8) !usize {
    return std.fmt.parseInt(usize, s, 10) catch error.BadNumber;
}

fn parseMode(s: []const u8) ?Mode {
    if (eq(s, "std")) return .std;
    if (eq(s, "brt") or eq(s, "brute")) return .brt;
    if (eq(s, "axfr")) return .axfr;
    if (eq(s, "srv")) return .srv;
    if (eq(s, "tld")) return .tld;
    if (eq(s, "ptr")) return .ptr;
    if (eq(s, "snoop")) return .snoop;
    return null;
}

fn parseFmt(s: []const u8) ?Fmt {
    if (eq(s, "text") or eq(s, "txt")) return .text;
    if (eq(s, "json") or eq(s, "ndjson")) return .json;
    return null;
}

fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8, cfg: *Config, resolvers: *std.ArrayList([]const u8)) !bool {
    var i: usize = 1;
    if (args.len > 1 and args[1].len > 0 and args[1][0] != '-') {
        cfg.mode = parseMode(args[1]) orelse {
            std.debug.print("Unknown mode: {s}\n\n", .{args[1]});
            printUsage();
            return error.Unknown;
        };
        i = 2;
    }
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (eq(a, "-h") or eq(a, "--help")) {
            printUsage();
            return false;
        } else if (eq(a, "-d") or eq(a, "--domain")) {
            cfg.domain = try nextVal(args, &i);
        } else if (eq(a, "-w") or eq(a, "--wordlist")) {
            cfg.wordlist_path = try nextVal(args, &i);
        } else if (eq(a, "--range")) {
            cfg.range = try nextVal(args, &i);
        } else if (eq(a, "-r") or eq(a, "--resolver")) {
            try resolvers.append(allocator, try nextVal(args, &i));
        } else if (eq(a, "-t") or eq(a, "--threads")) {
            cfg.threads = try parseUsize(try nextVal(args, &i));
        } else if (eq(a, "--timeout")) {
            cfg.timeout_ms = @intCast(try parseUsize(try nextVal(args, &i)));
        } else if (eq(a, "--retries")) {
            cfg.retries = try parseUsize(try nextVal(args, &i));
        } else if (eq(a, "-o") or eq(a, "--output")) {
            cfg.format = parseFmt(try nextVal(args, &i)) orelse return error.BadFormat;
        } else if (eq(a, "--outfile")) {
            cfg.outfile_path = try nextVal(args, &i);
        } else if (eq(a, "-6") or eq(a, "--ipv6")) {
            cfg.want_aaaa = true;
        } else if (eq(a, "--no-wildcard")) {
            cfg.detect_wildcard = false;
        } else if (eq(a, "--show-wildcard")) {
            cfg.show_wildcard = true;
        } else if (eq(a, "-v") or eq(a, "--verbose")) {
            cfg.verbose = true;
        } else {
            std.debug.print("Unknown argument: {s}\n\n", .{a});
            printUsage();
            return error.Unknown;
        }
    }
    return true;
}

// ===========================================================================
// main
// ===========================================================================
pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;

    var argv_list: std.ArrayList([]const u8) = .empty;
    defer argv_list.deinit(allocator);
    {
        var it = init.minimal.args.iterate();
        while (it.next()) |a| try argv_list.append(allocator, a);
    }
    const args = argv_list.items;

    if (args.len < 2) {
        printUsage();
        return;
    }

    var cfg = Config{};
    var resolver_strs: std.ArrayList([]const u8) = .empty;
    defer resolver_strs.deinit(allocator);

    const should_run = parseArgs(allocator, args, &cfg, &resolver_strs) catch |e| {
        switch (e) {
            error.MissingValue => std.debug.print("Error: an option is missing its value.\n", .{}),
            error.BadNumber => std.debug.print("Error: expected a number.\n", .{}),
            error.BadFormat => std.debug.print("Error: --output must be 'text' or 'json'.\n", .{}),
            else => {},
        }
        return;
    };
    if (!should_run) return;

    const resolver_input: []const []const u8 = if (resolver_strs.items.len > 0) resolver_strs.items else &default_resolvers;
    const resolver_addrs = try allocator.alloc(linux.sockaddr.in, resolver_input.len);
    defer allocator.free(resolver_addrs);
    for (resolver_input, 0..) |rs, k| {
        const octets = parseIpv4(rs) orelse {
            std.debug.print("Error: invalid IPv4 resolver '{s}'\n", .{rs});
            return;
        };
        resolver_addrs[k] = makeSockaddr(octets, 53);
    }

    const needs_domain = switch (cfg.mode) {
        .std, .brt, .axfr, .srv, .tld => true,
        else => false,
    };
    if (needs_domain and cfg.domain.len == 0) {
        std.debug.print("Error: mode '{s}' requires -d <domain>.\n\n", .{@tagName(cfg.mode)});
        printUsage();
        return;
    }

    var out_fd: i32 = -1;
    if (cfg.outfile_path) |p| {
        const p_z = try allocator.dupeZ(u8, p);
        defer allocator.free(p_z);
        const rc = linux.open(p_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (sysOk(rc) == null) {
            std.debug.print("Error: cannot open output file '{s}'\n", .{p});
            return;
        }
        out_fd = @intCast(rc);
    }
    defer if (out_fd >= 0) {
        _ = linux.close(out_fd);
    };

    std.debug.print("subseeker — mode: {s}\n", .{@tagName(cfg.mode)});
    std.debug.print("  resolvers: ", .{});
    for (resolver_input, 0..) |rs, k| std.debug.print("{s}{s}", .{ if (k == 0) "" else ", ", rs });
    std.debug.print("   timeout: {d}ms   retries: {d}\n\n", .{ cfg.timeout_ms, cfg.retries });

    switch (cfg.mode) {
        .std => try runStd(allocator, &cfg, resolver_addrs, out_fd),
        .axfr => try attemptAxfr(allocator, &cfg, resolver_addrs, out_fd, true),
        .brt, .srv, .tld, .ptr, .snoop => {
            var file_bytes: ?[]u8 = null;
            defer if (file_bytes) |fb| allocator.free(fb);

            const candidates: [][]const u8 = switch (cfg.mode) {
                .brt => blk: {
                    if (cfg.wordlist_path.len == 0) {
                        std.debug.print("Error: brt requires -w <wordlist>.\n", .{});
                        return;
                    }
                    file_bytes = readFileAll(allocator, cfg.wordlist_path) catch {
                        std.debug.print("Error: cannot read wordlist '{s}'.\n", .{cfg.wordlist_path});
                        return;
                    };
                    break :blk try splitLines(allocator, file_bytes.?);
                },
                .snoop => blk: {
                    if (cfg.wordlist_path.len == 0) {
                        std.debug.print("Error: snoop requires -w <hosts-file>.\n", .{});
                        return;
                    }
                    if (resolver_strs.items.len == 0) {
                        std.debug.print("Error: snoop requires an explicit resolver via -r (the server whose cache you probe).\n", .{});
                        return;
                    }
                    file_bytes = readFileAll(allocator, cfg.wordlist_path) catch {
                        std.debug.print("Error: cannot read hosts file '{s}'.\n", .{cfg.wordlist_path});
                        return;
                    };
                    break :blk try splitLines(allocator, file_bytes.?);
                },
                .srv => try srvCandidates(allocator),
                .tld => try buildTldCandidates(allocator, cfg.domain),
                .ptr => blk: {
                    if (cfg.range.len == 0) {
                        std.debug.print("Error: ptr requires --range <cidr|a-b>.\n", .{});
                        return;
                    }
                    break :blk buildPtrCandidates(allocator, cfg.range) catch |e| {
                        switch (e) {
                            error.RangeTooLarge => std.debug.print("Error: range too large (max 65536 addresses). Narrow it.\n", .{}),
                            else => std.debug.print("Error: invalid --range '{s}'.\n", .{cfg.range}),
                        }
                        return;
                    };
                },
                else => unreachable,
            };
            defer allocator.free(candidates);

            if (candidates.len == 0) {
                std.debug.print("Nothing to do (empty candidate list).\n", .{});
                return;
            }

            var wildcard = WildcardSet{};
            if (cfg.mode == .brt and cfg.detect_wildcard) {
                if (udpSocket()) |s| {
                    var wp = seedRng();
                    wildcard = detectWildcard(s, resolver_addrs, cfg.domain, &cfg, wp.random());
                    _ = linux.close(s);
                }
                if (wildcard.active)
                    std.debug.print("[!] Wildcard DNS detected for {s} — matching hits suppressed (use --show-wildcard).\n\n", .{cfg.domain});
            }

            try runThreaded(allocator, &cfg, candidates, resolver_addrs, &wildcard, out_fd);
        },
    }
}
