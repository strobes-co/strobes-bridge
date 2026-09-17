"""Network egress policy — the OS-independent core of the bridge's scope control.

The bridge runs arbitrary AI-issued commands. Because a command can be *any*
binary (``curl``, a static Go scanner, a python one-liner, a raw-socket SYN
scan), egress cannot be enforced by inspecting the command text — it must be
enforced below the process. This module owns the *policy* half of that story:
what a policy is, how user-supplied hostnames/IPs become one, how host names
resolve to addresses, and how the result is consumed by each enforcement lane:

* the **proxy lane** (the one in use) — commands run in an OS sandbox that can
  reach only the egress proxy, which asks :class:`Checker` about every
  connection. See :mod:`egress_proxy` and :mod:`procsandbox`.
* the **scan lane** (Linux rootless netns + nftables/ipset) — see
  :meth:`ResolvedPolicy.to_nftables`. Not yet wired: it is the answer for tools
  that need raw sockets (``nmap -sS``, naabu), which cannot speak to a proxy.

Nothing here touches the network or the host; it is pure data + rendering so it
can be unit-tested without root, a VM, or a live resolver. Resolution is the one
side-effecting step and is isolated in :meth:`NetworkPolicy.resolve`.

Design invariants:

* **Explicit over implicit.** This type never guesses: ``default_egress`` says
  what happens to traffic no rule matched, and an allowlist grants only what it
  names. The *bridge* starts open (see :func:`config.network_policy_env`) so an
  unconfigured agent still runs; that is a product default expressed by the
  caller, not a property of this type.
* **Deny wins.** A destination matched by both an allow and a deny entry is
  denied — deny rules only ever subtract access.
* **Carve-outs are explicit.** Loopback and DNS are always permitted (otherwise
  the sandbox cannot resolve names or talk to a local proxy); everything else is
  opt-in via the policy.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Iterable, Literal, Optional

Action = Literal["allow", "deny"]
Kind = Literal["host", "ip", "cidr"]

# Destinations that are always permitted regardless of policy, because blocking
# them breaks the sandbox itself rather than constraining it. Loopback lets a
# workload reach a local filtering proxy / its own services; DNS (:53) lets it
# resolve the very hostnames the allowlist is written in terms of.
_LOOPBACK_CIDRS = ("127.0.0.0/8", "::1/128")
_DNS_PORT = 53

# Ranges that are dangerous to expose by default even under an allow-all policy:
# cloud-metadata (SSRF → credential theft) and link-local. Callers that want
# these must add them explicitly; :meth:`ResolvedPolicy.hard_denied_cidrs`
# surfaces them so a lane can pin them shut ahead of any allow rule.
_METADATA_CIDRS = ("169.254.169.254/32", "fd00:ec2::254/128")
_LINK_LOCAL_CIDRS = ("169.254.0.0/16", "fe80::/10")


def classify(value: str) -> Kind:
    """Infer whether ``value`` is a bare IP, a CIDR block, or a hostname.

    Lets the platform (and a human) hand us "hostnames or IPs, any of it" in one
    flat list without tagging each entry.
    """
    v = value.strip()
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
        except ValueError:
            pass  # e.g. a URL slipped through — fall through to host handling
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        return "host"


def _strip_to_host(value: str) -> str:
    """Reduce a user entry to a bare host/ip/cidr token.

    Tolerates ``https://host/path``, ``host:443`` and trailing dots so a policy
    can be written the way a target list usually arrives — while preserving a
    CIDR suffix (``10.0.0.0/24``) and IPv6 literals (``2001:db8::1``).
    """
    v = value.strip()
    if "://" in v:  # a URL — drop scheme and any path
        v = v.split("://", 1)[1]
        v = v.split("/", 1)[0]
    # Strip a :port suffix only for a bare host:port (single colon, no CIDR
    # slash, not an IPv6 literal which carries several colons).
    if "/" not in v and v.count(":") == 1:
        v = v.split(":", 1)[0]
    return v.rstrip(".")


@dataclass(frozen=True)
class Entry:
    """A single allow/deny clause: a destination, optionally narrowed by port.

    ``ports`` is a set of allowed TCP/UDP ports; empty means "any port".
    ``proto`` restricts to ``tcp``/``udp`` when set.
    """

    kind: Kind
    value: str
    ports: frozenset[int] = field(default_factory=frozenset)
    proto: Optional[Literal["tcp", "udp"]] = None

    @classmethod
    def parse(cls, raw: str, ports: Iterable[int] = (), proto: Optional[str] = None) -> "Entry":
        token = _strip_to_host(raw)
        kind = classify(token)
        return cls(kind=kind, value=token, ports=frozenset(ports), proto=proto)  # type: ignore[arg-type]


@dataclass(frozen=True)
class NetworkPolicy:
    """An unresolved egress policy: allow/deny clauses over hosts, IPs and CIDRs.

    "Unresolved" because host entries are still names; call :meth:`resolve` to
    turn them into concrete addresses for the L3 lanes.
    """

    allow: tuple[Entry, ...] = ()
    deny: tuple[Entry, ...] = ()
    default_egress: Action = "deny"
    # Extra hard-deny ranges beyond metadata/link-local; always subtracted first.
    block_metadata: bool = True

    @classmethod
    def from_lists(
        cls,
        allow: Iterable[str] = (),
        deny: Iterable[str] = (),
        default_egress: Action = "deny",
        block_metadata: bool = True,
    ) -> "NetworkPolicy":
        """Build a policy from flat lists of hostname/IP/CIDR strings.

        This is the shape the platform sends and the shape a human writes: a
        list of in-scope targets, optionally a list of carve-out denies.
        """
        return cls(
            allow=tuple(Entry.parse(x) for x in allow if x and x.strip()),
            deny=tuple(Entry.parse(x) for x in deny if x and x.strip()),
            default_egress=default_egress,
            block_metadata=block_metadata,
        )

    @property
    def is_open(self) -> bool:
        """True when the policy grants unrestricted egress (nothing to enforce)."""
        return self.default_egress == "allow" and not self.deny

    def hosts(self) -> tuple[Entry, ...]:
        return tuple(e for e in self.allow + self.deny if e.kind == "host")

    def resolve(self, resolver: Optional["Resolver"] = None) -> "ResolvedPolicy":
        """Resolve every host entry to addresses and return a concrete policy.

        Host resolution is the only network-touching step in this module. IPs
        that fail to resolve are dropped (not fatal) so one dead name never
        voids an otherwise valid scope; the caller can inspect
        :attr:`ResolvedPolicy.unresolved` to surface warnings.
        """
        resolver = resolver or Resolver()
        allow_ips: set[str] = set()
        deny_ips: set[str] = set()
        unresolved: list[str] = []

        for bucket, sink in ((self.allow, allow_ips), (self.deny, deny_ips)):
            for e in bucket:
                if e.kind == "cidr":
                    sink.add(e.value)
                elif e.kind == "ip":
                    sink.add(_as_host_cidr(e.value))
                else:  # host
                    addrs = resolver.resolve(e.value)
                    if not addrs:
                        unresolved.append(e.value)
                    for a in addrs:
                        sink.add(_as_host_cidr(a))

        return ResolvedPolicy(
            source=self,
            allow_cidrs=frozenset(allow_ips),
            deny_cidrs=frozenset(deny_ips),
            unresolved=tuple(unresolved),
            resolved_at=time.time(),
        )


def _as_host_cidr(ip: str) -> str:
    """Normalise a bare IP into a single-host CIDR (``1.2.3.4`` → ``1.2.3.4/32``)."""
    addr = ipaddress.ip_address(ip)
    return f"{ip}/{addr.max_prefixlen}"


@dataclass(frozen=True)
class ResolvedPolicy:
    """A policy with every hostname reduced to concrete CIDRs — ready for L3.

    Immutable snapshot taken at :attr:`resolved_at`; hostnames whose A/AAAA
    records rotate need a fresh :meth:`NetworkPolicy.resolve`, which the
    enforcement lane schedules on DNS TTL.
    """

    source: NetworkPolicy
    allow_cidrs: frozenset[str]
    deny_cidrs: frozenset[str]
    unresolved: tuple[str, ...]
    resolved_at: float

    def hard_denied_cidrs(self) -> tuple[str, ...]:
        """Ranges pinned shut before any allow rule (metadata, link-local, +user denies)."""
        hard: list[str] = list(self.deny_cidrs)
        if self.source.block_metadata:
            hard = list(_METADATA_CIDRS) + list(_LINK_LOCAL_CIDRS) + hard
        # de-dup, preserve order
        seen: set[str] = set()
        out: list[str] = []
        for c in hard:
            if c not in seen:
                seen.add(c)
                out.append(c)
        return tuple(out)

    # -- scan lane (Linux netns + nftables) --------------------------------
    def to_nftables(self, table: str = "strobes_jail") -> str:
        """Render an ``nft`` ruleset for the scan lane's private namespace.

        Applied *inside* a rootless network namespace, so these are namespaced
        rules — they never appear in, or affect, the host's tables. Default-deny
        on the ``output`` hook, with loopback + DNS carved out first, hard-deny
        ranges dropped next, then the allow set accepted. nftables matches on the
        originating socket, so this catches raw-socket SYN scans that a userspace
        proxy would miss — the whole reason the scan lane exists.
        """
        allow4, allow6 = _split_family(self.allow_cidrs)
        deny4, deny6 = _split_family(self.hard_denied_cidrs())
        default = "accept" if self.source.default_egress == "allow" else "drop"

        lines = [f"table inet {table} {{"]
        if allow4:
            lines.append("  set allow4 { type ipv4_addr; flags interval;")
            lines.append(f"    elements = {{ {', '.join(sorted(allow4))} }} }}")
        if allow6:
            lines.append("  set allow6 { type ipv6_addr; flags interval;")
            lines.append(f"    elements = {{ {', '.join(sorted(allow6))} }} }}")
        lines.append("  chain output {")
        lines.append("    type filter hook output priority 0; policy drop;")
        lines.append("    ct state established,related accept")
        lines.append("    oif \"lo\" accept")
        for c in _LOOPBACK_CIDRS:
            fam = "ip6" if ":" in c else "ip"
            lines.append(f"    {fam} daddr {c} accept")
        # DNS must survive so the workload can resolve names.
        lines.append(f"    udp dport {_DNS_PORT} accept")
        lines.append(f"    tcp dport {_DNS_PORT} accept")
        # Hard denies before allows — deny wins.
        for c in deny4:
            lines.append(f"    ip daddr {c} drop")
        for c in deny6:
            lines.append(f"    ip6 daddr {c} drop")
        if allow4:
            lines.append("    ip daddr @allow4 accept")
        if allow6:
            lines.append("    ip6 daddr @allow6 accept")
        lines.append(f"    {default}")
        lines.append("  }")
        lines.append("}")
        return "\n".join(lines)


def _split_family(cidrs: Iterable[str]) -> tuple[list[str], list[str]]:
    """Partition CIDR strings into (IPv4, IPv6) lists."""
    v4: list[str] = []
    v6: list[str] = []
    for c in cidrs:
        (v6 if ":" in c else v4).append(c)
    return v4, v6


class Resolver:
    """Hostname → address resolver with a short TTL cache.

    Wraps :func:`socket.getaddrinfo` so :meth:`NetworkPolicy.resolve` stays
    testable (tests inject a fake). The cache keeps repeated policy refreshes
    from hammering DNS; ``ttl`` bounds staleness for names whose records rotate.
    """

    def __init__(self, ttl: float = 60.0):
        self.ttl = ttl
        self._cache: dict[str, tuple[float, tuple[str, ...]]] = {}

    def resolve(self, host: str) -> tuple[str, ...]:
        now = time.monotonic()
        hit = self._cache.get(host)
        if hit and (now - hit[0]) < self.ttl:
            return hit[1]
        addrs = self._lookup(host)
        self._cache[host] = (now, addrs)
        return addrs

    def _lookup(self, host: str) -> tuple[str, ...]:
        out: set[str] = set()
        try:
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    for info in socket.getaddrinfo(host, None, family, socket.SOCK_STREAM):
                        addr = info[4][0].split("%", 1)[0]  # drop any zone id
                        try:
                            ip = ipaddress.ip_address(addr)
                        except ValueError:
                            continue
                        # Skip IPv4-mapped IPv6 (::ffff:1.2.3.4) — the v4 lookup
                        # already carries the real address; the mapped form would
                        # pollute the v6 set with a duplicate.
                        if ip.version == 6 and ip.ipv4_mapped is not None:
                            continue
                        out.add(str(ip))
                except socket.gaierror:
                    continue
        except Exception:
            return tuple()
        return tuple(sorted(out))


# ---------------------------------------------------------------------------
# Proxy lane — the decision the egress proxy makes per connection
# ---------------------------------------------------------------------------

class Decision:
    """The answer to "may this connection proceed", with a reason either way.

    The reason matters as much as the verdict: a refusal that reaches the agent
    as "not in scope" lets it retarget, where a bare connection failure just
    makes it retry or conclude the host is down.
    """

    __slots__ = ("allowed", "reason", "addresses")

    def __init__(self, allowed: bool, reason: str, addresses: tuple = ()):
        self.allowed = allowed
        self.reason = reason
        #: The addresses this decision was made about. The caller must connect
        #: to one of *these* rather than resolving again — re-resolving would
        #: reopen the DNS-rebinding window the check just closed.
        self.addresses = addresses

    def __bool__(self) -> bool:
        return self.allowed

    def __repr__(self) -> str:
        return f"<Decision {'allow' if self.allowed else 'deny'}: {self.reason}>"


class Checker:
    """Evaluates a :class:`NetworkPolicy` against one destination.

    This is the enforcement point for the proxy lane. Unlike the L3 lanes it is
    handed the *name* the client asked for (SOCKS5 carries the hostname, so the
    proxy resolves rather than the sandbox), which means hostname rules are
    exact here: no DNS pinning, no rebinding window, and no CDN over-permission
    where one allowed name grants every other site on a shared address.

    Evaluation order mirrors the other lanes — deny always wins:

    1. hard denies (metadata, link-local), ahead of every allow rule
    2. deny rules, by name then by address
    3. allow rules, likewise
    4. default egress
    """

    def __init__(self, policy: NetworkPolicy, resolver: Optional["Resolver"] = None):
        self.policy = policy
        self.resolver = resolver or Resolver()
        self._hard = tuple(
            ipaddress.ip_network(c)
            for c in (_METADATA_CIDRS + _LINK_LOCAL_CIDRS)
        ) if policy.block_metadata else ()

    # -- matching helpers ---------------------------------------------------

    @staticmethod
    def _name_matches(entry: Entry, name: str) -> bool:
        if entry.kind != "host":
            return False
        want = entry.value.lower().rstrip(".")
        got = name.lower().rstrip(".")
        if want.startswith("."):  # domain and all subdomains
            return got == want[1:] or got.endswith(want)
        return got == want

    @staticmethod
    def _addr_matches(entry: Entry, ip: str) -> bool:
        if entry.kind not in ("ip", "cidr"):
            return False
        try:
            addr = ipaddress.ip_address(ip)
            net = ipaddress.ip_network(
                entry.value if entry.kind == "cidr" else _as_host_cidr(entry.value)
            )
        except ValueError:
            return False
        return addr in net

    @staticmethod
    def _port_proto_ok(entry: Entry, port: int, proto: str) -> bool:
        if entry.ports and port not in entry.ports:
            return False
        if entry.proto and entry.proto != proto:
            return False
        return True

    def _match(self, entries, host: str, ips: tuple, port: int, proto: str):
        """First entry matching this destination by name or by any address."""
        for e in entries:
            if not self._port_proto_ok(e, port, proto):
                continue
            if self._name_matches(e, host):
                return e
            if any(self._addr_matches(e, ip) for ip in ips):
                return e
        return None

    # -- the decision -------------------------------------------------------

    def check(self, host: str, port: int, proto: str = "tcp") -> Decision:
        """Decide whether ``host:port`` may be reached.

        ``host`` may be a name or a literal address. Names are resolved here so
        address rules still apply to them — a policy that allows ``10.0.0.0/8``
        must also permit a name that resolves into it.
        """
        literal = classify(host) in ("ip", "cidr")
        ips: tuple = (host,) if literal else self.resolver.resolve(host)

        # 1. Hard denies, ahead of every allow rule.
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for net in self._hard:
                if addr in net:
                    return Decision(False, f"{ip} is hard-denied (metadata/link-local)")

        # An unresolvable name cannot be checked against address rules, so it is
        # only reachable if a name rule names it.
        if not literal and not ips:
            hit = self._match(self.policy.allow, host, (), port, proto)
            if hit and self._name_matches(hit, host):
                return Decision(False, f"{host} could not be resolved")
            return Decision(False, f"{host} could not be resolved and is not in scope")

        # 2. Deny rules.
        hit = self._match(self.policy.deny, host, ips, port, proto)
        if hit:
            return Decision(False, f"denied by rule {hit.value}")

        # 3. Allow rules.
        hit = self._match(self.policy.allow, host, ips, port, proto)
        if hit:
            return Decision(True, f"allowed by rule {hit.value}", ips)

        # A near miss is worth reporting precisely: the destination is in scope
        # but this port is not, which is a different mistake from being out of
        # scope entirely.
        for e in self.policy.allow:
            if self._name_matches(e, host) or any(self._addr_matches(e, ip) for ip in ips):
                return Decision(False, f"{e.value} is in scope but port {port} is not")

        # 4. Default.
        if self.policy.default_egress == "allow":
            return Decision(True, "default egress is allow", ips)
        return Decision(False, "not in the engagement scope")
