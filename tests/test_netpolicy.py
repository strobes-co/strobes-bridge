"""Tests for the OS-independent network egress policy core."""

from strobes_shell_agent.netpolicy import (
    Entry,
    NetworkPolicy,
    Resolver,
    classify,
)


class FakeResolver(Resolver):
    """Deterministic resolver so tests never touch DNS."""

    def __init__(self, table):
        super().__init__(ttl=0)
        self._table = table

    def _lookup(self, host):
        return tuple(self._table.get(host, ()))


# -- classify / parse -------------------------------------------------------

def test_classify_detects_kinds():
    assert classify("1.2.3.4") == "ip"
    assert classify("10.0.0.0/8") == "cidr"
    assert classify("example.com") == "host"
    assert classify("2001:db8::1") == "ip"
    assert classify("2001:db8::/32") == "cidr"


def test_entry_parse_strips_scheme_and_port():
    assert Entry.parse("https://example.com/path").value == "example.com"
    assert Entry.parse("example.com:443").value == "example.com"
    assert Entry.parse("1.2.3.4:80").value == "1.2.3.4"
    # IPv6 literal must survive its colons.
    assert Entry.parse("2001:db8::1").value == "2001:db8::1"


# -- default-deny invariants ------------------------------------------------

def test_empty_policy_is_default_deny_not_open():
    p = NetworkPolicy.from_lists(allow=[])
    assert p.default_egress == "deny"
    assert p.is_open is False


def test_open_policy_detected():
    assert NetworkPolicy.from_lists(default_egress="allow").is_open is True
    # a deny rule means there is still something to enforce
    assert NetworkPolicy.from_lists(deny=["1.2.3.4"], default_egress="allow").is_open is False


# -- resolution -------------------------------------------------------------

def test_resolve_mixes_hosts_ips_cidrs():
    p = NetworkPolicy.from_lists(allow=["scanme.example.com", "10.0.0.0/24", "8.8.8.8"])
    r = p.resolve(FakeResolver({"scanme.example.com": ["203.0.113.7"]}))
    assert "203.0.113.7/32" in r.allow_cidrs
    assert "10.0.0.0/24" in r.allow_cidrs
    assert "8.8.8.8/32" in r.allow_cidrs
    assert r.unresolved == ()


def test_unresolved_host_is_recorded_not_fatal():
    p = NetworkPolicy.from_lists(allow=["good.example.com", "dead.example.com"])
    r = p.resolve(FakeResolver({"good.example.com": ["1.1.1.1"]}))
    assert "1.1.1.1/32" in r.allow_cidrs
    assert "dead.example.com" in r.unresolved


# -- nftables rendering (scan lane) ----------------------------------------

def test_nftables_scopes_rules_to_the_sandbox_uid():
    """The bridge's own traffic must survive its own ruleset.

    Without the uid guard the table would apply to the whole machine, including
    the websocket the bridge reports results over.
    """
    nft = NetworkPolicy.from_lists(allow=["1.2.3.4"]).resolve().to_nftables(uid=1500)
    assert "meta skuid != 1500 accept" in nft
    assert "ip daddr @allow4 accept" in nft
    assert "1.2.3.4/32" in nft


def test_nftables_rejects_rather_than_drops():
    """A dropped packet is indistinguishable from a black hole.

    The caller waits out a full TCP timeout and a scanner reports the port as
    filtered. Rejecting fails immediately and says so.
    """
    nft = NetworkPolicy.from_lists(allow=["1.2.3.4"]).resolve().to_nftables(uid=1500)
    assert "reject" in nft
    assert "drop" not in nft


def test_nftables_does_not_carve_out_loopback():
    """Loopback is the operator's own machine, so it must be asked for.

    Same rule as the proxy lane: reaching a local service is a scope decision,
    not a freebie.
    """
    nft = NetworkPolicy.from_lists(allow=["1.2.3.4"]).resolve().to_nftables(uid=1500)
    assert "127.0.0.0/8 accept" not in nft
    assert 'oif "lo" accept' not in nft
    # DNS is the one exception, or a hostname scope cannot resolve.
    assert "udp dport 53 accept" in nft


def test_nftables_hard_denies_metadata_before_allow():
    p = NetworkPolicy.from_lists(allow=["0.0.0.0/0"])
    nft = p.resolve().to_nftables(uid=1500)
    deny_idx = nft.index("169.254.169.254/32 reject")
    allow_idx = nft.index("@allow4 accept")
    assert deny_idx < allow_idx  # deny wins — metadata shut before the allow


def test_nftables_open_policy_still_blocks_metadata():
    nft = NetworkPolicy.from_lists(default_egress="allow").resolve().to_nftables(uid=1500)
    assert "169.254.169.254/32 reject" in nft
    assert nft.rstrip().endswith("accept\n  }\n}") or "    accept" in nft


def test_nftables_ipv6_set_separate():
    p = NetworkPolicy.from_lists(allow=["2001:db8::1", "1.2.3.4"])
    nft = p.resolve().to_nftables(uid=1500)
    assert "set allow6" in nft
    assert "set allow4" in nft
    assert "ip6 daddr @allow6 accept" in nft
