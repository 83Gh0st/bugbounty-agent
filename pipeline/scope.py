"""Scope parsing and validation.

This is the safety boundary for the whole pipeline: nothing gets actively
tested (port scan, vuln scan, content discovery) unless it matches an entry
here. Supports one entry per line:

    example.com         exact domain (apex only)
    *.example.com       domain + all subdomains
    192.168.1.10         single IP
    192.168.1.0/24       CIDR block

Lines starting with # are comments. Blank lines are ignored. Anything that
doesn't parse as a domain/wildcard/IP/CIDR is flagged invalid and excluded.
"""
import ipaddress
import re

DOMAIN_RE = re.compile(
    r"^(\*\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class ScopeEntry:
    def __init__(self, raw):
        self.raw = raw.strip()
        self.kind = None
        self.value = None
        self._network = None
        self._parse()

    def _parse(self):
        s = self.raw
        try:
            if "/" in s:
                self._network = ipaddress.ip_network(s, strict=False)
                self.kind, self.value = "cidr", s
                return
            ipaddress.ip_address(s)
            self.kind, self.value = "ip", s
            return
        except ValueError:
            pass
        if s.startswith("*."):
            self.kind, self.value = "wildcard", s[2:].lower()
            return
        if DOMAIN_RE.match(s):
            self.kind, self.value = "domain", s.lower()
            return
        self.kind, self.value = "invalid", s

    @property
    def network(self):
        return self._network

    def matches_host(self, host):
        host = host.lower().strip().rstrip(".")
        if self.kind == "domain":
            return host == self.value
        if self.kind == "wildcard":
            return host == self.value or host.endswith("." + self.value)
        return False

    def matches_ip(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.kind == "ip":
            return str(addr) == self.value
        if self.kind == "cidr":
            return addr in self._network
        return False


class Scope:
    def __init__(self, text):
        self.entries = []
        self.invalid = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            e = ScopeEntry(line)
            (self.invalid if e.kind == "invalid" else self.entries).append(
                line if e.kind == "invalid" else e
            )

    @property
    def domain_roots(self):
        return sorted({e.value for e in self.entries if e.kind in ("domain", "wildcard")})

    @property
    def ip_ranges(self):
        return [e for e in self.entries if e.kind in ("ip", "cidr")]

    def host_in_scope(self, host):
        return any(e.matches_host(host) for e in self.entries if e.kind in ("domain", "wildcard"))

    def ip_in_scope(self, ip):
        return any(e.matches_ip(ip) for e in self.entries if e.kind in ("ip", "cidr"))

    def is_empty(self):
        return not self.entries
