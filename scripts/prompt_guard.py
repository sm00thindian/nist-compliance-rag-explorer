#!/usr/bin/env python3
"""
Ring 0 prompt guard: a Claude Code UserPromptSubmit hook.

Ring 0's rule is "public data only; describe the question, not the system".
This hook scans each prompt before it is sent and blocks it when it finds
something that looks system-identifying: IPv4/IPv6 addresses, MAC addresses,
hostnames with private suffixes (.local, .corp, .internal, .lan, .home.arpa,
...) and FQDNs or URLs whose domain is not on the public allowlist.

Hook contract (https://code.claude.com/docs/en/hooks, UserPromptSubmit):
  stdin   JSON with the submitted text in "prompt".
  block   JSON {"decision": "block", "reason": ...} on stdout; the reason is
          shown to the user and not added to Claude's context. We also exit 2
          with the reason on stderr, so the prompt is blocked even if a Claude
          Code version rejects part of the JSON. "suppressOriginalPrompt"
          keeps the prompt text out of the block message.
  allow   exit 0 with no output.

Override: a prompt that starts with "#public-ok" is allowed as-is.
Allowlist: built in, plus optional config/prompt_guard_allowlist.txt
(one domain per line, "#" comments).

Standard library only. Fails open (exit 0, no output) on malformed input or
any internal error. Never writes the prompt anywhere; the block reason shows
findings masked (10.x.x.x, web01.…).

    echo '{"prompt": "is 10.1.2.3 compliant?"}' | python3 scripts/prompt_guard.py
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys

OVERRIDE = "#public-ok"
MAX_SHOWN = 3

ALLOWLIST_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "config", "prompt_guard_allowlist.txt")

# Public domains; a host matches if it equals one or is a subdomain of one.
PUBLIC_DOMAINS = {
    "nist.gov", "csrc.nist.gov", "cyber.mil", "public.cyber.mil", "disa.mil",
    "mitre.org", "saf.mitre.org", "github.com", "githubusercontent.com",
    "anthropic.com", "claude.ai", "claude.com", "libreoffice.org",
    "python.org", "pypi.org",
    # RFC 2606 / 6761 names reserved for examples; never identify a system.
    "example.com", "example.org", "example.net", "example", "test", "invalid",
    "localhost",
}

# Suffixes that only exist inside organizations.
PRIVATE_SUFFIXES = ("local", "corp", "internal", "intranet", "lan", "localdomain",
                    "home.arpa", "private")

# TLDs recognized in bare (non-URL) names. Deliberately curated: TLDs that
# collide with file extensions or code attributes (py, md, sh, pl, rs, so, tf,
# info, name, id, app, zip, ...) and with 800-53 family codes (ac, au, ca, cm,
# ir, pe, pl, pm, ps, pt, ra, sa, sc, si, sr, ...) are left out. Names in URLs
# (scheme://host) are checked whatever their TLD.
PUBLIC_TLDS = {
    "gov", "mil", "edu", "com", "net", "org", "int", "us", "uk", "io", "co",
    "biz", "cloud", "online", "site", "tech", "dev", "xyz", "ai",
    "de", "fr", "jp", "cn", "ru", "eu", "nl", "ch", "se", "nz", "ie", "es",
    "kr", "br", "mx", "za", "il", "tw", "sg", "hk", "be", "dk", "fi", "no",
    "it", "gr", "tr", "ua", "ro", "hu", "cz", "ar", "cl", "ae", "qa",
}

# Product names that look like domains.
NOT_HOSTS = {"asp.net", "vb.net", "ado.net"}

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOST_RE = re.compile(r"(?<![\w.@-])(?:%s\.)+[A-Za-z]{2,63}(?![\w-]|\.[A-Za-z0-9])" % _LABEL)
EMAIL_HOST_RE = re.compile(r"(?<=[\w.+-]@)(?:%s\.)*%s(?![\w-]|\.[A-Za-z0-9])" % (_LABEL, _LABEL))
URL_HOST_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{0,15}://(?:[^\s/@]*@)?(\[[0-9A-Fa-f:.%]+\]|[^\s/:?#\]\[)\"'<>,]+)")
IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w]|\.\d)")
IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{0,4}|\d{1,3}(?:\.\d{1,3}){3})(?:%[\w.-]+)?(?![\w:])")
MAC_RE = re.compile(r"(?<![\w:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}(?![\w:-])"
                    r"|(?<![\w.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![\w.])")
VERSION_PREFIX_RE = re.compile(r"(?:\b[vV]|\b(?:version|ver|build|release|rev)\s*)$", re.IGNORECASE)

# Non-identifying IPv4 ranges: unspecified, loopback, broadcast/netmasks,
# RFC 5737 documentation networks.
SAFE_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/32", "127.0.0.0/8", "255.0.0.0/8",
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def load_allowlist(path: str = ALLOWLIST_FILE) -> set:
    domains = set(PUBLIC_DOMAINS)
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                entry = line.split("#", 1)[0].strip().lower().strip(".")
                if entry:
                    domains.add(entry)
    except OSError:
        pass
    return domains


def _allowed(host: str, allowlist: set) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowlist)


def _private(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in PRIVATE_SUFFIXES)


def mask_ipv4(value: str) -> str:
    return value.split(".", 1)[0] + ".x.x.x"


def mask_ipv6(value: str) -> str:
    first = value.split(":", 1)[0] or ""
    return (first + ":…") if first else "::…"


def mask_mac(value: str) -> str:
    if "." in value:
        return value[:4] + ".xxxx.xxxx"
    sep = value[2]
    return value[:2] + (sep + "xx") * 5


def mask_host(value: str) -> str:
    return value.split(".", 1)[0] + ".…"


def find_issues(text: str, allowlist: set | None = None) -> list:
    """Return [(kind, masked value)] for system-identifying items in text."""
    if allowlist is None:
        allowlist = load_allowlist()
    found = []
    spans = []  # character ranges already reported, to avoid double counting

    def add(kind, masked, span):
        spans.append(span)
        if (kind, masked) not in found:
            found.append((kind, masked))

    def taken(span):
        return any(s[0] <= span[0] < s[1] or span[0] <= s[0] < span[1] for s in spans)

    for m in MAC_RE.finditer(text):
        v = m.group(0).lower()
        if v.replace(":", "").replace("-", "").replace(".", "") in ("000000000000", "ffffffffffff"):
            continue
        add("a MAC address", mask_mac(m.group(0)), m.span())

    for m in IPV4_RE.finditer(text):
        if taken(m.span()) or any(int(o) > 255 for o in m.groups()):
            continue
        if VERSION_PREFIX_RE.search(text[max(0, m.start() - 10):m.start()]):
            continue
        ip = ipaddress.ip_address(m.group(0))
        if any(ip in n for n in SAFE_V4):
            continue
        add("an IPv4 address", mask_ipv4(m.group(0)), m.span())

    for m in IPV6_RE.finditer(text):
        if taken(m.span()):
            continue
        raw = m.group(0)
        try:
            ip = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            continue
        if ip.version != 6 or ip.is_loopback or ip.is_unspecified:
            continue
        groups = [g for g in raw.split("%", 1)[0].split(":") if g]
        # Skip short hex-ish fragments like "1::2" (slices) that happen to parse.
        if len(groups) < 3 and not any(len(g) >= 3 for g in groups):
            continue
        add("an IPv6 address", mask_ipv6(raw), m.span())

    def check_host(host, span, any_tld):
        host = host.strip(".").lower()
        if not host or taken(span) or host in NOT_HOSTS:
            return
        if _private(host):
            add("a private hostname", mask_host(host), span)
        elif "." not in host:
            return
        elif _allowed(host, allowlist):
            return
        elif any_tld or host.rsplit(".", 1)[-1] in PUBLIC_TLDS:
            add("a hostname not on the public allowlist", mask_host(host), span)

    for m in URL_HOST_RE.finditer(text):
        host = m.group(1)
        if host.startswith("["):  # bracketed IPv6 literal, handled above
            continue
        try:
            ipaddress.ip_address(host)
            continue  # IP literal, handled above
        except ValueError:
            pass
        check_host(host, m.span(1), any_tld=True)

    for m in EMAIL_HOST_RE.finditer(text):
        check_host(m.group(0), m.span(), any_tld=True)

    for m in HOST_RE.finditer(text):
        check_host(m.group(0), m.span(), any_tld=False)

    return found


def block_reason(issues: list) -> str:
    shown = ", ".join("%s (%s)" % (kind, masked) for kind, masked in issues[:MAX_SHOWN])
    more = " and %d more" % (len(issues) - MAX_SHOWN) if len(issues) > MAX_SHOWN else ""
    return ("Ring 0 prompt guard: not sent. Found %s%s. Describe the question, not the system. "
            "If this is public information, start the prompt with %s." % (shown, more, OVERRIDE))


def main() -> int:
    try:
        data = json.loads(sys.stdin.read())
        prompt = data.get("prompt") if isinstance(data, dict) else None
        if not isinstance(prompt, str) or not prompt.strip():
            return 0
        if prompt.lstrip().startswith(OVERRIDE):
            return 0
        issues = find_issues(prompt)
        if not issues:
            return 0
        reason = block_reason(issues)
    except Exception:
        return 0  # fail open: a guard bug must never lock the user out
    sys.stdout.write(json.dumps({
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
    }))
    sys.stderr.write(reason + "\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
