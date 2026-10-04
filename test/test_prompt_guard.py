"""
Tests for the Ring 0 prompt guard (scripts/prompt_guard.py), a Claude Code
UserPromptSubmit hook that blocks prompts containing system-identifying details.

    pytest test/test_prompt_guard.py
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import prompt_guard  # noqa: E402
from prompt_guard import (block_reason, find_issues, load_allowlist, mask_host,  # noqa: E402
                          mask_ipv4, mask_ipv6, mask_mac)

SCRIPT = os.path.join(ROOT, "scripts", "prompt_guard.py")
ALLOW = prompt_guard.PUBLIC_DOMAINS  # built-in list only, independent of the repo file


def kinds(text):
    return [k for k, _ in find_issues(text, ALLOW)]


@pytest.mark.parametrize("text, kind", [
    # IPv4
    ("why does 10.2.3.4 fail AC-7?", "an IPv4 address"),
    ("server at 192.168.1.20 has sshd open", "an IPv4 address"),
    ("subnet 172.16.0.0/12 needs SC-7", "an IPv4 address"),
    ("connect to 8.8.8.8:53", "an IPv4 address"),
    ("trailing dot 10.0.0.5.", "an IPv4 address"),
    ("(10.20.30.40)", "an IPv4 address"),
    # IPv6
    ("host fe80::1ff:fe23:4567:890a is unreachable", "an IPv6 address"),
    ("2001:db8:85a3::8a2e:370:7334 is our gateway", "an IPv6 address"),
    ("addr 2600:1f18:abcd:1234:0:0:0:1", "an IPv6 address"),
    ("link-local fe80::abcd%eth0", "an IPv6 address"),
    # MAC
    ("NIC 00:1A:2B:3C:4D:5E is flagged", "a MAC address"),
    ("NIC 00-1a-2b-3c-4d-5e is flagged", "a MAC address"),
    ("cisco style 001a.2b3c.4d5e", "a MAC address"),
    # private hostnames
    ("ssh to web01.corp please", "a private hostname"),
    ("dc1.example.local fails the check", "a private hostname"),
    ("db.internal returns errors", "a private hostname"),
    ("printer.lan is out of scope", "a private hostname"),
    ("nas.home.arpa", "a private hostname"),
    ("mail.agency.localdomain", "a private hostname"),
    ("http://jenkins.corp:8080/job/x", "a private hostname"),
    # unlisted FQDNs
    ("web01.agency.gov fails RHEL-09-211010", "a hostname not on the public allowlist"),
    ("our portal is portal.contoso.com", "a hostname not on the public allowlist"),
    ("WEB01.AGENCY.MIL", "a hostname not on the public allowlist"),
    ("see https://intranet.agency.xyz/page", "a hostname not on the public allowlist"),
    ("see https://wiki.agency.weirdtld/page", "a hostname not on the public allowlist"),
    ("email jane@agency.gov about it", "a hostname not on the public allowlist"),
    ("fake allowlist suffix evilnist.gov", "a hostname not on the public allowlist"),
    ("nist.gov.attacker.com", "a hostname not on the public allowlist"),
])
def test_blocked(text, kind):
    assert kind in kinds(text)


@pytest.mark.parametrize("text", [
    "",
    "Which RHEL 9 rules are evidence for AU-03a?",
    "AC-2(1) and AC-2(12)(a) and SI-4(4)",
    "CCI-000015 and CCI-002235",
    "V-258054 and V-220697",
    "RHEL-09-211010 and WN10-00-000005",
    "SV-258054r926593_rule",
    "xccdf_mil.disa.stig_rule_SV-258054r926593_rule",
    "xccdf_mil.disa.stig_benchmark_RHEL_9_STIG",
    "/etc/ssh/sshd_config and /etc/audit/rules.d/audit.rules",
    "/etc/security/faillock.conf and /etc/pki/ca-trust/source/anchors/DoD.crt",
    "C:\\Windows\\System32\\config",
    "AC-02a.01, AC-02a.02 and d.1 and a.1.a",
    "catalog 5.2.0 with openssh 8.7p1 and 3.1.2-2.el9",
    "STIG V2R3 release 2.3 and Rev 5",
    "version 1.2.3.4 of the agent",
    "build 10.0.19045.2965",
    "v1.2.3.4",
    "OID 1.3.6.1.4.1.311",
    "localhost 127.0.0.1 and 0.0.0.0 and ::1",
    "netmask 255.255.255.0",
    "docs range 192.0.2.10",
    "https://csrc.nist.gov/projects/cprt and nist.gov",
    "https://public.cyber.mil/stigs/cci/ and disa.mil",
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/x.json",
    "github.com/mitre/heimdall2 and saf.mitre.org",
    "docs at https://code.claude.com/docs/en/hooks and claude.ai and anthropic.com",
    "pypi.org, python.org and libreoffice.org",
    "example.com and host.example.org",
    "http://localhost:8000/health",
    "src/checks/spec.py, README.md, setup.py, run.sh, data.json",
    "logger.info, obj.name, self.id, app.run, checks.spec",
    "ASP.NET and .NET Framework",
    "time 10:30:45 and ratio 1:2:3",
    "slice a[1::2]",
    "e.g. this, i.e. that, U.S. government",
    "#public-ok marker text alone",
])
def test_allowed(text):
    assert find_issues(text, ALLOW) == []


def test_masking_helpers():
    assert mask_ipv4("10.2.3.4") == "10.x.x.x"
    assert mask_ipv6("fe80::1ff:fe23:4567:890a") == "fe80:…"
    assert mask_ipv6("::ffff:abcd") == "::…"
    assert mask_mac("00:1A:2B:3C:4D:5E") == "00:xx:xx:xx:xx:xx"
    assert mask_mac("00-1a-2b-3c-4d-5e") == "00-xx-xx-xx-xx-xx"
    assert mask_mac("001a.2b3c.4d5e") == "001a.xxxx.xxxx"
    assert mask_host("web01.agency.gov") == "web01.…"


@pytest.mark.parametrize("text, secret", [
    ("ip 10.2.3.4", "10.2.3.4"),
    ("ip 10.2.3.4", "2.3.4"),
    ("host web01.agency.gov", "agency.gov"),
    ("host db7.corp", "corp"),
    ("mac 00:1A:2B:3C:4D:5E", "3C:4D"),
    ("v6 2001:db8:85a3::8a2e:370:7334", "8a2e"),
])
def test_reason_never_echoes_value(text, secret):
    issues = find_issues(text, ALLOW)
    assert issues
    reason = block_reason(issues)
    assert secret not in reason
    assert "#public-ok" in reason


def test_reason_limits_items():
    issues = find_issues("10.0.0.1 10.0.0.2 11.0.0.3 12.0.0.4 13.0.0.5", ALLOW)
    reason = block_reason(issues)
    assert "and 1 more" in reason or "and 2 more" in reason
    assert reason.count("an IPv4 address") == 3


def test_allowlist_file(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("# comment\n\nagency.gov   # our public site\n.Contoso.COM\n")
    allow = load_allowlist(str(f))
    assert find_issues("www.agency.gov and portal.contoso.com", allow) == []
    assert find_issues("www.other.gov", allow)


def test_missing_allowlist_file(tmp_path):
    allow = load_allowlist(str(tmp_path / "nope.txt"))
    assert allow == set(prompt_guard.PUBLIC_DOMAINS)


# --- end to end: run the hook as Claude Code would --------------------------

def run(stdin):
    return subprocess.run([sys.executable, SCRIPT], input=stdin, capture_output=True,
                          text=True, timeout=30)


def hook_input(prompt):
    return json.dumps({"session_id": "abc123", "hook_event_name": "UserPromptSubmit",
                       "cwd": ROOT, "prompt": prompt, "prompt_source": "user_input"})


def test_e2e_blocks():
    r = run(hook_input("why does web01.agency.gov at 10.2.3.4 fail AC-7?"))
    assert r.returncode == 2
    out = json.loads(r.stdout)
    assert out["decision"] == "block"
    assert out["hookSpecificOutput"] == {"hookEventName": "UserPromptSubmit",
                                         "suppressOriginalPrompt": True}
    assert "10.x.x.x" in out["reason"] and "web01.…" in out["reason"]
    assert "#public-ok" in out["reason"]
    for secret in ("10.2.3.4", "agency.gov"):
        assert secret not in r.stdout and secret not in r.stderr
    assert r.stderr.strip() == out["reason"]


def test_e2e_allows_clean_prompt():
    r = run(hook_input("Which RHEL 9 rules (RHEL-09-211010, V-258054) cover AC-2(1)?"))
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")


def test_e2e_override_marker():
    r = run(hook_input("#public-ok what does www.dhs.gov say about 8.8.8.8?"))
    assert (r.returncode, r.stdout) == (0, "")
    r = run(hook_input("   #public-ok leading whitespace www.dhs.gov"))
    assert (r.returncode, r.stdout) == (0, "")


def test_e2e_marker_must_lead():
    r = run(hook_input("www.dhs.gov #public-ok"))
    assert r.returncode == 2


@pytest.mark.parametrize("stdin", [
    "", "not json", "{", "[]", "null", '"a string"', '{"prompt": 42}', '{"no_prompt": "10.2.3.4"}',
    json.dumps({"prompt": ""}),
])
def test_e2e_fail_open(stdin):
    r = run(stdin)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")


def test_internal_error_fails_open(monkeypatch, capsys):
    import io

    def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(prompt_guard, "find_issues", boom)
    monkeypatch.setattr(sys, "stdin", io.StringIO(hook_input("10.2.3.4")))
    assert prompt_guard.main() == 0
    assert capsys.readouterr() == ("", "")
