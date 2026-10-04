#!/usr/bin/env python3
"""
Measure the quality of LLM-generated STIG checks against synthetic evidence.

Generates checks for a fixed set of RHEL 9 rules (public STIG text only),
then runs each generated check, and the hand-written reference check where
one exists, against synthetic evidence scenarios whose correct verdict is
known from the STIG text. Generated checks go to an output folder (default
knowledge/check_eval/, gitignored), never into checks/, and stay
reviewed: false.

    python scripts/eval_checks.py                  # live: calls the configured LLM (LLM_PROVIDER)
    python scripts/eval_checks.py --fake           # no API: the "model" answers with the reference checks
    python scripts/eval_checks.py --rules V-257985,V-258151

Scenarios are synthetic and contain no real system data.
"""
import argparse
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from checks.engine import evaluate_check  # noqa: E402
from checks.evidence import EvidenceBundle  # noqa: E402
from checks.generator import CheckStore, PublicRequirement, generate_check  # noqa: E402
from checks.spec import CheckSpecError  # noqa: E402

TECH = "Red Hat Enterprise Linux 9"
RULES = ["V-258054", "V-257987", "V-258151", "V-258152", "V-257985", "V-257809", "V-258106", "V-257777"]

SSHD_OK = "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n"
REDHAT_OK = "Include /etc/crypto-policies/back-ends/opensshserver.config\nSyslogFacility AUTHPRIV\n"
DROPIN = "/etc/ssh/sshd_config.d/01-permitrootlogin.conf"
# The STIG's own V-257985 command (leading sudo removed), and sshd -T, which prints the effective value.
STIG_PRL_CMD = ("/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\\r' | tr '\\n' ' ' "
                "| xargs sudo grep -iH '^\\s*permitrootlogin'")


def _sshd(files, effective, grep_lines):
    """V-257985 evidence: config files, `sshd -T` output, and the STIG command's output."""
    t = f"port 22\npermitrootlogin {effective}\nx11forwarding no\n"
    return files, {"sshd -T": t, "/usr/sbin/sshd -T": t, STIG_PRL_CMD: grep_lines}


# rule -> [(scenario, expected verdict per the STIG text, files, commands)]
SCENARIOS = {
    "V-258054": [
        ("deny = 3", "pass", {"/etc/security/faillock.conf": "deny = 3\n"}, {}),
        ("deny=2", "pass", {"/etc/security/faillock.conf": "silent\ndeny=2\n"}, {}),
        ("deny = 5", "fail", {"/etc/security/faillock.conf": "deny = 5\n"}, {}),
        ("deny = 0", "fail", {"/etc/security/faillock.conf": "deny = 0\n"}, {}),
        ("deny commented out", "fail", {"/etc/security/faillock.conf": "# deny = 3\n"}, {}),
    ],
    "V-257987": [
        ("both includes present", "pass",
         {"/etc/ssh/sshd_config": SSHD_OK, "/etc/ssh/sshd_config.d/50-redhat.conf": REDHAT_OK}, {}),
        ("crypto include missing", "fail",
         {"/etc/ssh/sshd_config": SSHD_OK, "/etc/ssh/sshd_config.d/50-redhat.conf": "SyslogFacility AUTHPRIV\n"}, {}),
        ("sshd_config include commented", "fail",
         {"/etc/ssh/sshd_config": "#Include /etc/ssh/sshd_config.d/*.conf\n",
          "/etc/ssh/sshd_config.d/50-redhat.conf": REDHAT_OK}, {}),
    ],
    "V-258151": [
        ("dnf table output", "pass", {}, {"dnf list --installed audit":
                                          "Installed Packages\naudit.x86_64    3.1.2-2.el9    @AppStream\n"}),
        ("STIG example output", "pass", {}, {"dnf list --installed audit": "audit-3.0.7-101.el9_0.2.x86_64\n"}),
        ("not installed", "fail", {}, {"dnf list --installed audit": "Error: No matching Packages to list\n"}),
        ("only audit-libs", "fail", {}, {"dnf list --installed audit":
                                         "Installed Packages\naudit-libs.x86_64    3.1.2-2.el9    @anaconda\n"}),
    ],
    "V-258152": [
        ("active (running)", "pass", {}, {"systemctl status auditd.service":
            "● auditd.service - Security Auditing Service\n     Loaded: loaded (/usr/lib/systemd/system/auditd.service; enabled)\n"
            "     Active: active (running) since Mon 2026-09-28 10:00:00 EDT; 1h ago\n"}),
        ("inactive (dead)", "fail", {}, {"systemctl status auditd.service":
            "○ auditd.service - Security Auditing Service\n     Loaded: loaded\n     Active: inactive (dead)\n"}),
        ("active (exited)", "fail", {}, {"systemctl status auditd.service":
            "● auditd.service - Security Auditing Service\n     Active: active (exited) since Mon 2026-09-28\n"}),
    ],
    # Regression scenarios for #27: sshd uses the first value it reads, and drop-ins come first.
    "V-257985": [
        ("drop-in yes, main no", "fail", *_sshd(
            {"/etc/ssh/sshd_config": SSHD_OK + "PermitRootLogin no\n", DROPIN: "PermitRootLogin yes\n"}, "yes",
            f"{DROPIN}:PermitRootLogin yes\n/etc/ssh/sshd_config:PermitRootLogin no\n")),
        ("only a drop-in sets no", "pass", *_sshd(
            {"/etc/ssh/sshd_config": SSHD_OK, DROPIN: "PermitRootLogin no\n"}, "no",
            f"{DROPIN}:PermitRootLogin no\n")),
        ("only sshd_config sets no", "pass", *_sshd(
            {"/etc/ssh/sshd_config": SSHD_OK + "PermitRootLogin no\n"}, "no",
            "/etc/ssh/sshd_config:PermitRootLogin no\n")),
        ("not set anywhere", "fail", *_sshd(
            {"/etc/ssh/sshd_config": SSHD_OK}, "prohibit-password", "")),
        ("sshd_config sets yes", "fail", *_sshd(
            {"/etc/ssh/sshd_config": SSHD_OK + "PermitRootLogin yes\n"}, "yes",
            "/etc/ssh/sshd_config:PermitRootLogin yes\n")),
    ],
}


def bundle(root, files, commands):
    for path, text in files.items():
        p = os.path.join(root, "files", path.lstrip("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
    os.makedirs(os.path.join(root, "files"), exist_ok=True)
    if commands:
        os.makedirs(os.path.join(root, "commands"), exist_ok=True)
        for i, (cmd, out) in enumerate(commands.items(), 1):
            with open(os.path.join(root, "commands", f"{i:03d}.txt"), "w") as f:
                f.write(f"$ {cmd}\n{out}")
    return EvidenceBundle(root)


def run_scenarios(check, vuln):
    """[(scenario, expected, verdict)] for one check against its rule's scenarios."""
    out = []
    for name, expected, files, commands in SCENARIOS.get(vuln, []):
        with tempfile.TemporaryDirectory() as tmp:
            verdict = evaluate_check(check, bundle(tmp, files, commands))["status"] if check else "no check"
        out.append((name, expected, verdict))
    return out


class Counting:
    def __init__(self, client):
        self.client, self.name, self.calls, self.replies = client, client.name, 0, []

    def complete(self, system, user, max_tokens=2000):
        self.calls += 1
        reply = self.client.complete(system, user, max_tokens)
        self.replies.append(reply)
        return reply


class FakeFromReference:
    """No-API self-test: answers with the reference check's body, or 'manual' when there is none."""
    name = "fake:reference"

    def __init__(self, store, rules):
        self.store, self.rules = store, rules

    def complete(self, system, user, max_tokens=2000):
        vuln = next(v for v in self.rules if v in user)
        ref = self.store.load(TECH, vuln)
        if not ref:
            return json.dumps({"automatable": False, "conditions": [], "notes": "", "manual_reason": "no reference"})
        return json.dumps({k: ref[k] for k in ("automatable", "logic", "conditions", "notes", "manual_reason")
                           if ref.get(k) is not None})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fake", action="store_true", help="no API call; use the reference checks as the model's answers")
    ap.add_argument("--rules", help="comma-separated Vuln IDs (default: the standard 8)")
    ap.add_argument("--out", default=os.path.join(ROOT, "knowledge", "check_eval"),
                    help="folder for generated checks and report.json (default knowledge/check_eval)")
    ap.add_argument("--knowledge", default=os.path.join(ROOT, "knowledge"))
    ap.add_argument("--stigs", default=os.path.join(ROOT, "stigs"))
    ap.add_argument("--provider", help="LLM provider (default: $LLM_PROVIDER, else anthropic)")
    args = ap.parse_args(argv)

    from checks.rollup import load_context
    ctx = load_context(args.knowledge, args.stigs)
    stig_rules = {r["vuln_id"]: r for r in ctx["rules"][TECH]}
    rules = [r.strip() for r in args.rules.split(",")] if args.rules else RULES
    reference = CheckStore(os.path.join(ROOT, "checks"))
    out_dir = os.path.join(args.out, "fake" if args.fake else "generated")
    store = CheckStore(out_dir)
    if args.fake:
        base = FakeFromReference(reference, rules)
    else:
        from checks.llm import make_client
        base = make_client(args.provider)
    print(f"client: {base.name}; writing to {out_dir}\n")

    report = {"client": base.name, "rules": {}}
    for vuln in rules:
        client, t0, entry = Counting(base), time.time(), {"title": stig_rules[vuln]["title"]}
        try:
            check = generate_check(PublicRequirement.from_rule(stig_rules[vuln], TECH), client)
            store.save(check, overwrite_reviewed=True)
            entry.update(valid=True, automatable=check["automatable"], logic=check["logic"],
                         conditions=check["conditions"], notes=check["notes"], manual_reason=check["manual_reason"])
        except CheckSpecError as e:  # the model answered, but not with a valid check
            entry.update(valid=False, error=str(e))
            check = None
        except Exception as e:  # API, auth or network problem: every other rule would fail the same way
            sys.exit(f"{vuln}: API call failed, stopping: {e}")
        entry.update(calls=client.calls, seconds=round(time.time() - t0, 1), replies=client.replies)
        kinds = [c["type"] for c in entry.get("conditions", [])]
        summary = (f"INVALID: {entry['error']}" if not entry["valid"] else
                   f"automatable {kinds}" if entry["automatable"] else f"manual: {entry['manual_reason']}")
        print(f"{vuln}: calls={client.calls} {summary}")
        ref = reference.load(TECH, vuln)
        rows = []
        for (name, expected, gen_v), (_, _, ref_v) in zip(run_scenarios(check, vuln),
                                                          run_scenarios(ref, vuln) if ref else
                                                          [(None, None, "-")] * len(SCENARIOS.get(vuln, []))):
            rows.append({"scenario": name, "expected": expected, "reference": ref_v, "generated": gen_v})
            flag = "" if gen_v == expected else "   <-- generated differs from expected"
            print(f"    {name:<30} expected {expected:<5} reference {ref_v:<14} generated {gen_v:<14}{flag}")
        if rows:
            entry["scenarios"] = rows
        report["rules"][vuln] = entry

    scen = [r for e in report["rules"].values() for r in e.get("scenarios", [])]
    with_ref = [r for r in scen if r["reference"] != "-"]
    agree = sum(r["generated"] == r["expected"] for r in scen)
    ref_agree = sum(r["reference"] == r["expected"] for r in with_ref)
    valid = sum(e["valid"] for e in report["rules"].values())
    first_try = sum(e["valid"] and e["calls"] == 1 for e in report["rules"].values())
    print(f"\nvalid checks: {valid}/{len(report['rules'])} ({first_try} on the first try)")
    print(f"scenario verdicts matching the STIG: generated {agree}/{len(scen)}; "
          f"reference {ref_agree}/{len(with_ref)} (rules with a hand-written check)")
    report["summary"] = {"valid": valid, "first_try": first_try, "scenarios": len(scen), "generated_correct": agree,
                         "reference_scenarios": len(with_ref), "reference_correct": ref_agree}
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, f"report{'-fake' if args.fake else ''}.json"), "w") as f:
        json.dump(report, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
