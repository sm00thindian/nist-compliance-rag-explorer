# Ring 0 prompt hygiene (R0-5)

Ring 0 rule: public data only. Describe the question, not the system.

## Checklist

1. Ask about controls, CCIs, STIG rules and 800-53A statements by ID, not about named systems.
2. No hostnames, IP or MAC addresses, URLs, account names or system names; say "a RHEL 9 web server".
3. No pasted configs, logs, scan output or screenshots; paraphrase the setting in generic terms ("PermitRootLogin is yes").
4. No ATO package details: system boundaries, POA&M items, inventories, findings for a named system.
5. If in doubt, leave it out. Use `#public-ok` only for text that is already public.

## The prompt guard

`scripts/prompt_guard.py` is a Claude Code `UserPromptSubmit` hook. It reads
each prompt before it is sent and blocks it when it finds:

- IPv4 addresses (except 0.0.0.0, 127.x, 255.x netmasks and the RFC 5737
  documentation ranges), IPv6 addresses (except `::` and `::1`), MAC addresses;
- hostnames with private suffixes: `.local`, `.corp`, `.internal`,
  `.intranet`, `.lan`, `.localdomain`, `.home.arpa`, `.private`;
- FQDNs, URLs and email domains not on the public allowlist (NIST, DISA,
  cyber.mil, MITRE, GitHub, Anthropic/Claude, Python, LibreOffice, and the
  reserved `example.*` names).

It ignores control IDs (`AC-2(1)`), CCIs, Vuln IDs, STIG and rule IDs, file
paths, 800-53A labels (`AC-02a.01`) and version numbers (`5.2.0`,
`3.1.2-2.el9`, `version 1.2.3.4`).

A blocked prompt is not sent. The message names what was found, masked
(`10.x.x.x`, `web01.…`), and the guard asks Claude Code to leave the prompt
text out of the block message. Your typed text can still be in Claude Code's
local transcript and prompt history; the guard itself writes nothing to disk.
If the guard fails or gets input it can't read, it lets the prompt through
rather than locking you out.

### Override

Start the prompt with `#public-ok` to send it as is. This is you asserting the
content is public (for example a public agency website or a vendor's
documented default address). The marker must be the first thing in the
prompt.

### Extending the allowlist

Add public domains to `config/prompt_guard_allowlist.txt`, one per line,
`#` for comments. A domain also allows its subdomains (`agency.gov` allows
`www.agency.gov`). The file is optional. Only list domains that are public and
don't identify an assessed system.

### Limits

It's a seatbelt, not a classifier. It matches patterns; it can't tell that
"phoenix" or "hr-db" is a system name, or that a paragraph describes your
boundary. Bare names with uncommon TLDs, single-label hostnames, account
names and pasted config text without addresses get through. Some public
names (`www.dhs.gov`) get blocked and need `#public-ok`. The checklist above
is the actual control; the guard catches the slips.
