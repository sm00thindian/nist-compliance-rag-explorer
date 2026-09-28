"""
Local STIG checks.

The split is deliberate:

- ``generator`` turns *public* STIG check text into structured checks. It is
  the only part that talks to an LLM, and it only ever sees a
  ``PublicRequirement`` built from the published STIG.
- ``engine`` evaluates those checks against an evidence folder on this
  machine. Evidence never leaves it and is never sent to a model.
- ``rollup`` joins the results to SP 800-53A determination statements.
"""
