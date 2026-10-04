"""
Tests for scripts/ring0_log.py (Ring 0 dogfood log, stories R0-2 #36 and R0-8 #42).

    pytest test/test_ring0_log.py
"""
import csv
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import ring0_log as r0  # noqa: E402


def add(log, *extra):
    return r0.main(["--log", str(log), "add", *extra])


def entry(log, qtype="control", tool="get_control", answered="yes", correct="yes", faster="same",
          date="2026-10-05", issue=None, note=""):
    args = ["--type", qtype, "--tool", tool, "--answered", answered, "--correct", correct,
            "--faster", faster, "--date", date]
    if issue:
        args += ["--issue", issue]
    if note:
        args += ["--note", note]
    return add(log, *args)


def test_default_log_is_under_gitignored_knowledge():
    rel = os.path.relpath(r0.DEFAULT_LOG, ROOT)
    assert rel.split(os.sep)[0] == "knowledge"
    with open(os.path.join(ROOT, ".gitignore"), encoding="utf-8") as f:
        assert any(line.strip().strip("/") == "knowledge" for line in f)


def test_add_round_trips_and_creates_folder(tmp_path):
    log = tmp_path / "nested" / "ring0" / "log.csv"
    assert entry(log, qtype="coverage", tool="statement_coverage", faster="yes",
                 note="AU-3 a rules for RHEL 9") == 0
    assert entry(log, answered="no", correct="no", issue="#51") == 0
    with open(log, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert list(rows[0]) == r0.FIELDS
    assert rows[0] == {"date": "2026-10-05", "question_type": "coverage", "tool": "statement_coverage",
                       "answered": "yes", "correct": "yes", "faster": "yes", "issue": "",
                       "note": "AU-3 a rules for RHEL 9"}
    assert rows[1]["issue"] == "51"
    assert r0.read_rows(str(log)) == rows


def test_date_defaults_to_today(tmp_path):
    import datetime as dt
    row = r0.make_row("cci", "lookup_cci", "yes", "unchecked", "no")
    assert row["date"] == dt.date.today().isoformat()


@pytest.mark.parametrize("kwargs, message", [
    ({"question_type": "hostname"}, "question_type"),
    ({"answered": "maybe"}, "answered"),
    ({"correct": "probably"}, "correct"),
    ({"faster": "much"}, "faster"),
    ({"tool": "get control; rm"}, "tool"),
    ({"date": "10/05/2026"}, "YYYY-MM-DD"),
    ({"issue": "abc"}, "issue"),
    ({"note": "x" * 121}, "120"),
    ({"note": "line one\nline two"}, "single line"),
])
def test_bad_values_are_rejected(kwargs, message):
    args = dict(question_type="control", tool="get_control", answered="yes", correct="yes", faster="same")
    args.update(kwargs)
    with pytest.raises(r0.LogError, match=message):
        r0.make_row(**args)


@pytest.mark.parametrize("note", [
    "server at 10.2.3.4 failed",
    "host 192.168.0.1",
    "fe80::1 on eth0",
    "2001:db8::8a2e:370:7334",
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "nic aa:bb:cc:dd:ee:ff",
    "nic AA-BB-CC-DD-EE-FF",
])
def test_addresses_in_note_are_refused(tmp_path, note, capsys):
    log = tmp_path / "log.csv"
    assert entry(log, note=note) == 2
    assert "Describe the question, not the system" in capsys.readouterr().err
    assert not log.exists()


@pytest.mark.parametrize("note", ["AC-2(1) a.1 statements", "RHEL-09-211010 vs V-258054", "took 12:30:45",
                                  "v1.2.3 of the STIG", "CCI-000130 to AU-3 a"])
def test_ordinary_notes_are_allowed(note):
    assert r0.check_note(note) == note


def test_cli_rejects_value_outside_choices(tmp_path):
    with pytest.raises(SystemExit):
        entry(tmp_path / "log.csv", qtype="hostname")


def synthetic_log(path, n=30, unanswered=4, faster=3, issues_for_problems=True):
    for i in range(n):
        problem = i < unanswered
        entry(path, qtype=r0.QUESTION_TYPES[i % 4], tool=["get_control", "statement_coverage", "cli"][i % 3],
              answered="no" if problem else "yes", correct="no" if problem else ("unchecked" if i == n - 1 else "yes"),
              faster="yes" if unanswered <= i < unanswered + faster else "same",
              date=f"2026-10-{1 + i % 14:02d}",
              issue=str(100 + i) if problem and issues_for_problems else None)


def test_summary_all_targets_pass(tmp_path, capsys):
    log = tmp_path / "log.csv"
    synthetic_log(log)
    m = r0.metrics(r0.read_rows(str(log)))
    assert m["lookups"] == 30 and m["answered"] == 26
    assert m["answer_rate"] == pytest.approx(26 / 30)
    assert m["incorrect"] == 4 and m["unchecked"] == 1
    assert m["problems"] == 4 and m["problems_with_issue"] == 4 and m["issues"] == [100, 101, 102, 103]
    assert m["faster"] == 3
    assert m["by_type"]["control"] == 8 and sum(m["by_type"].values()) == 30
    assert m["by_tool"]["cli"] == 10
    assert (m["first"], m["last"]) == ("2026-10-01", "2026-10-14")
    assert all(m["targets"].values())

    capsys.readouterr()
    assert r0.main(["--log", str(log), "summary"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("## Ring 0 dogfood summary")
    assert "MISS" not in out and out.count("PASS") == 4
    assert "| 26/30 (87%) |" in out and "#100, #101, #102, #103" in out


def test_summary_misses(tmp_path):
    log = tmp_path / "log.csv"
    synthetic_log(log, n=10, unanswered=3, faster=2, issues_for_problems=False)
    m = r0.metrics(r0.read_rows(str(log)))
    assert m["targets"] == {"lookups": False, "answer_rate": False, "issues": False, "faster": False}
    out = r0.summary_markdown(r0.read_rows(str(log)))
    assert out.count("MISS") == 4 and "| 0/3 |" in out


def test_empty_log_summary(tmp_path):
    out = r0.summary_markdown(r0.read_rows(str(tmp_path / "missing.csv")))
    assert "no entries" in out and out.count("MISS") == 3  # the issue target is vacuously met


def test_date_filters(tmp_path, capsys):
    log = tmp_path / "log.csv"
    for d in ("2026-10-01", "2026-10-05", "2026-10-10", "2026-10-14"):
        entry(log, date=d)
    assert len(r0.read_rows(str(log), since="2026-10-05")) == 3
    assert len(r0.read_rows(str(log), until="2026-10-05")) == 2
    assert [r["date"] for r in r0.read_rows(str(log), "2026-10-05", "2026-10-10")] == ["2026-10-05", "2026-10-10"]
    with pytest.raises(r0.LogError):
        r0.read_rows(str(log), since="yesterday")
    capsys.readouterr()
    r0.main(["--log", str(log), "list", "--since", "2026-10-10"])
    out = capsys.readouterr().out
    assert "2026-10-10" in out and "2026-10-14" in out and "2026-10-01" not in out


def test_log_option_works_before_or_after_the_subcommand(tmp_path):
    before, after = tmp_path / "before.csv", tmp_path / "after.csv"
    args = ["--type", "control", "--tool", "get_control", "--answered", "yes", "--correct", "yes", "--faster", "same"]
    assert r0.main(["--log", str(before), "add", *args]) == 0
    assert r0.main(["add", "--log", str(after), *args]) == 0
    assert before.exists() and after.exists()
