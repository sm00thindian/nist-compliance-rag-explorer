"""
Evidence collected from a target system, stored in a local folder.

    evidence/
      files/etc/security/faillock.conf      # copies of files, at their absolute paths
      files/etc/ssh/sshd_config
      commands/001.txt                      # first line "$ <command>", then its output
      commands.json                         # optional: {"<command>": "<output>"}

Nothing here is sent anywhere. ``collection_script`` writes a shell script the
assessor reviews and runs on the target to build this folder.
"""
import glob
import json
import os
import re
import shlex
from typing import Dict, Iterable, List, Optional, Tuple


def normalize_command(cmd: str) -> str:
    """Compare commands ignoring whitespace differences and a leading sudo."""
    cmd = " ".join((cmd or "").split())
    return re.sub(r"^sudo\s+", "", cmd)


class EvidenceBundle:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.files_root = os.path.join(self.root, "files")
        self._commands = self._load_commands()

    # ---- files -------------------------------------------------------
    def _local_path(self, abs_path: str) -> str:
        local = os.path.realpath(os.path.join(self.files_root, abs_path.lstrip("/")))
        if not local.startswith(os.path.realpath(self.files_root) + os.sep):
            raise ValueError(f"path escapes the evidence folder: {abs_path}")
        return local

    def files(self, pattern: str) -> List[Tuple[str, str]]:
        """[(target path, local copy)] for a path that may contain wildcards."""
        local_pattern = self._local_path(pattern)
        matches = sorted(glob.glob(local_pattern)) if any(c in pattern for c in "*?[") else (
            [local_pattern] if os.path.isfile(local_pattern) else [])
        out = []
        for local in matches:
            if os.path.isfile(local):
                target = "/" + os.path.relpath(local, self.files_root).replace(os.sep, "/")
                out.append((target, local))
        return out

    def read(self, local_path: str) -> str:
        with open(local_path, encoding="utf-8", errors="replace") as f:
            return f.read()

    def has_files_folder(self) -> bool:
        return os.path.isdir(self.files_root)

    # ---- commands ----------------------------------------------------
    def _load_commands(self) -> Dict[str, str]:
        commands: Dict[str, str] = {}
        index = os.path.join(self.root, "commands.json")
        if os.path.exists(index):
            with open(index, encoding="utf-8") as f:
                for cmd, output in json.load(f).items():
                    commands[normalize_command(cmd)] = output
        folder = os.path.join(self.root, "commands")
        if os.path.isdir(folder):
            for name in sorted(os.listdir(folder)):
                path = os.path.join(folder, name)
                if not os.path.isfile(path):
                    continue
                with open(path, encoding="utf-8", errors="replace") as f:
                    first, _, rest = f.read().partition("\n")
                if first.startswith("$ "):
                    commands[normalize_command(first[2:])] = rest
        return commands

    def command_output(self, command: str) -> Optional[str]:
        return self._commands.get(normalize_command(command))

    def commands(self) -> Iterable[str]:
        return self._commands.keys()


def collection_script(files: List[str], commands: List[str], unreviewed: List[str]) -> str:
    """A shell script that gathers evidence into ./evidence on the target system.

    It is written out for a person to read and run; nothing here executes it.
    """
    lines = [
        "#!/bin/sh",
        "# Evidence collection for local STIG checks.",
        "# Review every command before running it on the target system.",
    ]
    if unreviewed:
        lines.append("# WARNING: commands from unreviewed, model-generated checks: " + ", ".join(sorted(unreviewed)))
    lines += ["set -u", "OUT=${1:-evidence}", 'mkdir -p "$OUT/files" "$OUT/commands"', ""]
    for path in sorted(set(files)):
        if any(c in path for c in "*?["):
            lines.append(f"for f in {path}; do [ -f \"$f\" ] && mkdir -p \"$OUT/files$(dirname \"$f\")\" "
                         f"&& cp -p \"$f\" \"$OUT/files$f\"; done")
        else:
            q = shlex.quote(path)
            lines.append(f"[ -f {q} ] && mkdir -p \"$OUT/files$(dirname {q})\" && cp -p {q} \"$OUT/files\"{q}")
    lines.append("")
    for i, cmd in enumerate(sorted(set(commands)), 1):
        lines.append(f"{{ echo {shlex.quote('$ ' + cmd)}; {cmd}; }} > \"$OUT/commands/{i:03d}.txt\" 2>&1")
    lines += ["", 'echo "Evidence written to $OUT"']
    return "\n".join(lines) + "\n"
