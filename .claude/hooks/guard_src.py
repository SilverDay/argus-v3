#!/usr/bin/env python3
"""PreToolUse guard for Write/Edit on src/.

Reads the Claude Code hook payload from stdin and inspects the *new* content
(Write: content, Edit: new_string). Exit code 2 blocks the tool call and feeds
stderr back to Claude. Anything outside src/ is ignored.
"""
import json
import re
import sys

RULES = [
    (re.compile(r"\bRPi\.GPIO\b|^\s*import\s+RPi\b", re.M),
     "RPi.GPIO (and the rpi-lgpio shim that provides it) is not used. Use the native lgpio module."),
    (re.compile(r"\bdasbus\b|udisks2|UDisks2", re.I),
     "udisks2/dasbus is replaced by src/broker/. No D-Bus mount calls."),
    (re.compile(r"verify\s*=\s*False|ssl_verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False"),
     "TLS verification must never be disabled."),
    (re.compile(r"(print|log\w*\.\w+)\([^)]*\bpin\b(?!_)", re.I),
     "Never print or log a PIN value."),
]


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return 0
    tool_input = payload.get("tool_input") or {}
    path = str(tool_input.get("file_path", ""))
    if "/src/" not in path.replace("\\", "/") or not path.endswith(".py"):
        return 0
    text = str(tool_input.get("content") or tool_input.get("new_string") or "")
    for pattern, message in RULES:
        if pattern.search(text):
            print(f"Blocked by project guard: {message} ({path})", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
