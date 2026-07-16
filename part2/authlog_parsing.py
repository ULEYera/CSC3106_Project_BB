#!/usr/bin/env python3
"""
CSC3106 Mini-Project - Part 2: shared auth.log parsing.
Group BB

This is a trimmed-down version of the parser from part1/analysis.py. Part 2
only needs the authentication events themselves (failed password, accepted
password, invalid user), so the sudo/CRON/session bookkeeping from Part 1 is
left out. The regexes are copied verbatim from Part 1 rather than rewritten,
so both parts count events identically - if the two scripts ever disagreed on
what a "failed attempt" is, none of our cross-references would hold up.
"""

import re
from datetime import datetime

# Same assumption as Part 1: syslog timestamps carry no year, the extract is
# one contiguous week, so a fixed year only affects printed labels.
ASSUMED_YEAR = 2026

# Same list as Part 1: accounts observed running privileged sudo commands.
PRIVILEGED_USERS = {"root", "deploy", "webadmin", "ops", "sysadmin"}

IP_RE = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

LINE_RE = re.compile(
    r"^(?P<month>\w{3}) (?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)

SSHD_PATTERNS = [
    ("failed_password", re.compile(
        r"^Failed password for (?:invalid user )?(?P<user>\S+) "
        rf"from {IP_RE} port (?P<port>\d+)"
    )),
    ("accepted_password", re.compile(
        r"^Accepted password for (?P<user>\S+) "
        rf"from {IP_RE} port (?P<port>\d+)"
    )),
    ("invalid_user", re.compile(
        rf"^Invalid user (?P<user>\S+) from {IP_RE} port (?P<port>\d+)$"
    )),
]


def parse_auth_events(path):
    """Read the raw log and return the failed/accepted/invalid-user events in
    chronological order. Lines that are not one of those three types are
    simply skipped here - Part 1 already accounts for every line in the
    extract, so Part 2 does not repeat that audit."""
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            m = LINE_RE.match(line)
            if not m or m.group("process").strip() != "sshd":
                continue
            for event_type, pattern in SSHD_PATTERNS:
                pm = pattern.match(m.group("message"))
                if pm:
                    ts = datetime.strptime(
                        f"{m.group('month')} {m.group('day')} {m.group('time')} {ASSUMED_YEAR}",
                        "%b %d %H:%M:%S %Y",
                    )
                    events.append({
                        "lineno": lineno,
                        "timestamp": ts,
                        "event_type": event_type,
                        "user": pm.group("user"),
                        "ip": pm.group("ip"),
                    })
                    break
    events.sort(key=lambda e: (e["timestamp"], e["lineno"]))
    return events
