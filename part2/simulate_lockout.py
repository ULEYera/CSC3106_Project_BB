#!/usr/bin/env python3
"""
CSC3106 Mini-Project - Part 2: Technical Defensive Response.
Group BB

Replays our assigned extract through a fail2ban-style rate-limit/lockout
policy to test, against real evidence rather than intuition, whether the
"prevent" layer of our proposed response (config/fail2ban/jail.local) would
actually have stopped what we saw in Part 1 - and what it would have cost
legitimate users.

Policy modelled (same shape as fail2ban's sshd jail):
  - an IP that accumulates `maxretry` failed attempts within `findtime`
    seconds is banned for `bantime` seconds
  - with --increment (our recommendation, and the default), each repeat ban
    of the same IP doubles in length, mirroring fail2ban's
    bantime.increment behaviour
  - any event from a banned IP (failed OR successful) is counted as blocked:
    a banned IP cannot reach sshd at all

Honesty caveat, also spelled out in the report: this replays the traffic
exactly as it happened. A real attacker who keeps getting banned would
change behaviour (rotate IPs, slow down), so the right reading of these
numbers is "this specific observed attack would have been interrupted", not
"attacks like this become impossible". That residual risk is why the
response also has a detection layer (detector.py) and a structural fix
(key-only auth for privileged accounts, config/sshd_config.d/).

Usage:
    python simulate_lockout.py [path-to-log-file] [--outdir OUTDIR]
                               [--maxretry N] [--findtime SECONDS]
                               [--bantime SECONDS] [--no-increment]

Outputs output/lockout_simulation.csv (per-IP results) and a console summary
answering the question we actually care about: would the deploy compromise
have been prevented, and would anyone legitimate have been locked out?
"""

import argparse
import csv
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

from authlog_parsing import parse_auth_events


def simulate(events, maxretry=5, findtime_seconds=600, bantime_seconds=3600,
             increment=True):
    """Replay events chronologically through the ban policy. Returns per-IP
    stats, the list of individual bans, and the successful logins that fell
    inside a ban window (i.e. logins the policy would have prevented)."""
    findtime = timedelta(seconds=findtime_seconds)

    banned_until = {}
    ban_counts = defaultdict(int)
    recent_fails = defaultdict(deque)
    stats = defaultdict(lambda: {
        "failed_seen": 0, "failed_blocked": 0,
        "accepted_seen": 0, "accepted_blocked": 0, "bans": 0,
    })
    bans = []
    blocked_logins = []

    for e in events:
        if e["event_type"] not in ("failed_password", "accepted_password"):
            continue
        ip = e["ip"]
        s = stats[ip]
        is_banned = ip in banned_until and e["timestamp"] < banned_until[ip]

        if e["event_type"] == "failed_password":
            s["failed_seen"] += 1
            if is_banned:
                s["failed_blocked"] += 1
                continue
            dq = recent_fails[ip]
            dq.append(e["timestamp"])
            while dq and e["timestamp"] - dq[0] > findtime:
                dq.popleft()
            if len(dq) >= maxretry:
                ban_counts[ip] += 1
                # bantime doubles per repeat ban when increment is on
                factor = 2 ** (ban_counts[ip] - 1) if increment else 1
                duration = timedelta(seconds=bantime_seconds * factor)
                banned_until[ip] = e["timestamp"] + duration
                s["bans"] += 1
                bans.append({
                    "source_ip": ip,
                    "ban_time": e["timestamp"],
                    "ban_seconds": int(duration.total_seconds()),
                    "ban_number_for_ip": ban_counts[ip],
                })
                dq.clear()
        else:  # accepted_password
            s["accepted_seen"] += 1
            if is_banned:
                s["accepted_blocked"] += 1
                blocked_logins.append({
                    "timestamp": e["timestamp"],
                    "source_ip": ip,
                    "username": e["user"],
                })

    return {"stats": dict(stats), "bans": bans, "blocked_logins": blocked_logins}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", nargs="?", default="../1_auth.log.txt",
                        help="Path to the auth.log extract (default: ../1_auth.log.txt)")
    parser.add_argument("--outdir", default="output",
                        help="Directory for generated outputs (default: output)")
    parser.add_argument("--maxretry", type=int, default=5,
                        help="Failed attempts within findtime before a ban (default 5)")
    parser.add_argument("--findtime", type=int, default=600,
                        help="Window in seconds for counting retries (default 600)")
    parser.add_argument("--bantime", type=int, default=3600,
                        help="Initial ban length in seconds (default 3600)")
    parser.add_argument("--no-increment", action="store_true",
                        help="Disable doubling of repeat-ban durations")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    events = parse_auth_events(args.logfile)
    result = simulate(events, maxretry=args.maxretry,
                      findtime_seconds=args.findtime,
                      bantime_seconds=args.bantime,
                      increment=not args.no_increment)

    rows = []
    for ip, s in sorted(result["stats"].items(),
                        key=lambda kv: kv[1]["failed_blocked"], reverse=True):
        rows.append({"source_ip": ip, **s})
    with open(outdir / "lockout_simulation.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    total_blocked = sum(s["failed_blocked"] for s in result["stats"].values())
    total_failed = sum(s["failed_seen"] for s in result["stats"].values())
    print(f"Policy: maxretry={args.maxretry}, findtime={args.findtime}s, "
          f"bantime={args.bantime}s, increment={not args.no_increment}")
    print(f"{len(result['bans'])} bans across {sum(1 for s in result['stats'].values() if s['bans'])} IPs; "
          f"{total_blocked} of {total_failed} failed attempts would have been blocked.")

    if result["blocked_logins"]:
        print("Successful logins that would have been PREVENTED (fell inside a ban):")
        for b in result["blocked_logins"]:
            print(f"  {b['timestamp']:%b %d %H:%M:%S}  {b['username']} from {b['source_ip']}")
    else:
        print("No successful logins fell inside a ban window under this policy.")

    # The cost side: a legitimate user locked out by their own typos would
    # show up here as a blocked login from an IP with routine successes.
    collateral = [b for b in result["blocked_logins"]
                  if result["stats"][b["source_ip"]]["accepted_seen"]
                  - result["stats"][b["source_ip"]]["accepted_blocked"] > 5]
    if collateral:
        print(f"Note: {len(collateral)} of those look like routine users "
              f"(IPs with >5 other successful logins) - check before tightening.")

    print(f"Per-IP details written to {outdir / 'lockout_simulation.csv'}")


if __name__ == "__main__":
    main()
