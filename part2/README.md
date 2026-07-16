# Part 2 - Technical Defensive Response (Group BB)

This folder is the technical side of our Part 2 submission. The risk we're
responding to is **Risk 3 from our Part 1 risk matrix**: SSH password
authentication on `web01` has no working rate limit or lockout. That's the
gap that let one IP fire 117 uninterrupted password guesses at `deploy` in
34 minutes and get in (`part1/output/brute_force_success.csv`), so fixing it
is also, in practice, a response to Risk 1 (the `deploy` compromise) and
Risk 2 (the wider guessing campaign).

The response has three layers, and each file here belongs to one of them:

| Layer | What | Where |
|---|---|---|
| Prevent | fail2ban rate-limit/lockout policy + SSH hardening | `config/fail2ban/jail.local`, `config/sshd_config.d/50-hardening.conf` |
| Detect | Alerting rules for the attack patterns Part 1 found | `detector.py` |
| Preserve | Ship auth logs off-host so a compromised `web01` can't erase the evidence | `config/rsyslog.d/90-forward-auth.conf` |

`simulate_lockout.py` isn't a layer itself - it's how we tested the
"prevent" layer against our actual extract instead of just asserting it
would work.

## What you need

Same as Part 1: Python 3.10+ (built and tested on 3.11), and `matplotlib`
only if you want the timeline figure (`--plot`). Both scripts are otherwise
standard library only.

```
pip install matplotlib
```

## Running it

From inside `part2/` (both scripts default to `../1_auth.log.txt`, same
layout as Part 1):

```
python detector.py ../1_auth.log.txt --plot
python simulate_lockout.py ../1_auth.log.txt
```

`--outdir` defaults to `output/`, which is already populated from our last
run; rerunning overwrites it.

Parsing is shared via `authlog_parsing.py`, which is a trimmed copy of the
Part 1 parser (same regexes, verbatim) so Part 1 and Part 2 can never
disagree about what counts as a failed attempt. Sanity check: `detector.py`'s
R1 rule reproduces the Part 1 headline finding exactly - 117 failed attempts
from 203.0.113.77, then `deploy` compromised at Jul 11 23:47:04.

## The detection rules, and why the thresholds are what they are

We didn't want magic numbers, so every threshold is (a) an argparse flag a
review team can re-tune for a different extract, and (b) justified by a
measured gap in our own data between legitimate and campaign behaviour:

- **R1 `burst_then_success` (CRITICAL, >= 10 failures then a success from
  the same IP):** the same logic and threshold as Part 1's
  `build_brute_force_success`, kept identical deliberately. Ordinary users
  in the extract mistype 5-6 times at worst; 10 sits comfortably above
  that, and the one real compromise scored 117.
- **R2 `high_volume_source` (HIGH, >= 25 failures in one burst, 30-min gap
  grouping):** we measured every IP's largest burst. Legitimate IPs top out
  at 9; the four campaign IPs' smallest maximum burst is 348. 25 sits in
  the dead zone between those, so on this extract the rule has a 0% false
  positive rate with a ~14x margin before a real burst would be missed.
  It fires at the moment the 25th attempt arrives, not when the burst ends -
  that's what gives it lead time (6m41s into the final burst, 27 minutes
  before the compromise).
- **R3 `privileged_targeting` (MEDIUM, >= 15 failures against one
  privileged account within 60 minutes, any source):** R1/R2 key on source
  IP, so an attacker rotating addresses would slip past both - which is
  exactly the uncertainty we flagged on Risk 2 ("one actor or several?").
  R3 keys on the *target account* instead. Measured 60-minute peaks:
  `ops` never exceeds 7 (an account under no concentrated attack), while
  `root` hits 19, `sysadmin` 20, `webadmin` 25 and `deploy` 131 during
  campaign windows. 15 splits those cleanly.

Across the whole week the three rules produce **10 alerts total** (1
CRITICAL, 5 HIGH, 4 MEDIUM), every one of them campaign activity. That
matters: an alert stream noisy enough to be ignored is how 117 attempts go
unnoticed in the first place.

## What the lockout simulation showed

`simulate_lockout.py` replays the extract through the exact policy in
`jail.local` (5 retries in 10 minutes -> 1h ban, doubling on repeat). Under
that policy:

- 9 bans are issued against exactly the 4 campaign IPs from Part 1 - no
  legitimate IP is ever banned, and no legitimate login is ever blocked
- 2,510 of 3,724 failed attempts (67%) never reach sshd
- 203.0.113.77's third ban (4 hours, starting Jul 11 23:13:45 - 45 seconds
  into the final burst) covers Jul 11 23:47:04, so **the successful
  brute-force login to `deploy` falls inside a ban window and is
  prevented**

The one honesty caveat, which is also in the report: the simulation replays
recorded traffic as-is. A real attacker who keeps getting banned would
adapt (rotate IPs, slow down), so the claim is "this observed attack would
have been interrupted", not "this class of attack is now impossible".
That's why the detection layer and the key-only migration exist.

## What ends up in `output/`

| File | What it is |
|---|---|
| `alerts.csv` | Every alert the three rules raise on the extract, with fire time, rule, severity, and evidence detail. |
| `lockout_simulation.csv` | Per-IP replay results: attempts seen/blocked, logins blocked, bans issued. |
| `detection_timeline.png` | The compromise window (Jul 11 23:13-23:47) with the moment each proposed layer fires marked on it. This is the Part 2 figure in the report. |

## Assumptions and limitations

- Thresholds were tuned on one week of one host's traffic. On another
  extract (or next month's traffic) the legitimate/attack gap could be
  narrower; that's why they're flags, not constants, and why the README
  documents how we derived them so the derivation can be repeated.
- The simulation models fail2ban's counting a little more simply than the
  real thing (it counts `Failed password` lines only; real fail2ban with the
  standard sshd filter also matches some pre-auth disconnect lines, and bans
  at the firewall level with its own timing quirks). We'd expect the real
  deployment to ban slightly *earlier* than our replay, not later, because
  it matches more line types - so the numbers here should be conservative.
- `ignoreip` in `jail.local` is deliberately left as a placeholder. We can't
  know the organisation's admin egress addresses from a log extract, and
  shipping a lockout tool without an admin allowlist is how you hand an
  attacker a denial-of-service button against the org's own admins.
- The `Match User` key-only block in the sshd config is commented out on
  purpose: deploy/webadmin/ops currently password-authenticate daily
  (330+ accepted logins each in the extract), so keys have to be issued and
  tested before it's enabled, or the fix locks out the admins before it
  locks out anyone else.
- Everything here still depends on sshd's logging being trustworthy at the
  moment of writing. The rsyslog forwarder mitigates after-the-fact
  tampering but can't do anything about events that were never logged.
