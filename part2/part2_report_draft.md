# Part 2: Technical Defensive Response (Group BB)

*Draft for the group report, same deal as the Part 1 draft: numbers are all
pulled from `part2/output/`, so they're safe to quote, but the wording could
use a once-over before it goes into report.pdf. Should fit in 3 pages with
the figure.*

## 1. Which Part 1 risk we're addressing, and why it's the right priority

We're responding to **Risk 3 from our risk matrix: SSH password
authentication on `web01` has no working rate limit or lockout.** Of the
five risks we identified, this one isn't the scariest-sounding (Risk 1, the
actual `deploy` compromise, is), but we picked it deliberately, for three
reasons.

First, it's the *enabling condition* for the two risks above and below it.
The `deploy` compromise (Risk 1) only happened because one IP was allowed
117 uninterrupted guesses in 34 minutes; the ongoing campaign (Risk 2) only
generates 3,724 failed attempts a week because nothing pushes back. Treating
the compromised account (rotate the password, audit the session) is
necessary but reactive - it cleans up after Risk 3, and leaves the door open
for the next burst. Closing the control gap is the fix that changes the
odds for every account at once.

Second, it's confirmed with unusually high confidence for a log-only
analysis. We don't have to infer the absence of rate-limiting from theory:
the evidence is 117 failures from one IP without interruption
(`part1/output/brute_force_success.csv`), and 443 "maximum authentication
attempts exceeded" errors showing sshd's per-connection cap firing while the
campaign simply reconnected and carried on
(`part1/output/summary_counts.csv`).

Third, it's the risk where a *technical* response actually bites. Risk 1's
remediation is mostly procedural (credential rotation, session audit);
Risk 3's is configuration and code, which is what Part 2 asks for.

## 2. What we propose

One control wouldn't be honest here - our own Part 1 uncertainty notes say
why. Rate-limiting by IP can be sidestepped by rotating addresses (we
couldn't tell whether the campaign is one actor or several, Risk 2), and any
detection that reads `web01`'s local log is only as good as a log an
attacker with sudo could edit (Risk 5 territory). So the response is three
small layers, each covering the previous one's known weakness:

**Layer 1 - Prevent (`config/fail2ban/jail.local`,
`config/sshd_config.d/50-hardening.conf`).** A fail2ban jail for sshd: 5
failed attempts within 10 minutes bans the source IP for 1 hour, doubling on
each repeat ban. Alongside it, four sshd settings the evidence directly
supports: `PermitRootLogin no` (root was guessed 149 times but has *zero*
legitimate SSH logins in the entire extract, so this costs nothing),
`MaxAuthTries 3`, `LoginGraceTime 30`, and `MaxStartups` to stop pre-auth
connections crowding out real admins. Phase two, commented out in the config
until keys are issued, is key-only authentication for the four
most-targeted privileged accounts - which ends password guessing against
them entirely rather than rate-limiting it.

**Layer 2 - Detect (`detector.py`).** Three alerting rules derived from the
attack patterns we actually observed, with thresholds picked from measured
gaps between legitimate and campaign behaviour (details in
`part2/README.md`): R1 flags a success immediately after a >= 10-failure
burst from the same IP (CRITICAL - this is precisely the `deploy` incident,
and Part 1's recommendation that we alert on "burst of failures followed by
a success"); R2 flags any IP reaching 25 failures in one burst (legitimate
IPs in our extract never exceed 9; campaign bursts never fall below 348);
R3 flags any *privileged account* accumulating 15 failures in an hour
regardless of source - the rule that still fires if the attacker rotates
IPs, which is the main way someone beats Layer 1 and R2.

**Layer 3 - Preserve (`config/rsyslog.d/90-forward-auth.conf`).** Forward
`auth`/`authpriv` logging to a separate collector over TCP with a disk
queue. Risk 5 was that attacker activity on a compromised `web01` is
indistinguishable from admin activity; the stronger version of that problem
is an attacker with sudo *editing the log itself*, at which point Layers 1-2
are analysing evidence the attacker controls. Off-host copies mean deleting
`web01`'s log no longer deletes the record.

## 3. Does it actually work? We tested it against our own extract

Rather than assert the policy is sensible, we replayed our full extract
through it (`simulate_lockout.py`, results in
`output/lockout_simulation.csv`):

- The policy issues 9 bans against **exactly the four campaign IPs** from
  Part 1 and nobody else. No legitimate IP is banned; no legitimate login is
  blocked. (Legitimate users do mistype - the worst run we measured is 9
  failures - but spread over more than 10 minutes, so they never trip the
  5-in-10-minutes trigger.)
- 2,510 of 3,724 failed attempts (67%) would never have reached sshd.
- Most importantly: 203.0.113.77's third ban of the week (4 hours, starting
  Jul 11 23:13:45 - 45 seconds and 5 attempts into the final burst) covers
  23:47:04, the moment `deploy` was actually compromised. **Under this
  policy, the Part 1 incident does not happen.**

The detection layer was tested the same way (`output/alerts.csv`). Across
the week the three rules raise **10 alerts, all of them campaign activity** -
a triage load of about one or two a day, which matters because an alert
stream noisy enough to be ignored is how 117 attempts went unnoticed in the
first place. In the final burst, R2 fires at 23:19:41, 27 minutes before the
compromise; R1 fires at the moment of compromise itself. And R2 had flagged
this specific IP four days earlier (Jul 07, 02:05). The figure below shows
the compromise window with each layer's firing time marked
(`output/detection_timeline.png`).

**[Figure: detection_timeline.png - cumulative failed attempts from
203.0.113.77 on 11 Jul, 23:13-23:47, with the simulated fail2ban ban
(23:13:45), the R2 alert (23:19:41), and the actual successful login
(23:47:04) marked.]**

In risk-matrix terms: Layer 1 cuts the *likelihood* of Risk 3's consequence
(a guessing campaign succeeding) - in the replay, to zero for the observed
traffic. Layer 2 cuts *time-to-detection* from "days later, by manual log
review" (which is how we found it) to under seven minutes. Layer 3 protects
the *investigability* of whatever still gets through. The phase-two key-only
migration removes the attack class altogether for the accounts that matter
most.

## 4. Limitations, trade-offs, and what's still exposed

- **The simulation replays recorded traffic; real attackers adapt.** Once
  bans start landing, a competent attacker rotates source IPs or slows below
  5-per-10-minutes. So "67% blocked" describes the observed campaign, not a
  future one. R3 exists for the rotation case (it keys on target account,
  not source), and slow guessing - while much harder to detect - also takes
  proportionally longer to succeed, which widens the window in which the
  phase-two key migration lands.
- **Lockout tools are a denial-of-service surface.** An attacker who can
  spoof or share an admin's egress IP can deliberately trip the ban and lock
  admins out. `jail.local` leaves `ignoreip` as an explicit placeholder for
  the org's admin networks - we can't fill it from a log extract, and
  shipping it empty is safer than guessing.
- **The key-only migration has a real operational cost.** deploy, webadmin
  and ops password-authenticate daily (330+ accepted logins each in our
  week). Flipping `PasswordAuthentication no` before keys are issued and
  tested would lock out the admins before it inconveniences any attacker,
  which is why that block ships commented out with the ordering spelled out.
- **Thresholds are tuned to one week of one host.** The
  legitimate-vs-campaign gap that makes 25 and 15 safe choices here could be
  narrower elsewhere, so every threshold is a command-line flag and the
  README documents how we measured our way to each value, so the tuning can
  be redone rather than trusted.
- **Detection still trusts sshd's logging at write time.** Layer 3 protects
  the log after it's written; nothing here helps if events are never logged.
  And our simulation counts `Failed password` lines only, where real
  fail2ban's sshd filter matches more line types - meaning the real
  deployment should ban slightly earlier than our replay, so we believe our
  numbers are conservative rather than flattering.
- **Residual risk we are explicitly not addressing:** what an attacker does
  *after* a successful login (Risk 5's core). Layer 3 makes the evidence
  survivable, but distinguishing attacker sessions from admin sessions in
  real time needs host-level controls (auditd, command logging) beyond
  authentication - that's the next project, not a footnote to this one.

## 5. What we'd deploy first, in order

1. `jail.local` with `ignoreip` filled in by someone who knows the admin
   networks, plus the four uncommented sshd settings - immediate, low-risk,
   and the replay says it stops the observed campaign outright.
2. `detector.py`'s rules as alerts on the existing log pipeline (or as a
   cron job on the collector once Layer 3 is up).
3. The rsyslog forwarder, so the evidence chain stops depending on the
   host under attack.
4. Keys for deploy/webadmin/ops/sysadmin, then enable the `Match User`
   block - the structural fix that makes most of the above a second line of
   defence instead of the only one.
