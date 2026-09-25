# Phase 3 — Baseline: What Normal Looks Like

**Purpose:** reference point for interpreting Phase 4 attack-simulation results. Anything that shows up during Phase 4 gets compared against this document — if it's already here, it's noise; if it's not, it's worth investigating.

**Status:** substantially complete. One item outstanding — see "Outstanding: clean-day re-baseline" at the end.

---

## Environment snapshot at time of writing

| Asset | Address | Role |
|---|---|---|
| `wazuh-manager` | 192.168.56.101 | SIEM manager, indexer, dashboard |
| `WIN11-ENDPOINT` | 192.168.57.121 | Windows 11, Sysmon (SwiftOnSecurity config) |
| `rocky-endpoint` | 192.168.57.210 | Rocky Linux 9.8, auditd instrumented |
| `opnsense-fw` | LAN 192.168.57.1 / OPT1 192.168.56.254 | Firewall, syslog source |

All three endpoints behind a default-deny firewall segmenting `192.168.57.0/24` from `192.168.56.0/24`, no NAT bypass, internal NTP hierarchy anchored to the firewall.

## Coverage matrix — final state

| Category | Windows | Rocky | Firewall |
|---|---|---|---|
| Authentication | ✅ Event Log | ✅ PAM | n/a |
| Process execution + command line | ✅ Sysmon, alerting | ✅ ingested, no rule | n/a |
| File integrity | ✅ real-time FIM | ✅ real-time FIM | n/a |
| Registry | ✅ Sysmon, **partial — see gap below** | n/a | n/a |
| Network connections | ✅ Sysmon + firewall correlation possible | firewall-log only | ✅ ingested, mostly no rule |
| Privilege escalation | untested | ✅ sudo (rule 5402) | n/a |

## Known recurring alerts — expected, not signal

These fire regularly under normal idle conditions. Seeing them during Phase 4 is not evidence of anything; they need to be filtered out mentally (or later, technically) before attributing anything to a simulated attack.

- **Rule 61618 — "Sysmon - Suspicious Process - svchost.exe"** (level 12). Observed firing roughly every 10–15 minutes throughout a normal afternoon. Almost certainly a legitimate Windows service restart pattern that happens to match this heuristic's launch-pattern check. Assessed, not confirmed via deeper investigation — if it ever needs ruling out definitively, check the parent process chain and command-line arguments via `Get-Process` or the dashboard's raw event view.
- **Rule 92058 — "Application Compatibility Database launched."** Recurs alongside the above; part of normal Windows compatibility subsystem activity (`sdbinst.exe`).
- **Rule 87702 — "Multiple pfSense firewall blocks events from same source"** (level 10, burst-detection: 18 events in 45s). Investigated one real firing: `192.168.57.121` making rapid blocked port-80 SYN attempts to multiple rotating external IPs (`209.148.170.176`, `72.136.195.x`, etc.). Assessed as very likely benign — consistent with Windows connectivity-checking / delivery-optimization behavior against CDN endpoints, all blocked since port 80 is deliberately closed, no completed connections. **Caveat:** not fully confirmable without process-level correlation on the Windows side (which host process initiated it). Known coverage gap at time of writing.
- **NetBIOS broadcast blocks (UDP 137/138)** on the firewall, from both endpoints, hitting the implicit deny on LAN and OPT1. Routine Windows network discovery chatter. High volume, zero significance.
- **Rules 5501/5502/5402 (PAM session open/close, sudo-to-root)** on the manager itself — this is the operator (Zuhaib) working in SSH sessions, not endpoint activity. Expect these to spike whenever a session is actively being worked.
- **Rule 80705 — "Auditd: Configuration changed"** on Rocky — fires whenever `auditctl`/`augenrules` rules are reloaded. Expected only during deliberate config changes, not during quiet operation.

## Confirmed pattern: ingestion vs. alerting

The single most important finding from this phase, repeated across all three log sources: **collection and decoding are not the same as alerting.** In every case checked, raw events reached the manager and were correctly parsed — visible via `ausearch`, `archives.log` with `logall` temporarily enabled, or the dashboard's raw event view — well before any corresponding entry appeared in `alerts.log`. Absence from `alerts.log` means "didn't cross this rule's severity threshold," not "never arrived." This distinction needs to be checked explicitly, every time, before concluding a gap exists.

## Confirmed detection gaps — Phase 5 targets, in priority order

1. **No custom rule alerts on arbitrary command execution on Rocky.** `auditd` rules (`exec_commands`, `exec_commands_root`) capture full `execve` telemetry with argv, correctly tagged and verified via `ausearch`. Wazuh's stock `0365-auditd_rules.xml` only alerts on audit *configuration* changes (rule 80705), not on execution matching these custom keys. **Target:** a custom rule chaining off the pattern used throughout `0365-auditd_rules.xml` (`if_sid` on the audit parent, matching `audit.type: SYSCALL` + the custom key field), scoped carefully — this will fire on every command a logged-in user runs, so it needs either a low severity level or additional scoping (e.g., only flag when the command matches a sensitive binary list) to avoid drowning in noise.

2. **No custom rule alerts on cross-segment firewall blocks specifically.** The only firewall rule that alerts is the generic burst-detection rule (87702), which requires 18 matching events in 45 seconds from one source — it will not catch a slow, deliberate single-connection probe from `192.168.57.0/24` toward `192.168.56.0/24`, which is exactly the shape of a real lateral-movement attempt. **Target:** a rule matching `filterlog` events where source is `192.168.57.0/24`, destination is `192.168.56.0/24`, and action is block — independent of frequency.

3. **Wazuh's stock Sysmon registry ruleset (`0860-sysmon_id_13.xml`) has a structural blind spot for per-user persistence.** Rule 92300 (the parent condition for all Run-key persistence detection, rules 92301–92306) matches `win.eventdata.targetObject` starting with `SOFTWARE\...` — an `HKLM`-style path. Sysmon logs per-user (`HKCU`) registry writes using the `HKU\<SID>\Software\...` format instead, which never matches. **Confirmed via a deliberate test:** wrote a value to `HKCU\...\CurrentVersion\Run`, verified Sysmon generated the event locally (Event ID 13, correctly tagged `RuleName: T1060,RunKey`), confirmed zero corresponding alerts in the index with no time-window restriction. This means **the entire HKCU persistence detection chain — including the level-12 malicious-extension check (92301) and the level-12 remote-access-tool check (92303) — is currently blind to the most common, lowest-privilege version of this technique.** **Target:** a custom rule extending 92300's regex to also match `HKU\\S-1-5-21-[\\d-]+\\Software\\...\\Run`, which would immediately activate the existing child-rule chain for free.

## Health-check routine

Run `wazuh-health` (script at `/usr/local/bin/wazuh-health` on the manager) at the start of every session, before anything else. Healthy baseline output:

- All four core services (`wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`, `filebeat`) report `active`
- Six port bindings present: 1514/tcp, 1515/tcp, 9200/tcp, 55000/tcp (both IPv4 and IPv6), 514/udp
- `wazuh-control status` shows every daemon running except the five known-intentional exceptions: `wazuh-clusterd`, `wazuh-maild`, `wazuh-agentlessd`, `wazuh-integratord`, `wazuh-csyslogd`
- `filebeat test output` ends in `talk to server... OK`
- `agent_control -l` lists both `WIN11-ENDPOINT` and `rocky-endpoint` as `Active`

This exists because the project has hit three separate silent full-outages (Filebeat stopped and disabled with no warning; every manager daemon dead while `agent_control` still reported stale "Active" status; a config error that would have gone unnoticed without checking logs) — each cheap to catch, expensive to discover by accident.

## Clean-day re-baseline — closed with a documented limitation

A true 24-hour idle measurement was attempted twice and both attempts failed for legitimate, worth-recording reasons rather than a testing mistake:

1. **First attempt** produced identical, rule-for-rule static numbers on Rocky across two "24 hours apart" queries (72 alerts, same 19/17/16/9/2 split on rules 5501/5502/5402/80705/554 both times). Root-caused to a **38-hour clock drift on the manager itself** — `chronyc tracking` showed the system time was ~137,000 seconds (~38 hours) behind reference time, meaning every `now-24h` query was sampling roughly the same stale window rather than genuinely rolling forward. Corrected via `chronyc makestep` (immediate step correction rather than gradual slew) and `hwclock --systohc` (writes the corrected time to the hardware clock so the drift doesn't silently reappear on next boot). Confirmed post-fix: `System clock synchronized: yes`, `Leap status: Normal`, and all Wazuh daemons still healthy after the ~38-hour step. **This is itself a legitimate finding**, not a footnote: an undetected clock drift on the SIEM manager's own host quietly corrupted a measurement, and the only reason it was caught was that the data looked suspiciously static rather than because any monitoring flagged the drift itself — the exact blind spot a "monitor the monitor" health check should cover, and a good argument for why NTP health specifically belongs in a routine check going forward.

2. **Second attempt**, after the clock fix, could not run to completion. The lab runs on a personal laptop (not dedicated always-on hardware), which experienced Windows updates and reboots that interrupted VM uptime before a genuine 24-hour idle window could complete. This is a real, recurring constraint of home-lab infrastructure — worth stating explicitly rather than presenting a number as clean when it isn't.

**Decision made:** rather than continue chasing an empirically "perfect" idle window against unreliable host uptime, the baseline below is a **reasoned estimate**, built from the two (contaminated but consistent) 24h reads already collected, with the known contamination sources explicitly subtracted out in the reasoning rather than the data.

### Estimated quiet-state baseline (reasoned, not empirically isolated)

| Source | Observed raw (contaminated) | Known contamination | Estimated genuine idle rate |
|---|---|---|---|
| `rocky-endpoint` | ~72/day | ~52 from PAM/sudo session events during active SSH work; ~9 from `auditd` config-reload events (only fire on deliberate rule changes); ~2 FIM test-file alerts | **Low single digits/day** — Rocky should be nearly silent when genuinely untouched, since journald/PAM only fire on logins and auditd's execve rules only fire on actual command execution |
| `WIN11-ENDPOINT` | 203–380/day across two reads | Includes active testing (Sysmon install, registry test, repeated `Get-WinEvent` checks) | **Recurring rule 61618 ("Sysmon - Suspicious Process - svchost.exe") and 92058 ("Application Compatibility Database launched") observed firing on their own roughly every 10–15 minutes even outside deliberate testing** — this is genuine background Windows noise, not operator activity, and should be treated as expected baseline going forward. A rough estimate of 60–100/day purely from this recurring pattern is reasonable; anything meaningfully above that during Phase 4 is worth attention. |
| `wazuh-manager` | 234–259/day | Almost entirely `5501`/`5502`/`5402` (PAM/sudo) tied directly to active SSH sessions | **Near zero** when genuinely idle — this source is a near-perfect proxy for "was a human working on the box," which is itself a useful thing to know: manager-agent alert volume during Phase 4 sessions should be discounted as operator noise, not treated as findings |
| Firewall (via manager) | not isolated separately | NetBIOS broadcast blocks (137/138) confirmed high-volume and constant; rule 87702 bursts observed intermittently | **NetBIOS blocks should be treated as constant background noise at any volume**; 87702 firing occasionally (once every few hours) is expected, repeated rapid firing would not be |

**How this gets used in Phase 4:** rather than a single trusted number, the working rule is — Rocky and the manager should be nearly silent absent operator activity, so *any* meaningful volume from either during an attack simulation is signal. Windows will have a real, non-zero hum from Sysmon's own heuristics catching benign OS behavior, so Windows findings need to be filtered against the specific *rule IDs* already identified as recurring background noise (61618, 92058) rather than against a raw volume number.

---

*Phase 3 is now closed on this basis. The clock-drift finding and the reasoning behind accepting an estimated rather than measured baseline are both worth including in the write-up — they demonstrate the same judgment as the earlier "declined to mark Phase 3 complete without a real check" moment, just resolved by making a scoped, explicit trade-off instead of waiting indefinitely for ideal conditions that the hardware can't reliably provide.*
