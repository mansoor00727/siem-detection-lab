# Phase 5 — Detection Engineering

**Goal:** close the real gaps Phase 4 found, verify each fix against the same attack that surfaced it, and — just as importantly — catch and correct a gap that turned out not to be real before it shipped as a "fix."

All rules live in [`detections/local_rules.xml`](../detections/local_rules.xml), rule ID range `100000+` (Wazuh's convention for custom, non-vendor rules).

## Rule 100400 / 100401 — Linux command execution visibility

**Gap:** `auditd` rules (`exec_commands`, `exec_commands_root`) captured full `execve` telemetry, correctly tagged and verified via `ausearch` — but Wazuh's stock ruleset only alerted on audit *configuration changes*, never on execution matching these custom keys. The telemetry existed and was silently dropped at the rule layer.

```xml
<rule id="100400" level="5">
  <if_group>audit</if_group>
  <field name="audit.key" type="pcre2">^exec_commands$</field>
  <description>Command executed on monitored Linux host (auditd exec_commands)</description>
  <mitre><id>T1059</id></mitre>
</rule>

<rule id="100401" level="5">
  <if_group>audit</if_group>
  <field name="audit.key" type="pcre2">^exec_commands_root$</field>
  <description>Command executed as root on monitored Linux host (auditd exec_commands_root)</description>
  <mitre><id>T1059</id></mitre>
</rule>
```

**Bug caught during build, not after:** the first version of these rules had no anchors — `<field name="audit.key">exec_commands</field>` matches as an unanchored substring, so `exec_commands_root` events also matched the `exec_commands` pattern, and rule 100400 (declared first) always won. Rule 100401 never fired despite being logically correct. Confirmed by checking `rule.id` on a live fired alert against the actual `audit.key` value — `100400` was firing on events tagged `exec_commands_root`. Fixed with `type="pcre2"` and `^...$` anchors, then **re-verified live**: `whoami` fires 100400, `sudo whoami` fires 100401, correctly separated.

*This is a general lesson, not a one-off: unanchored substring matching is a common way for a "more specific" rule to be silently shadowed by a broader one that happens to declare first.*

## Rule 100402 — Cron persistence via direct spool write

**Gap:** the existing cron-persistence signal only worked because it decoded the `crontab` binary's own log line — a direct write to `/var/spool/cron/<user>` (bypassing `crontab` entirely) produced no detection at all, despite being the more evasive and more realistic version of the technique.

```xml
<rule id="100402" level="8">
  <if_group>audit</if_group>
  <field name="audit.key" type="pcre2">^cron_persistence$</field>
  <description>Direct write to cron spool directory (bypasses crontab self-logging)</description>
  <mitre><id>T1053.003</id></mitre>
</rule>
```

Backed by a new auditd watch rule: `-w /var/spool/cron -p wa -k cron_persistence`, plus real-time FIM on `/var/spool/cron` in `ossec.conf`.

**Troubleshooting note:** after adding the FIM directory, verification produced no alerts for over an hour. Root cause: the `ossec.conf` edit was made on the Rocky endpoint, but only `wazuh-manager` (on the SIEM host) had been restarted repeatedly during unrelated rule work — the **agent's own service was never restarted**, so it kept running on its old, pre-edit config. Diagnosed by checking `systemctl status wazuh-agent`'s "Active since" timestamp against the time of the config change, and cross-referencing FIM scan-start log lines showing no new scan since before the edit. Fixed with an explicit agent restart on the correct host, confirmed by a fresh scan-start log entry and a subsequent clean FIM "added" alert.

## Rule 100500 — Cross-segment firewall blocks, independent of frequency

**Gap:** the only firewall-alerting rule in the stock ruleset is burst-detection (18+ matching blocked events in 45 seconds from one source) — sufficient for noisy scanning, but blind to a slow, deliberate single-connection probe from the endpoint segment toward the management segment, which is exactly the shape a real lateral-movement attempt would take.

```xml
<rule id="100500" level="8">
  <if_sid>87701</if_sid>
  <srcip>192.168.57.0/24</srcip>
  <dstip>192.168.56.0/24</dstip>
  <description>Blocked traffic from endpoint segment to management segment</description>
  <mitre><id>T1046</id></mitre>
</rule>
```

Chained off rule `87701` deliberately, not `87700` or a duplicate match against the raw decoder fields — `87701` is a stock rule that fires on *every* firewall block event but is itself suppressed from logging (`<options>no_log</options>`); it exists purely to feed the burst-counter rule `87702`. Using it as the parent condition means 100500 inherits the correct match logic for "this was a block" without re-deriving it, and fires independently of the frequency threshold that gates 87702.

**Verified live:** an `nmap` scan from the Rocky endpoint against the management segment produced **zero** alerts before this rule existed (confirmed by checking for rule 87702 hits in the scan's time window — the only two hits found were unrelated Windows connectivity-check noise to external IPs, correctly ruled out rather than mistaken for a match) and a correctly-firing 100500 alert after.

## Retracted finding — HKCU registry persistence (T1547.001)

Phase 3 baselining concluded that Wazuh's stock Sysmon registry ruleset (`0860-sysmon_id_13.xml`) had a structural blind spot: rule 92300, the parent condition for the whole Run-key persistence detection chain, appeared to require an `HKLM`-style path (`SOFTWARE\...`), while Sysmon logs per-user registry writes as `HKU\<SID>\Software\...` — a different prefix that seemingly could never match. A deliberate registry write to `HKCU\...\CurrentVersion\Run` produced a Sysmon event but no corresponding alert, which was read as confirmation.

**Before building a "fix" for this, it was re-tested and checked more rigorously — and the original finding didn't hold up.** Two things exposed the error:

1. `wazuh-logtest` cannot properly evaluate Windows eventchannel/Sysmon events fed to it directly — it lacks the eventchannel context a real agent connection provides, so it was decoding the test JSON generically rather than as the Sysmon-specific event type, and rule 92300's `if_group` condition never had a chance to match in that tool regardless of the regex itself. This made the tool look like it was confirming the gap when it was actually incapable of testing it at all.
2. Re-running the actual Atomic Red Team T1547.001 test live (rather than trusting the isolated `wazuh-logtest` check) showed the **stock rule 92302 fired correctly** — not a custom rule, the original stock rule believed to be blind to this path. A standalone Python `re.search()` test against rule 92300's real regex, run outside the Wazuh pipeline entirely, confirmed why: the pattern was never anchored with `^`/`$`, so it was always an unanchored substring match that matches `HKU\<SID>\...` paths just as well as `HKLM`-style ones. The believed restriction never existed.

The custom rules originally written to "close" this gap (100300–100303) were deleted rather than kept as a redundant fix for a gap that wasn't there.

**Why this is included as a finding rather than left out:** a portfolio that only ever shows gaps found and fixed invites the question of how those gaps were verified in the first place. Catching your own false positive — recognizing that a test tool's limitation had produced a wrong conclusion, and correcting it before it shipped as a "fix" — demonstrates the same verification discipline as the real gaps above, applied to your own prior work instead of the vendor's.

## Outcome

Three genuine detection gaps closed and independently re-verified with live re-tests using the same technique that originally surfaced each one; one believed gap investigated further, found to be inaccurate, and retracted with the reasoning documented.
