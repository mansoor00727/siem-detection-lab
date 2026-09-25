# Phase 4 — Attack Simulation

**Goal:** stop trusting the dashboard and start proving what the lab actually detects, by running real named attack techniques and checking the evidence — not the "no alerts fired" default assumption.

**Tooling:** [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — chosen because every test maps to a specific MITRE ATT&CK technique ID, executes a real (if minimal) version of the technique rather than a synthetic log line, and is cross-platform via `Invoke-AtomicTest` (PowerShell Core) on both Windows and Linux.

## Why this phase exists

Phase 3 established the ingestion vs. alerting distinction and set expectations for background noise. Phase 4 is where that distinction gets used for real: every result below was checked against raw ingestion (`archives.log`/`archives.json`, `ausearch`, or the dashboard's raw event view) before concluding an alert was or wasn't present — because "nothing in `alerts.log`" and "nothing arrived" are different findings with different fixes.

## Techniques executed

| Technique | Target | Result |
|---|---|---|
| T1082 — System Information Discovery | Windows | Detected by stock ruleset — no gap |
| T1547.001 — Registry Run Keys / Startup Folder (HKCU) | Windows | Initially assessed as a gap in Phase 3 baselining; **retracted in Phase 5** — see below |
| T1053.003 — Cron Persistence | Linux (Rocky) | Gap found — no custom rule alerted on the underlying command execution or the cron spool write; closed in Phase 5 |
| Command execution via auditd `exec_commands`/`exec_commands_root` keys | Linux (Rocky) | Gap found — telemetry was captured and correctly tagged by auditd, but Wazuh's stock ruleset only alerted on `auditd` *configuration changes*, never on the commands the custom keys were built to flag; closed in Phase 5 |
| T1070.006 — Timestomp | Windows | **Inconclusive by design** — see note below |
| T1046 — Network Service Discovery (`nmap`) | Cross-segment, endpoint → management network | Gap found — the firewall's only alerting rule is burst-detection (18+ blocked events in 45s), which a deliberate low-and-slow scan doesn't trigger; closed in Phase 5 |

## Note on the timestomp test (T1070.006)

This test manipulated a file's timestamp inside Atomic Red Team's own working directory (`C:\AtomicRedTeam\ExternalPayloads\...`), which is outside the paths Windows FIM is actually configured to watch (scoped to system-critical locations, not arbitrary tool working directories). The test executed successfully and the timestamp change was confirmed directly (`CreationTime` rolled back to 1970), but the resulting "no FIM alert" is a **path-scope limitation of the test setup, not a confirmed detection gap** — the two look identical in isolation, and only checking the target path against the FIM configuration distinguishes them. Recorded as inconclusive rather than claimed either way, since overclaiming an untested case is the same credibility risk as underclaiming a real one.

## Outcome

Four genuine detection gaps identified with evidence (three confirmed real, carried into Phase 5; the fourth investigated further and retracted — see Phase 5), one technique confirmed already covered by the stock ruleset, one technique correctly scoped as inconclusive rather than forced into a finding either way.
