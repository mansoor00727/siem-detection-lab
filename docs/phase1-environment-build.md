# Phase 1 — Environment Build

**Goal:** a working Wazuh manager, indexer, and dashboard, on a hypervisor that fits home hardware — before touching any endpoints or detection logic.

## Platform decisions

| Decision | Choice | Rejected alternatives | Why |
|---|---|---|---|
| SIEM | Wazuh | Security Onion, raw ELK, Splunk Free | Agent-based endpoint collection out of the box, manageable learning curve for a first SIEM build, lighter hardware footprint than Security Onion's bundled Zeek/Suricata stack |
| Firewall | OPNsense | pfSense | Fully open licensing with no Community/Plus split |
| Linux endpoint OS | Rocky Linux 9.8 Minimal | Rocky 10, DVD ISO | RHEL/Rocky 9 reflects what's actually deployed in enterprise environments today (9 vs. the newer 10); the Minimal (not DVD) install forces a headless, CLI-driven build and keeps the attack surface smaller |
| Hypervisor | VirtualBox | — | Free, runs on the available Windows host ("Legion" — i9, 32GB RAM, 3TB storage) without needing dedicated server hardware |

## Install path

The Wazuh all-in-one installer was attempted first and hit seven distinct root causes before it produced a working stack:

1. Stale package repository URL
2. Clock skew between host and VM
3. A `curl` command typo
4. Insufficient VM RAM sizing for the indexer
5. LVM logical volume under-allocation (VirtualBox's disk provisioning doesn't auto-extend the LVM volume or filesystem — required `lvextend` + `resize2fs`)
6. Windows Defender real-time scanning throttling virtual disk I/O for the VMs folder (fixed by excluding the folder and enabling Host I/O Cache)
7. A systemd service startup timeout during indexer warm-up

After the sixth fix, a late-stage upstream bug surfaced (a "user `wazuh` not registered" API error), root-caused via the Wazuh GitHub issue tracker rather than guessed at. Rather than keep patching around the all-in-one installer, the build was **restarted component-by-component** (indexer, manager, dashboard installed and configured separately) — a deliberate architecture decision, not just a workaround: it trades a faster happy-path install for full visibility into what each component needs and how they talk to each other, which paid off repeatedly in later phases (credential rotation, service health-checking) where understanding the three-component split mattered.

One additional recovery during this phase: an overly broad `pkill` command aimed at a hung process instead matched and killed a live `wazuh-indexer` process mid-write, corrupting directory ownership. Diagnosed via `journalctl`, fixed with a targeted `chown -R` — no reinstall needed.

## Outcome

Working dashboard, indexer, and manager, with alerts flowing, installed via a path that's fully understood rather than a black-box script.

## Interview-relevant judgment calls

- Choosing to root-cause an installer bug via upstream issue research rather than reflexively reinstalling.
- Recognizing when a "just re-run the installer" loop had stopped being productive and switching install strategy instead of persisting with the same approach.
