# Phase 2 — Log Source Onboarding & Network Architecture

**Goal:** get real telemetry flowing from a Windows endpoint, a Linux endpoint, and a firewall into Wazuh — behind a network that actually enforces segmentation, not just one that's configured to look like it does.

## Network design

```
                    [Internet]
                        |
                       NAT
                        |
                  ┌─────────────┐
                  │  OPNsense   │
                  │  WAN / LAN / MGMT
                  └─────────────┘
                    /          \
        192.168.57.0/24    192.168.56.0/24
        (endpoint segment)   (management segment)
                |                    |
      ┌─────────┴─────────┐    ┌─────┴─────┐
  win11-endpoint     rocky-endpoint   wazuh-manager
```

**Design decision: the manager is single-homed on the management segment, not bridged across both.** Putting everything on one flat segment was rejected — agent-to-manager traffic would never cross the firewall, so there'd be no meaningful allow/deny telemetry at all. Multi-homing the manager onto both segments was also rejected — that turns the SIEM itself into a bridge between security zones, and a pivot point if it's ever compromised. The trade-off: every single agent check-in and every denied packet crosses the firewall boundary, which is what makes the firewall worth having in this lab in the first place.

## Firewall ruleset (OPNsense, LAN interface, first-match-wins)

1. Allow LAN → OPNsense GUI (443)
2. Allow LAN → OPNsense DNS (53)
3. Allow LAN → OPNsense NTP (123)
4. Allow Wazuh agents → manager (1514–1515, LAN net → manager /32) — **logged**
5. **Block LAN → management segment, default deny** (all protocols) — **logged**
6. Allow LAN web egress (443 only — port 80 deliberately left blocked; both package repos and Windows Update work over HTTPS, so denied port-80 attempts become useful telemetry instead of legitimate traffic)
7. Default allow rules — disabled, not deleted (kept for fast rollback)

Logging is deliberately enabled on only two rules — the permitted agent path and the denied cross-segment path — since those are the two that produce meaningful signal; logging DNS/NTP/web egress would just be noise.

## The NAT bypass — the most important finding of this phase

A positive test for the block rule (ping from the Rocky endpoint toward the management segment) appeared to fail: replies came back with no matching firewall log entry. `ip route get` revealed the actual cause — **both endpoints held two default routes simultaneously**: one via the original NAT adapter (metric 100) and one via OPNsense (metric 101). The lower metric always won, so all non-local traffic was silently leaving via NAT and bypassing the firewall entirely.

This meant the segmentation policy was **configured correctly and completely unenforced** — and critically, any attack-simulation traffic in Phase 4 would have been invisible to network monitoring if this hadn't been caught first.

Before removing the bypass, real egress dependencies were worked out and satisfied first: HTTPS (repos/updates, already covered), DNS (already covered), and NTP (**not** covered — a genuine gap that would have broken time sync the moment NAT was removed). Rather than permit external NTP, OPNsense was configured as the lab's internal authoritative time source — a single internal source is better practice for cross-log-source time correlation and needs one fewer firewall permit. Both endpoints were repointed and confirmed synced *before* the NAT adapter was removed.

With NTP settled, the NAT adapter was removed from each endpoint in turn and re-verified: single default route via OPNsense, real traffic (`dnf check-update`) succeeding through the permitted egress rule, and the same ping that succeeded before now correctly timing out with a matching firewall log entry — same test, opposite and now-correct result.

**Why this is the strongest finding in the project:** it's the difference between a control that's configured and a control that's proven. Anyone can add a firewall rule; verifying that traffic actually has no other path is the part that matters in a real environment.

## Log sources onboarded

- **Windows endpoint** — Wazuh agent, SCA (CIS Windows 11 benchmark), real-time FIM, Windows Event Log collection.
- **Linux endpoint (Rocky)** — Wazuh agent installed via the RPM repo (`dnf`, not a curl-piped install script — auditable, versioned, GPG-checked), SCA (`cis_rocky_linux_9.yml`), real-time FIM, journald/PAM/sudo collection, rootcheck.
- **OPNsense firewall** — onboarded as an agentless syslog source (UDP 514), with `allowed-ips` restricted to the firewall's own address. This restriction matters because syslog is unauthenticated by default — without it, anything able to reach port 514 could inject fabricated events into the SIEM. Validated in stages (packet capture → port binding → parsed output in `archives.log`) rather than assuming "no errors" meant "working."

## Operational lessons banked

- Agent "Active" status in `agent_control -l` is a stored value, not a liveness check — a fully dead manager can still report agents as Active. Verify with actual listening ports (`ss -tlnp`/`ss -ulnp`) or `wazuh-control status`.
- A firewall rule with no interface selected becomes a floating rule, evaluated on every interface — an easy accidental way to open a hole in a policy.
- DHCP leases from a hypervisor's host-only DHCP server are not guaranteed persistent, even when they look stable — pin static addresses for anything else that depends on them by IP.
- Firewall behavior is direction-dependent under stateful inspection: return traffic on a connection the protected segment initiated is automatically permitted, but unsolicited inbound in the other direction still hits the implicit deny.

## Outcome

Both endpoints active behind the firewall, no route around it, all three log sources validated end-to-end, firewall allow/deny telemetry flowing into Wazuh as a genuine third data source.
