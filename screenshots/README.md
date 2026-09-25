# Screenshots

Drop sanitized dashboard/alert/rule-test screenshots here as they're gathered (blur or crop out any real IP outside the lab's private ranges, hostnames tied to your identity, etc. — the lab's own 192.168.x addresses are fine to leave visible since they're private-range and meaningless outside this network).

Suggested set, matching the phase docs:
- `phase1-dashboard-healthy.png` — working Wazuh dashboard, all daemons green
- `phase2-firewall-rules.png` — OPNsense ruleset in evaluation order
- `phase2-nat-bypass-route.png` — the `ip route get` output showing the dual default route finding
- `phase3-coverage-matrix.png` — dashboard view backing the coverage audit
- `phase4-atomic-test-run.png` — an `Invoke-AtomicTest` run in progress
- `phase5-rule-100500-firing.png` — the cross-segment block alert firing after the fix
- `phase5-retraction-regex-test.png` — the standalone Python regex check that caught the false HKCU finding
