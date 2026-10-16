# MITRE ATT&CK Mapping — Nimbrek S.A. (Active Directory)

This document maps each simulated attack in the lab to its MITRE ATT&CK
technique, the Windows event that evidences it, and the custom Wazuh rule
that detects it. All detections are validated against the Wazuh manager's
`alerts.json`; the dashboard is a secondary view of the same data.

Status legend: ✅ validated = the rule has fired against a real attack and the
alert is captured in `alerts.json`; ⏳ pending = rule written, not yet
validated end-to-end.

| Tactic | Technique | ID | Windows event | Wazuh rule | Status |
|---|---|---|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 | 4625 | 100200 (level 12) → built-in 60204 | ✅ validated |
| Credential Access | Brute Force: Password Spraying | T1110.003 | 4625 / 4771 | 100201 (level 12) | ⏳ pending |
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | 4769 (RC4 `0x17`) | 100210 / 100211 (level 12) | ⏳ pending |
| Discovery | Account Discovery: Domain Account | T1087.002 | 4662 | built-in 60176+ | ⏳ pending |
| Persistence / Priv. Esc. | Account Manipulation | T1098 | 4728 / 4732 / 4756 | 100220 (level 12) | ⏳ pending |

## Detection logic

### T1110.001 — Brute force (rule 100200) — ✅ validated
A single source IP producing **multiple failed logons (event 4625) in a short
window** is flagged. This catches an attacker hammering one or a few accounts
with a password list. Wazuh's built-in rule **60204 — "Multiple Windows Logon
Failures"** already correlates the raw `4625 → 60122` events; the custom rule
**100200** chains off 60204 (`if_sid`) to raise the level to 12 and attach the
Nimbrek context and the precise sub-technique **T1110.001**.

**Validated 2026-10-14:** 10 failed SMB authentications generated from the DC
(`net use \\192.168.56.10\ipc$` with wrong credentials) produced event 4625
(logon type 3) on the domain controller, forwarded by the Wazuh agent, and
fired alert **60204 (level 10)** — captured in `alerts.json`. See
[`docs/img/20-alert-60204-bruteforce.jpg`](img/20-alert-60204-bruteforce.jpg).

### T1110.003 — Password spraying (rule 100201)
Spraying is the inverse of brute force: **one or few passwords tried across
many accounts** to stay under per-account lockout thresholds. Rule 100201
fires when the **same source IP fails against 6+ different target accounts**
in 120 seconds (`same_field` source IP + `different_field` target user),
distinguishing spraying from single-account brute force.

### T1558.003 — Kerberoasting (rules 100210 / 100211)
An attacker requests Kerberos service tickets (event 4769) for accounts with
an SPN, then cracks them offline. The tell is the **RC4 encryption type
`0x17`**, which modern clients should not request. Rule 100210 flags each
weak-cipher ticket; rule 100211 escalates when 5+ occur from one source in
60 seconds (burst = enumeration of service accounts).

### T1098 — Privileged group manipulation (rule 100220)
Adding a member to a privileged group (Domain Admins, etc.) generates event
4728 / 4732 / 4756. Rule 100220 surfaces every such change at level 12 —
in a monitored domain these should be rare and always reviewed.

## Evidence

Each validated detection is captured directly from the manager:

```bash
# Confirm the custom rule fired, with its MITRE id
sudo jq 'select(.rule.id=="100200")
         | {time:.timestamp, rule:.rule.id, level:.rule.level,
            desc:.rule.description, mitre:.rule.mitre.id,
            srcip:.data.win.eventdata.ipAddress}' \
     /var/ossec/logs/alerts/alerts.json
```

Screenshots of the resulting alerts are stored in [`docs/img/`](img/).
