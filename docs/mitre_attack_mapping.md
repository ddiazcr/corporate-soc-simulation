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
| Credential Access | Brute Force: Password Guessing | T1110.001 | 4625 | 60122 → 100200 (level 12) | ✅ validated (100200) |
| Credential Access | Brute Force: Password Spraying | T1110.003 | 4625 / 4771 | 100201 (NTLM) / 100202 → 100203 (Kerberos), level 13 | ✅ validated (100201, NTLM) |
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | 4769 (RC4 `0x17`) | 100210 (level 8) → 100211 (level 12) | ✅ validated (100210) |
| Discovery | Account Discovery: Domain Account | T1087.002 | 4662 | not written yet (needs SACLs on AD objects) | ⏳ pending |
| Persistence / Priv. Esc. | Account Manipulation | T1098 | 4728 / 4732 / 4756 | 100220 (level 13) | ✅ validated (100220) |

## Detection logic

### T1110.001 — Brute force (rule 100200) — ✅ validated
A single source IP producing **multiple failed logons (event 4625) in a short
window** is flagged. This catches an attacker hammering one or a few accounts
with a password list. Rule **100200** self-correlates off `60122` (the
`4625` logon-failure rule): **8+ failures from the same `ipAddress` in 240 s**
(`if_matched_sid` 60122 + `same_field` ipAddress), at level 12. This is the
same proven pattern as rule 100201.

**Validated 2026-10-19:** 10 failed SMB authentications were generated from
**Kali (`192.168.56.103`)** against `crojas` on the DC (`netexec smb` with
wrong passwords). Each produced event **4625** (logon type 3) carrying the real
source IP `192.168.56.103`; the agent forwarded them and the manager fired
rule **100200 (T1110.001, level 12)** — confirmed in `alerts.json`:

```bash
grep '"id":"100200"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq \
  '{rule:.rule.id, level:.rule.level, mitre:.rule.mitre.id,
    ip:.data.win.eventdata.ipAddress}'
# { "rule": "100200", "level": 12, "mitre": ["T1110.001"], "ip": "192.168.56.103" }
```

**Root cause of the earlier failure (documented for the record).** The first
version chained off the built-in **60204** (`if_sid 60204`). In this 4.9.2
install 60204 never fired for these events, even once the source IP was real
and populated: 60204 correlates with `<if_matched_group>authentication_failed</if_matched_group>`,
which did not group these 4625 events here, whereas rule 100201 — using
`<if_matched_sid>60122</if_matched_sid>` — correlated reliably. 100200 was
therefore rewritten to self-correlate off 60122, matching the working pattern.
A second factor delayed detection: the only 60204 that ever fired was on
2026-10-14, two days before 100200 was deployed to the manager (2026-10-16),
and the manager was later down with a full disk (see incident reports), so no
brute-force test reached a working manager until the 2026-10-19 Kali run.

### T1110.003 — Password spraying (rules 100201, 100202, 100203)
Spraying is the inverse of brute force: **one or few passwords tried across
many accounts** to stay under per-account lockout thresholds. It can arrive
over two protocols, so there are two detections:

- **NTLM / SMB (4625):** rule 100201 fires when the **same source IP fails
  against 6+ different target accounts** in 120 seconds (`same_field`
  source IP + `different_field` target user).
- **Kerberos (4771):** Wazuh 4.9.2 has no dedicated rule for 4771 (it only
  reaches the generic audit-failure rule 60104), so rule 100202 classifies it
  and rule 100203 applies the same 6-accounts-in-120-seconds logic. This is
  the path tools like `kerbrute` produce.

Both spraying rules are level 13 so they outrank 100200 when a large spray
also trips the built-in 8-failures-per-IP threshold of 60204.

**Validated 2026-10-16 (NTLM path):** seven failed SMB authentications were
generated from the domain controller against seven different lab accounts
(`crojas, mjimenez, lvargas, amora, scastro, dherrera, lsoto`) with a wrong
password, from a single source IP. Each produced event 4625 (logon type 3);
the agent forwarded them and the manager fired **rule 100201 (T1110.003,
level 13)** — confirmed in `alerts.json`:

```bash
sudo grep -hoE '100(200|201|202|203|210|211|220)' \
     /var/ossec/logs/alerts/alerts.json | sort | uniq -c
#       1 100201   # password spraying  (T1110.003)
#       1 100210   # Kerberoasting      (T1558.003)
#       1 100220   # privileged group   (T1098)
```

### T1558.003 — Kerberoasting (rules 100210 / 100211)
An attacker requests Kerberos service tickets (event 4769) for accounts with
an SPN, then cracks them offline. The tell is the **RC4 encryption type
`0x17`**, which modern clients should not request. In Wazuh 4.9.2 a
successful 4769 is classified by the generic logon-success rule **60106**, so
rule 100210 chains from it, pins event ID 4769 and matches `0x17`. Rule 100211
escalates when RC4 tickets for **5+ different services** come from one source
in 60 seconds (burst = enumeration of service accounts).

**Validated 2026-10-17:** a honeytoken service account `svc_sql_backup` was
created with RC4-only encryption (`-KerberosEncryptionType RC4`) and given the
SPN `MSSQLSvc/db01.lab.local:1433`. Requesting its service ticket from the DC
(`klist get MSSQLSvc/db01.lab.local:1433`) made the KDC issue the ticket with
`RSADSI RC4-HMAC(NT)` — the `0x17` signature. The resulting event 4769 was
forwarded by the agent and the manager fired **rule 100210 (T1558.003)** —
confirmed in `alerts.json` (see the evidence block above).

### T1098 — Privileged group manipulation (rule 100220)
Adding a member to a privileged group generates event 4728 / 4732 / 4756.
Wazuh already ships level-12 rules for changes to **Administrators (60154),
Domain Admins (60159), Schema Admins (60166) and Enterprise Admins (60167)**,
but they fire on additions and removals alike. Because built-in child rules
are evaluated first, a custom rule hanging from the generic "member added"
rules would never see these groups. Rule 100220 therefore chains off the four
privileged-group rules and keeps only **additions**, at level 13.

**Validated 2026-10-17:** adding a lab user to Domain Admins and removing it
(`Add-ADGroupMember 'Domain Admins' crojas` → `Remove-ADGroupMember ...`)
generated event 4728. The agent forwarded it and the manager fired **rule
100220 (T1098)** on the addition — confirmed in `alerts.json` (see the
evidence block above).

### T1087.002 — Domain account discovery
No custom rule yet. Event 4662 is only logged when the queried AD objects
carry a SACL; enabling the "Directory Service Access" audit subcategory alone
is not enough. Planned once the SACLs are in place.

## Testing rules before deploying

Every rule is checked with `wazuh-logtest` on the manager before restarting
it, by pasting a real event copied from `archives.json` or the DC's Event
Viewer:

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste the event JSON; phase 3 must show the expected rule id and level
```

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
