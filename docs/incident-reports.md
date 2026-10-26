# Incident Reports — Nimbrek S.A. (Active Directory lab)

These are analyst-style incident reports for the attacks simulated against the
Nimbrek S.A. lab and detected by the Wazuh SIEM. Every attack was run in an
isolated VirtualBox environment against a controlled domain controller; the
reports are written from the Blue Team / SOC analyst perspective to practice
the full cycle — **detect → triage → scope → respond → harden**.

## Environment

| Asset | Role | Address |
|---|---|---|
| DC01 (`02-dc-promovido.lab.local`) | Domain controller, `lab.local` forest | 192.168.56.10 |
| Wazuh server | SIEM manager + indexer + dashboard | 192.168.56.102 |
| Network | VirtualBox Host-Only | 192.168.56.0/24 |

Lab domain accounts referenced below: `crojas, mjimenez, lvargas, amora,
scastro, dherrera, lsoto` (plus `Administrator`, `krbtgt`, `Guest`).

## Incident summary

| ID | Date | Technique | MITRE | Windows event | Wazuh rule | Severity |
|---|---|---|---|---|---|---|
| INC-001 | 2026-10-19 | Brute force (password guessing) | T1110.001 | 4625 | 60122 → 100200 | Medium |
| INC-002 | 2026-10-16 | Password spraying | T1110.003 | 4625 | 100201 | High |
| INC-003 | 2026-10-17 | Kerberoasting | T1558.003 | 4769 (RC4 `0x17`) | 100210 | High |
| INC-004 | 2026-10-17 | Privileged-group manipulation | T1098 | 4728 | 100220 | Critical |

Severity reflects the potential impact of the technique in a production domain,
not the controlled lab blast radius.

---

## INC-001 — Brute force / password guessing (T1110.001)

**Summary.** A single source produced a burst of failed authentications against
the domain controller, consistent with an attacker trying a password list
against one or a few accounts.

**Timeline.**
- `2026-10-19` — 10 failed SMB authentications generated from **Kali
  (`192.168.56.103`)** against `crojas` on DC01 (`netexec smb` with wrong
  passwords). Each produced event **4625** (logon type 3, failure) carrying the
  real source IP.

**Detection.** Rule **100200** self-correlates off `60122` (the 4625
logon-failure rule): **8+ failures from the same `ipAddress` in 240 s**
(`if_matched_sid` 60122 + `same_field` ipAddress), at level 12, mapped to
**T1110.001**. Alert confirmed in `alerts.json` (rule 100200, level 12,
T1110.001, ip 192.168.56.103).

> **Root cause note.** The first version of 100200 chained off the built-in
> **60204** (`if_sid 60204`), which never fired for these events in this 4.9.2
> install even with a real source IP — 60204 uses `if_matched_group`, which did
> not group these 4625s here, while `if_matched_sid` (as rule 100201 uses) did.
> 100200 was rewritten to self-correlate off 60122. See
> [`mitre_attack_mapping.md`](mitre_attack_mapping.md) for the full analysis.

**IOCs (lab).** Repeated 4625 (logon type 3), same source, short time window;
target account(s) with many consecutive failures and no matching success.

**Impact.** None — controlled lab, no account compromised, lockout thresholds
not reached.

**Response.** Confirmed the burst came from a single source and was not a
legitimate service misconfiguration; documented the source and targeted
accounts; no containment needed in the lab.

**Hardening / recommendations.**
- Enforce account lockout policy (threshold + observation window) and smart
  lockout where available.
- Alert on *N* failed logons per source IP within a short window (covered by
  rule 100200: 8 failures / same IP / 240 s).
- Prefer phishing-resistant MFA for privileged and remote-accessible accounts.

**Follow-up.** Resolved — validated end-to-end from Kali on 2026-10-19 (see
Detection above).

---

## INC-002 — Password spraying (T1110.003)

**Summary.** One password was tried across many accounts — the inverse of brute
force — to stay under per-account lockout thresholds. This pattern commonly
precedes initial access in AD environments.

**Timeline.**
- `2026-10-16` — 7 failed SMB authentications from a single source against 7
  different lab accounts (`crojas, mjimenez, lvargas, amora, scastro,
  dherrera, lsoto`) with one wrong password. Each produced event **4625**
  (logon type 3).

**Detection.** Custom rule **100201** fires when the **same source IP fails
against 6+ different target accounts in 120 seconds** (`same_field` source IP +
`different_field` target user), at **level 13**. Confirmed in `alerts.json`:

```bash
sudo grep -hoE '100(200|201|202|203|210|211|220)' \
     /var/ossec/logs/alerts/alerts.json | sort | uniq -c
#       1 100201
```

**IOCs (lab).** Many distinct target accounts failing from one source in a
tight window; low failure count *per account* (evades lockout) but high
*breadth* across the directory.

**Impact.** None — no account authenticated successfully.

**Response.** Correlated the breadth-across-accounts pattern; verified no
success event followed for any sprayed account; documented source and account
list.

**Hardening / recommendations.**
- Detect on breadth (distinct targets per source), not just per-account
  failures — spraying hides below lockout thresholds.
- Ban weak/seasonal passwords and known-breached passwords.
- MFA on all externally reachable authentication surfaces.

---

## INC-003 — Kerberoasting (T1558.003)

**Summary.** An attacker requested a Kerberos service ticket for an account with
a Service Principal Name (SPN) and forced **RC4** encryption, which can be
cracked offline to recover the service account's password.

**Timeline.**
- `2026-10-17` — A honeytoken service account `svc_sql_backup` was created with
  **RC4-only** encryption (`-KerberosEncryptionType RC4`) and the SPN
  `MSSQLSvc/db01.lab.local:1433`.
- `2026-10-17 12:22` — A service ticket was requested from the DC
  (`klist get MSSQLSvc/db01.lab.local:1433`). The KDC issued the ticket with
  **`RSADSI RC4-HMAC(NT)`** — the `0x17` signature — generating event **4769**.

**Detection.** In Wazuh 4.9.2 a successful 4769 is classified by the generic
logon-success rule **60106**, so rule **100210** chains from it, pins event ID
4769 and matches the RC4 type **`0x17`**. Rule 100211 escalates on a burst of
RC4 tickets for 5+ services (enumeration). Alert for 100210 confirmed in
`alerts.json`.

**IOCs (lab).** 4769 with ticket encryption type `0x17` (RC4) where modern
clients would use AES; service tickets requested for SPN-bearing accounts,
especially several in a short burst.

**Impact.** None — the honeytoken has no real privileges; its only purpose is to
bait and surface this exact technique.

**Response.** Confirmed the RC4 ticket request against the honeytoken SPN;
because the honeytoken should never be legitimately used, any 4769 against it is
high-fidelity (near-zero false positives).

**Hardening / recommendations.**
- Set strong, long, randomly generated passwords on service accounts (or use
  gMSAs) so offline cracking is infeasible.
- Disable RC4 for Kerberos where possible; require AES.
- Keep honeytoken SPNs as tripwires — no legitimate traffic should ever touch
  them.

---

## INC-004 — Privileged-group manipulation (T1098)

**Summary.** A standard account was added to **Domain Admins**, granting full
domain control. Adding a member to a privileged group is one of the highest-
signal events in Active Directory.

**Timeline.**
- `2026-10-17` — `crojas` was added to **Domain Admins** and then removed
  (`Add-ADGroupMember 'Domain Admins' crojas` → `Remove-ADGroupMember ...`),
  generating event **4728** (member added to a security-enabled global group).

**Detection.** Wazuh ships level-12 rules for changes to Administrators (60154),
Domain Admins (60159), Schema Admins (60166) and Enterprise Admins (60167), but
they fire on additions *and* removals. Rule **100220** chains off those four
privileged-group rules and keeps **only additions**, at **level 13**. Alert
confirmed in `alerts.json`.

**IOCs (lab).** 4728/4732/4756 adding a member to a highly privileged group,
especially outside a change window or by an account that does not normally
manage group membership.

**Impact.** In the lab, none (immediately reverted). In production this is a
**critical** finding — Domain Admins membership is effectively full control of
the forest.

**Response.** Verified the addition and the actor; confirmed the membership was
removed; in production this would trigger immediate containment (disable the
added account, force credential reset, review all actions taken while the
membership was active).

**Hardening / recommendations.**
- Treat privileged-group additions as page-worthy alerts with a tight response
  SLA.
- Use tiered administration and Privileged Access Management (PAM) /
  just-in-time elevation instead of standing membership.
- Protect privileged groups with restricted delegation and regular membership
  attestation.

---

## Detection coverage status

| Technique | Rule | Status |
|---|---|---|
| T1110.001 Brute force | 60122 → 100200 | ✅ validated live (2026-10-19, from Kali) |
| T1110.003 Password spraying | 100201 | ✅ validated live |
| T1558.003 Kerberoasting | 100210 | ✅ validated live |
| T1098 Privileged-group | 100220 | ✅ validated live |

Full detection logic and evidence: [`mitre_attack_mapping.md`](mitre_attack_mapping.md).

## Operational incident — SIEM manager down (full disk)

On 2026-10-18 the Wazuh manager silently stopped: its root filesystem reached
**100 %**, driven by the vulnerability-detector feed cache
(`/var/ossec/queue/vd_updater/tmp` held 12 GB of downloads that never complete
offline). With the manager down, alert rotation failed and the alert files for
**2026-10-17 and 2026-10-18 were left at 0 bytes**, so the on-disk evidence for
the Kerberoasting (100210) and privileged-group (100220) detections validated
on 2026-10-17 was lost. The rules themselves were unaffected.

**Resolution (2026-10-19).** Cleared the feed cache, restarted the manager
clean, and **disabled the vulnerability detector** in `ossec.conf` (it cannot
update in an offline host-only lab and was the root cause here, as in the
Phase 2 disk incident). Brute force (100200) was then validated from Kali, and Kerberoasting (100210)
and privileged-group (100220) were re-run and re-validated the same day,
regenerating their evidence on the healthy manager.

**Lesson.** Monitor the monitoring stack. A SIEM that stops ingesting fails
silently — you believe you have coverage while blind. Disk and service health
of the manager deserve their own alerting.
