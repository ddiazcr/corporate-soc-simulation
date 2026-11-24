# Incident Report — <Attack name> (<ID>)

> Template for Phase 3 incident reports. Copy this file to
> `docs/incidents/IR-<nn>-<slug>.md`, fill every section, and remove this
> quote block. Keep all timestamps in **UTC** and note the source timezone of
> any raw log. Anonymize real hostnames/usernames if the repo is public.

| | |
|---|---|
| Report ID | IR-<nn> |
| Date (UTC) | <YYYY-MM-DD> |
| Analyst | <name> |
| Severity | Low / Medium / High / Critical |
| Status | Open / Contained / Resolved |
| MITRE technique | T#### — <name> |

## 1. Summary

Two or three sentences a manager can read: what happened, what was affected,
what was done. No jargon.

## 2. Timeline (UTC)

| Time (UTC) | Event | Source |
|---|---|---|
| | Attack started (first 4625/4769/…) | DC01 Security log |
| | Wazuh alert fired (rule ####, level ##) | alerts.json |
| | Analyst triage began | — |
| | Containment action | — |
| | Resolved | — |

State explicitly if detection or response lagged the attack, and why.

## 3. Detection

- **Rule(s):** #### (level ##), MITRE T####.
- **Triggering event:** event ID ####, key fields (logon type, sub-status,
  source IP, target account / service).
- **Evidence:** `samples/<file>.json`, `docs/img/<screenshot>`.
- **`wazuh-logtest` proof** that the rule classifies the event (Phase 3
  output) if not already in the mapping doc.

## 4. Investigation

How you pivoted: the queries run (link `hunting-queries.md`), what you ruled
out, and how you scoped it (one account? many? which source?). Include the
field-by-field read of the key event.

## 5. Impact

What the attacker could achieve (accounts exposed, tickets crackable,
privilege gained). For Kerberoasting, include time-to-crack of the honeytoken.

## 6. Indicators of Compromise (IOCs)

| Type | Value | Notes |
|---|---|---|
| Source IP | 192.168.56.103 | Kali attacker |
| Account | | targeted / abused |
| SPN | | Kerberoasting |
| Tool | | netexec / kerbrute / Impacket |

## 7. Response & remediation

Containment (disable account, block IP via active response, reset password)
and the longer fix (lockout policy, AES-only Kerberos, tiering, remove
unnecessary SPNs).

## 8. Lessons learned / detection gaps

What the lab did not catch, and the next rule or log source that would close
the gap (e.g. Sysmon 10 for credential dumping, 4662 with SACLs for
discovery).

## 9. MITRE ATT&CK mapping

| Tactic | Technique | ID | Detected by |
|---|---|---|---|
| | | T#### | rule #### |
