# Threat hunting & investigation queries — Nimbrek S.A.

Saved queries for reading the lab's events field by field, on the Wazuh
manager (`jq` over `alerts.json` / `archives.json`) and in the dashboard
Discover view (KQL). The point is to show *how* an analyst pivots, not just
that a rule fired.

> `alerts.json` holds events that matched a rule (level ≥ 3 by default).
> `archives.json` holds **every** decoded event and must be enabled
> (`<logall_json>yes</logall_json>` in `ossec.conf`) — useful to confirm an
> event arrived even when no rule fired.

## Validating a rule before deploy — `wazuh-logtest`

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste a real event copied from archives.json or Event Viewer (XML/JSON),
# then read:  **Phase 3: Completed filtering (rules)**  -> id and level
```

Run this for each custom rule (100200–100220) with a representative event and
save the Phase 3 output; it is the proof the rule works.

## Event 4625 — failed logon (brute force / spraying)

### Field breakdown (what to read, and why)

| Field | Where | Meaning |
|---|---|---|
| `LogonType` | `win.eventdata.logonType` | 3 = network (SMB/NTLM), 2 = interactive, 10 = RDP |
| `Status` / `SubStatus` | `win.eventdata.subStatus` | `0xC000006A` wrong password · `0xC0000064` user does not exist · `0xC0000072` disabled · `0xC0000234` locked out |
| `TargetUserName` | `win.eventdata.targetUserName` | account attacked |
| `IpAddress` | `win.eventdata.ipAddress` | **attacker source** |
| `WorkstationName` | `win.eventdata.workstationName` | attacker hostname (often spoofable) |

### jq

```bash
# All 4625 grouped by source IP and sub-status
sudo jq -r 'select(.data.win.system.eventID=="4625")
            | [.data.win.eventdata.ipAddress,
               .data.win.eventdata.targetUserName,
               .data.win.eventdata.subStatus] | @tsv' \
     /var/ossec/logs/archives/archives.json | sort | uniq -c | sort -rn

# Distinct accounts targeted per source IP (spraying signal)
sudo jq -r 'select(.data.win.system.eventID=="4625")
            | [.data.win.eventdata.ipAddress,
               .data.win.eventdata.targetUserName] | @tsv' \
     /var/ossec/logs/archives/archives.json | sort -u \
  | awk '{c[$1]++} END{for(i in c) print c[i], i}' | sort -rn
```

A single IP with **many distinct accounts** = spraying; a single IP with
**many tries on few accounts** = brute force.

### KQL (Discover)

```
data.win.system.eventID:"4625" and data.win.eventdata.ipAddress:"192.168.56.103"
```

## Event 4769 — Kerberos service ticket (Kerberoasting)

| Field | Meaning |
|---|---|
| `TicketEncryptionType` = `0x17` | **RC4** — the roasting tell (`0x12` = AES256, normal) |
| `ServiceName` | the SPN account targeted |
| `TicketOptions` | `0x40810000` typical for roasting tools |

```bash
# RC4 service tickets by requesting IP and service
sudo jq -r 'select(.data.win.system.eventID=="4769"
                   and .data.win.eventdata.ticketEncryptionType=="0x17")
            | [.data.win.eventdata.ipAddress,
               .data.win.eventdata.serviceName] | @tsv' \
     /var/ossec/logs/archives/archives.json | sort | uniq -c | sort -rn
```

```
data.win.system.eventID:"4769" and data.win.eventdata.ticketEncryptionType:"0x17"
```

## Event 4728/4732/4756 — privileged group additions

```bash
sudo jq -c 'select(.data.win.system.eventID=="4728"
                   or .data.win.system.eventID=="4732"
                   or .data.win.system.eventID=="4756")
            | {grp:.data.win.eventdata.targetUserName,
               member:.data.win.eventdata.memberName,
               by:.data.win.eventdata.subjectUserName,
               t:.timestamp}' \
     /var/ossec/logs/archives/archives.json
```

## Generic — what fired, ranked by severity

```bash
sudo jq -r 'select(.rule.groups[]? == "nimbrek")
            | [.rule.level, .rule.id, .rule.description] | @tsv' \
     /var/ossec/logs/alerts/alerts.json | sort -rn | head -20
```

## Baseline before hunting

Know what normal looks like so anomalies stand out:

```bash
# Logon types seen in the last run, by account
sudo jq -r 'select(.data.win.system.eventID=="4624")
            | [.data.win.eventdata.logonType,
               .data.win.eventdata.targetUserName] | @tsv' \
     /var/ossec/logs/archives/archives.json | sort | uniq -c | sort -rn
```
