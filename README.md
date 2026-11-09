# 🛡️ Corporate SOC Simulation — Nimbrek S.A.

![Status](https://img.shields.io/badge/status-SOC%20cycle%20complete-brightgreen)
![Windows Server](https://img.shields.io/badge/Windows%20Server-2022-0078D6?logo=windows&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active%20Directory-lab.local-0078D6)
![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.9.2-3BB1C2)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)

A corporate Windows domain built from scratch to practice the full SOC cycle — **build, monitor, attack, detect and respond** — against Active Directory, the identity backbone of most organizations and one of the first things an attacker goes after.

This is the second project in my Blue Team portfolio. It extends my [Home SOC Lab](https://github.com/ddiazcr/home-soc-lab), reusing the same Wazuh SIEM, Kali attacker and AI triage pipeline, and moves the scenario from a single vulnerable Linux host to an enterprise identity environment.

> **Fictional company:** Nimbrek S.A. · **Domain:** `lab.local` · **Environment:** isolated home lab (VirtualBox, Host-Only network)

---

## 🎯 What this project demonstrates

A full SOC cycle on an enterprise identity environment — **build → monitor → attack → detect → triage → harden** — with every claim backed by evidence in the repo, not slides.

- **6 Active Directory attack techniques** mapped to MITRE ATT&CK and caught with **custom Wazuh detection rules** — brute force, password spraying, Kerberoasting, domain account discovery, privileged-group change, and an accessibility-feature backdoor. All six are validated end-to-end, with the alert captured in `alerts.json`.
- **Portable detections** — every AD detection is also written as a vendor-neutral [Sigma rule](sigma/), so the same logic compiles to Splunk, Sentinel, Elastic or QRadar, not just Wazuh.
- **Honeytoken and decoy detections** — an RC4-only service account and a disabled user with a read SACL — that turn an attacker's own enumeration into a high-confidence, low-noise alert.
- **AI-assisted triage** — Wazuh alerts sent to Claude with schema-validated JSON output and human approval before any action: **10/10** on a labeled benchmark with benign look-alikes, **0 false positives**, and **2/2 prompt-injection attempts caught**, at ~4 s and ~$0.003 per alert.
- **Measured hardening** — a 14-check audit scored the domain, hardening was applied, and the re-measure went **50% → 93%** (7/14 → 13/14). Re-running the attack proved the point: the account now **locks** and the detection **still fires** — hardened without going blind.
- **Incident-driven** — real failures (a full-disk SIEM, a clock-skew blackout, a domain controller locked out and recovered via WinRE) are written up as blameless postmortems, each turned into a detection or a hardening item.

Jump to: [lab results](#-lab-results) · [MITRE mapping](docs/mitre_attack_mapping.md) · [AI triage](ai_triage/README.md) · [incident reports](docs/incident-reports.md) · [hardening results](#️-phase-5--hardening)

---

## 📊 Lab results

**Live run, 2026-11-08 — one execution.** A Kerberoasting attempt against the honeytoken on DC01, followed through the whole chain on a single clock (the screen recording):

![Timeline of the live run: 0 s Enter on DC01, 1.90 s alert in the triage feed, 8.27 s Telegram receives the verdict](docs/img/live-run-timeline.svg)

| Stage (start → end) | Value | Status |
|---|---|---|
| Enter on DC01 → alert `100212` in the triage feed | **1.90 s** | [✅ verified](docs/evidence/live-run-2026-11-08/) |
| Model analysis (API call → validated verdict) | **5.81 s** | [🟡 reported by the pipeline](docs/evidence/live-run-2026-11-08/t3-verdict-in-feed.jpg) |
| Enter on DC01 → Telegram receives the verdict | **8.27 s** | [✅ verified](docs/evidence/live-run-2026-11-08/) |

n = 1: observations of one run, not a benchmark. *Verified* means [`measure_events.py`](docs/evidence/live-run-2026-11-08/measure_events.py) recomputes the figure from the published, unedited recording; *reported* means the pipeline printed it. Telegram time is the desktop client.

<details>
<summary><b>Evidence chain for this run</b></summary>

| Stage | Evidence | Status |
|---|---|---|
| Original Windows event 4769 (anonymized) | — | ⏳ Pending export |
| Wazuh alert `100212` | [alert line in the feed](docs/evidence/live-run-2026-11-08/t1-alert-in-feed.jpg) | 🟡 Partial (full JSON pending) |
| Model verdict | [feed](docs/evidence/live-run-2026-11-08/t3-verdict-in-feed.jpg) · [Telegram: `critical`, T1558.003, summary](docs/evidence/live-run-2026-11-08/telegram-notification.jpg) | ✅ As displayed |
| Decision after policy | Tripwire floor not active in this run; the model's `critical` is already above it | n/a |
| Notification | [Telegram message](docs/evidence/live-run-2026-11-08/telegram-notification.jpg) | ✅ |
| Human decision | Not captured (the recording ends at the approval prompt) | ⏳ Pending |

</details>

<details>
<summary><b>Scenario baseline — what to compare future runs against</b></summary>

| Scenario | Expected | Observed | Runs | Evidence |
|---|---|---|---|---|
| Kerberoasting on the honeytoken, from DC01 (`100212`) | Alert; `high`/`critical`; escalate | Alert in 1.90 s; `critical` / `escalate_tier2` | 1 live | [live run](docs/evidence/live-run-2026-11-08/) |
| Read of the decoy account (`100230`) | Alert; `high`; escalate | `medium`/`manual_review` and `high`/`escalate_tier2` on two reads of the same decoy, which motivated the tripwire priority floor | 2 replayed (2026-11-07) | Reported · [PR #4](https://github.com/ddiazcr/corporate-soc-simulation/pull/4) |
| Privileged-group change (`100220`) | Alert; `critical` unless it is an approved change | `critical` / `escalate_tier2` | 1 replayed (2026-11-07) | Reported |
| Benign look-alike (a legitimate service ticket, a routine admin read) | No tripwire alert, or `low`/`medium` without escalation | — | ⏳ Not run live | Offline benchmark only ([AI triage](ai_triage/README.md)) |
| Kerberoasting from the network (Kali) | Alert `100212` | No alert: known detection gap | ⏳ Open | [MITRE mapping](docs/mitre_attack_mapping.md) |
| Model unavailable during a tripwire alert | Still `high` + priority human review | Unit tests only | ⏳ Not run live | [PR #4](https://github.com/ddiazcr/corporate-soc-simulation/pull/4) |

Once a scenario has three or more comparable runs, this table will report the number of runs with the median and range per stage, and comparative charts will be added then.

</details>

---

## 📍 Project status

| Phase | Scope | Status |
|---|---|---|
| **1 — Infrastructure** | Domain controller, `lab.local` forest, Nimbrek S.A. structure | ✅ Complete |
| **2 — Visibility** | Wazuh agent on the DC, advanced audit policies, 4625 events reaching the SIEM | ✅ Complete |
| **3 — Attack & detection** | Attacks mapped to MITRE ATT&CK, custom detections, honeytoken | ✅ 6 of 6 techniques validated end-to-end (brute force, spraying, Kerberoasting, account discovery, privileged-group change, accessibility backdoor) |
| **4 — AI-assisted triage** | Wazuh alerts → Claude with schema-validated JSON output, human approval before any action, prompt-injection defenses, measured accuracy and cost | ✅ Real mode — 10/10 on a labeled attack/benign benchmark, 0 false positives, injections 2/2 ([details](ai_triage/README.md)) |
| **5 — Hardening** | AD security audit with before/after measurement | ✅ Hardened: audit score **7/14 → 13/14**; spraying re-run now locks the account ([results](#️-phase-5--hardening)) |

---

## 🗺️ Architecture

```mermaid
flowchart LR
    subgraph HOST["Host · Windows 11 Pro · VirtualBox 7.2.12"]
        subgraph NET["Host-Only network · 192.168.56.0/24"]
            DC01["DC01<br/>Windows Server 2022<br/>AD DS + DNS<br/>192.168.56.10"]
            WAZUH["Wazuh Server 4.9.2<br/>Manager · Indexer · Dashboard<br/>+ Suricata<br/>192.168.56.102"]
            KALI["Kali Linux<br/>Attacker<br/>192.168.56.103"]
        end
    end
    DC01 -- "Wazuh agent (1514/TCP) ✅" --> WAZUH
    KALI -. "Simulated attacks (Phase 3)" .-> DC01
```

| Component | Details |
|---|---|
| Operating system | Windows Server 2022 Standard Evaluation (Desktop Experience) |
| Resources | 2 vCPU · 4 GB RAM · 60 GB dynamic VDI disk |
| Network | Host-Only `192.168.56.10/24`, DNS pointing to itself |
| Domain | `lab.local` · NetBIOS `LAB` · Windows Server 2016 functional level |
| Roles | Active Directory Domain Services, DNS |
| Monitoring | Wazuh agent 4.9.2 → manager `192.168.56.102` |

---

## ⚙️ Phase 1 — Infrastructure

### 1. Base server configuration

Hostname, static IP and local DNS were set before installing any roles.

```powershell
Rename-Computer -NewName "DC01" -Restart

New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
```

### 2. AD DS installation and promotion to domain controller

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Install-ADDSForest `
    -DomainName "lab.local" `
    -DomainNetbiosName "LAB" `
    -DomainMode "WinThreshold" `
    -ForestMode "WinThreshold" `
    -InstallDns
```

### 3. Nimbrek S.A. organizational structure

Created with PowerShell so the environment is **reproducible**:

| Type | Items |
|---|---|
| Organizational units | IT (`TI`) · Sales (`Ventas`) · HR (`RRHH`) · Finance (`Finanzas`) · `Servidores` · `Estaciones` |
| Security groups | `GG_TI` · `GG_Ventas` · `GG_RRHH` · `GG_Finanzas` |
| Test users | 7 accounts distributed across departments |

> 🔐 Lab credentials are never published in this repository.

### 4. Validation

```powershell
dcdiag /v
Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode
Get-ADOrganizationalUnit -Filter * | Select-Object Name
```

`dcdiag` passes every test except **SystemLog**, an expected and harmless failure: the Host-Only network has no internet access, so Windows logs DNS timeouts when trying to reach Microsoft's activation endpoints.

---

## 📡 Phase 2 — Visibility ✅

The Wazuh agent was deployed **offline**: the domain controller has no internet access, so the MSI was downloaded on the host and delivered through a read-only VirtualBox shared folder.

```powershell
Start-Process msiexec.exe -ArgumentList '/i','C:\Temp\wazuh-agent-4.9.2-1.msi','/q',
    'WAZUH_MANAGER=192.168.56.102','WAZUH_AGENT_NAME=DC01',
    'WAZUH_REGISTRATION_SERVER=192.168.56.102' -Wait
Start-Service WazuhSvc
```

Enrollment was verified from the manager:

```text
$ sudo /var/ossec/bin/agent_control -l
   ID: 000, Name: wazuh-server (server), IP: 127.0.0.1, Active/Local
   ID: 004, Name: DC01, IP: any, Active
```

![DC01 agent active](docs/img/18-agent-dc01-active.jpg)
*DC01 agent reporting to the Wazuh manager as `Active`*

**Advanced audit policy** is applied with [`scripts/Enable-AuditPolicies.ps1`](scripts/Enable-AuditPolicies.ps1),
which turns on Success+Failure auditing for the subcategories that feed the
Phase 3 detections (logon, Kerberos AS/TGS, account and group management,
directory service access) and enlarges the Security event log. Local
`auditpol` alone is **not durable** on a domain controller: a Group Policy
refresh reverts it, which silenced every detection once (see
[incident reports](docs/incident-reports.md)). The same subcategories are
therefore **enforced through the Default Domain Controllers Policy** (Advanced
Audit Policy Configuration), and the script is kept for verification and for
standalone hosts.

**End-to-end validation (done).** Failed authentications generated against the
DC produced event **4625** (logon type 3), which the agent forwarded to the
manager. The events were confirmed directly in `alerts.json`:

```bash
$ grep -c 4625 /var/ossec/logs/alerts/alerts.json
22
```

![4625 events in alerts.json](docs/img/19-alerts-4625-rule-60122.jpg)
*Event 4625 reaching the SIEM and matched by the built-in Windows ruleset*

With the Windows pipeline confirmed end-to-end, the lab moves into Phase 3.

---

## 🔧 Troubleshooting: what didn't work the first time

Two real incidents happened while building this lab. I'm documenting them because solving them taught me more than anything that worked on the first try.

### Incident 1 — The first domain controller couldn't be saved

| Problem | Diagnosis | Resolution |
|---|---|---|
| Update **KB5122882** hung for hours on "Working on updates" and then rolled back | The host has **Hyper-V/VBS enabled at firmware level**, so VirtualBox runs on top of the Windows hypervisor with much lower disk I/O | Mitigate instead of remove: 2 vCPU, frequent snapshots, *headless* mode |
| `Install-WindowsFeature AD-Domain-Services` failed with **0x800f0827** | Servicing stack left in an inconsistent state by the half-applied update (`CBS_E_STACK_SHUTDOWN_REQUIRED` in `CBS.log`) | Repairing the VM was ruled out |
| The VM froze on reboot | System state not recoverable at a reasonable cost | **Clean rebuild (DC01-v2)**, keeping the original VM as evidence before deleting it |

**Deliberate decision:** Windows Update stays disabled in this isolated, offline lab to ensure stability. In production this would be unacceptable — a domain controller must be kept up to date.

### Incident 2 — The SIEM went silent

After deploying the agent, the DC could not reach the manager on ports 1514/1515.

| Step | Finding |
|---|---|
| Network check from DC01 | ARP resolved the host, but nothing answered at `192.168.56.102` |
| Manager status | `wazuh-manager` **failed**: *"No space left on device"* |
| Disk usage | Root filesystem at **100%**; `/var/ossec/queue/vd_updater/tmp` held **12 GB** of vulnerability-feed temporary files |
| Cleanup | Temporary files removed → disk at **55%** (11 GB free) |
| Second failure | Manager start killed by **systemd timeout** on slow I/O |
| Fix | Drop-in override `TimeoutStartSec=600` for `wazuh-manager.service` → service active, listening on 1514/1515 |

**Lessons learned**

- Knowing when to stop repairing and rebuild from a known-good state is an operational skill. Per-phase snapshots made the rebuild fast and safe.
- "The agent can't connect" is not always a network problem — check the service on the other end first.
- Monitoring the monitoring stack matters: a SIEM with a full disk fails silently.

### Incident 3 — The agent that would not connect

Before the first detection, the DC agent sat at **"Never connected"** for hours
even though enrollment had succeeded. The fix only came after ruling causes out
in order:

| Hypothesis | Check | Verdict |
|---|---|---|
| Key mismatch between agent and manager | Compared `client.keys` on both sides | Identical — not the cause |
| Clock skew breaking message validation | `timedatectl` on the manager | Real (manager was ~15 h behind); fixed, but not the cause |
| Manager not listening | `ss -tlnp` → `wazuh-remoted` on `0.0.0.0:1514` | Listening — not the cause |
| **Stale daemon holding the port** | A failed restart left an **old `wazuh-remoted` process bound to 1514** (`Address already in use`) | **Root cause** |

The agent had been talking to a **zombie `remoted`** that still held port 1514
but no longer had the current keys, so every connection was silently dropped.
Killing the stale processes (`pkill -9 -f /var/ossec`) and starting the manager
clean fixed it immediately — the agent registered as `Active` within seconds.

**Lessons learned**

- "Never connected" is rarely one thing. Rule causes out methodically.
- A zombie process can impersonate a healthy service. Always confirm **which PID
  owns the port**, not just that *something* is listening.
- On a slow single-vCPU VM, `systemctl restart` can start the new daemon before
  the old one released its socket. A clean `stop → kill stragglers → start` is
  more reliable than a plain restart.

---

## 📸 Evidence

| | |
|---|---|
| ![Hostname](docs/img/11-hostname.png) | ![Static IP](docs/img/12-static-ip.png) |
| *DC01 hostname and Windows Update disabled* | *Static IP and local DNS* |
| ![AD DS installed](docs/img/13-adds-installed.png) | ![Domain](docs/img/14-domain-lab-local.png) |
| *AD DS role installed* | *Forest `lab.local` created* |
| ![dcdiag](docs/img/15-dcdiag.png) | ![Nimbrek structure](docs/img/16-nimbrek-structure.png) |
| *`dcdiag` validation* | *Nimbrek S.A. OUs, groups and users* |

![Wazuh agent active](docs/img/17-wazuh-agent-active.png)
*DC01 enrolled and active in the Wazuh manager*

<details>
<summary>🔧 Troubleshooting evidence</summary>

![VM configuration](docs/img/01-vm-config.png)
*Original VM configuration*

![Error 0x800f0827](docs/img/02-error-0x800f0827.png)
*AD DS installation failing with 0x800f0827*

![CBS log](docs/img/03-cbs-log-diagnosis.png)
*Root cause in `CBS.log`: `CBS_E_STACK_SHUTDOWN_REQUIRED`*

![Recovery snapshots](docs/img/04-recovery-snapshots.png)
*Recovery attempts on the original VM*

![Rebuild](docs/img/05-rebuild-dc01-v2.png)
*Original VM powered off, DC01-v2 in service*

</details>

---

## 🚀 Phase 3 — Attack & detection

| Technique | MITRE ATT&CK | Key Windows event | Status |
|---|---|---|---|
| Brute force | T1110.001 | 4625 | ✅ detected live |
| Password spraying | T1110.003 | 4625 / 4771 | ✅ detected live |
| Kerberoasting | T1558.003 | 4769 (RC4 encryption `0x17`) | ✅ validated (100210 burst logic, 100212 honeytoken single request, level 12) · also seen on the wire by Suricata (86601) |
| Domain account discovery | T1087.002 | 4662 (decoy object with a read SACL) | ✅ validated live from Kali (100230, level 12) |
| Privileged group changes | T1098 | 4728 / 4732 / 4756 | ✅ detected live |
| Accessibility-feature backdoor (sethc / utilman) | T1546.008 | FIM 550/554 on System32 helpers | ✅ validated (100240, level 13) — arose from the DC [recovery incident](docs/incident-reports.md); three FIM config pitfalls documented in the [mapping](docs/mitre_attack_mapping.md) |

Full technique-by-technique breakdown with detection logic and evidence:
[`docs/mitre_attack_mapping.md`](docs/mitre_attack_mapping.md).

Portable [Sigma](sigma/) versions of each rule are kept in [`sigma/`](sigma/).

### First live detection — Brute force (T1110.001)

Ten failed SMB authentications were generated from the DC against itself
(`net use \\192.168.56.10\ipc$` with wrong credentials). Each produced event
4625; the agent forwarded them; the manager correlated them and raised a
**brute-force alert mapped to MITRE ATT&CK T1110**, captured in `alerts.json`.

![Brute-force alert in alerts.json](docs/img/20-alert-60204-bruteforce.jpg)
*Alert 60204 "Multiple Windows Logon Failures" → T1110 (Credential Access / Brute Force)*

Deliverables:

- [x] Advanced audit policy script ([`scripts/Enable-AuditPolicies.ps1`](scripts/Enable-AuditPolicies.ps1))
- [x] Custom Wazuh rules for brute force, password spraying (NTLM and Kerberos), Kerberoasting and privileged group changes ([`rules/local_rules.xml`](rules/local_rules.xml)), aligned with the Wazuh 4.9.2 ruleset
- [x] End-to-end validation: brute force (T1110.001) fired by a real attack, alert captured from `alerts.json`
- [x] End-to-end validation: password spraying (100201), Kerberoasting (100210) and privileged-group changes (100220) each fired by a real attack and captured in `alerts.json`
- [x] Honeytoken service account (`svc_sql_backup`, RC4-only SPN `MSSQLSvc/db01.lab.local:1433`) used to trigger the Kerberoasting detection
- [x] Incident report per attack (timeline, IOCs, response, hardening) — [`docs/incident-reports.md`](docs/incident-reports.md)
- [x] Discovery decoy: disabled account `adm_backup_legacy` with a Read-Property SACL ([`scripts/Setup-DiscoveryDecoy.ps1`](scripts/Setup-DiscoveryDecoy.ps1)) + rule 100230
- [x] End-to-end validation of 100230 (LDAP enumeration from Kali) and 100212 (honeytoken ticket request)

---

## 🤖 Phase 4 — AI-assisted triage (in progress)

This phase evolves the [Home SOC Lab AI pipeline](https://github.com/ddiazcr/home-soc-lab/tree/main/AI) into a triage assistant for Active Directory alerts. The design goal is an assistant the analyst controls, not an autonomous responder.

```
Wazuh alert (level ≥ 10)
   → Wazuh custom integration (Python)
   → Claude API: schema-validated JSON
        { verdict, confidence, mitre_id, summary, suggested_action }
   → Telegram/Discord card with [Approve] [False positive]
   → analyst decision logged; nothing executes without approval
```

Design decisions:

| Decision | Why |
|---|---|
| **Only alerts go to the model, never raw logs** | The SIEM filters and correlates; the model assists on dozens of alerts a day, not thousands of events per second. Keeps cost and latency realistic. |
| **Structured output validated against a schema** | Free text cannot be measured or automated safely. Invalid JSON is rejected and the alert falls back to normal handling. |
| **The model suggests, the analyst decides** | Log fields (usernames, command lines) are attacker-controlled, so model output is untrusted input. Containment of a domain controller would break authentication for the whole company and is never automated. |
| **Prompt-injection defenses** | Alert data is passed as delimited data, never as instructions; the allowed `suggested_action` values are a fixed list; the model has no credentials and no tools that change the environment. |
| **Single model call before multi-agent** | Multiple agents multiply cost and failure points. The pipeline will be split only if measurements show a need. |
| **Prompt caching for static context** | The static instructions are marked for caching. In the first measured run the prompt was still below the model's minimum cacheable length, so no discount applied yet; it will matter once playbooks and MITRE context are added. |

Deliverables:

- [x] Triage of level ≥ 10 alerts (currently fed from a file of the validated Phase 3 alerts)
- [ ] Live Wazuh custom integration feeding alerts as they fire
- [x] JSON schema for the triage verdict, with validation and fallback
- [x] Human-approval gate with decision log + Telegram notification
- [x] Prompt-injection test cases using malicious values in log fields — both flagged, kept at critical
- [x] Latency and cost per alert (~4 s, ~$0.003 with Claude Haiku 4.5)
- [x] Accuracy on a labeled benchmark with benign look-alikes: 10/10, 0 false positives, 0 false negatives, injections 2/2 ([details](ai_triage/README.md))
- [ ] Remediation scripts generated by the model for human review, never auto-executed

---

## 🛡️ Phase 5 — Hardening

**Result (2026-11-03): 7/14 → 13/14 checks passed (50% → 93%).**
Raw output: [`docs/evidence/phase5-audit-before-after.txt`](docs/evidence/phase5-audit-before-after.txt).

| Check | Mitigates | Before | After | Change |
|---|---|---|---|---|
| P1 Account lockout threshold | T1110 brute force / spraying | ❌ 0 (never) | ✅ 5 attempts / 15 min | H1 |
| P2 Minimum password length ≥ 12 | T1110 / offline cracking | ❌ 7 | ✅ 12 | H1 |
| P3 Password complexity | T1110 | ✅ | ✅ | — |
| K1 No Kerberoastable account allows RC4 | T1558.003 | ✅ (honeytoken excepted) | ✅ | — |
| K2 No AS-REP roastable account | T1558.004 | ✅ | ✅ | — |
| K3 krbtgt changed in last 180 days | T1558.001 golden ticket | ✅ 24 days | ✅ | — |
| A1 Domain Admins ≤ 2 members | T1098 / blast radius | ✅ | ✅ | — |
| A2 Domain Admins in Protected Users | T1550 / credential theft | ❌ | ❌ | manual, by design |
| A3 Guest disabled | T1078 | ✅ | ✅ | — |
| A4 MachineAccountQuota = 0 | T1136 / RBCD abuse | ❌ 10 | ✅ 0 | H5 |
| N1 NTLMv1 / LM refused | T1557 relay / downgrade | ❌ not set | ✅ 5 | H6 |
| N2 LDAP signing required | T1557 LDAP relay | ❌ 1 | ✅ 2 | H7 |
| N3 SMB signing required | T1557 SMB relay | ✅ | ✅ | — |
| N4 Print Spooler disabled on DC | T1187 coercion (PrinterBug) | ❌ running | ✅ disabled | H9 |

**Why A2 is still failing.** Adding the only Domain Admin to *Protected Users*
blocks NTLM, RC4 and delegation for that account. Done without first proving
it can log on with Kerberos alone, it can lock the last administrator out of
the domain — exactly the failure this lab already lived through (see the
[DC recovery incident](docs/incident-reports.md)). It stays a planned manual
change, along with the krbtgt double reset.

**Bug caught during the run.** The first *before* run reported A1 as FAIL with
a single Domain Admin: a one-member result from `Get-ADGroupMember` is a lone
object whose `.Count` is not 1. Wrapping it in `@()` fixed it, and the
baseline was re-taken with the corrected script before applying anything.

**Safety net.** A VirtualBox snapshot (`pre-hardening`) of DC01 was taken
before `-Apply`.

**Attack re-run (the point of the exercise).** The password spray was repeated
after hardening. Rule **100201** fired again — the detection still works — and
this time the targeted account (`crojas`) reached `badPwdCount = 5` and
`LockedOut = True`. Before hardening the lockout threshold was `0`, so the same
spray ran unchecked. The hardening does not blind the SIEM; it **detects and
stops** the attack. A side effect worth noting: with SMB signing now enforced,
some spray attempts fail at negotiation before they count, so it took a couple
of passes to cross the threshold — hardening quietly raising the cost of the
attack.

### How it was run

Measure, harden, measure again, then re-run the Phase 3 attacks to see what
changed — including what the detections stop seeing.

1. `Invoke-ADAudit.ps1 -Label before` — read-only, 14 checks (lockout, password length, RC4 on SPN accounts, AS-REP roasting, krbtgt age, Domain Admins size, Protected Users, Guest, MachineAccountQuota, NTLMv1, LDAP signing, SMB signing, Print Spooler), each mapped to the technique it mitigates; saves JSON.
2. `Invoke-ADHardening.ps1` — dry run by default; `-Apply` to change. Domain Admins membership, Protected Users and the krbtgt reset are reported only, never automated.
3. `Invoke-ADAudit.ps1 -Label after`, then repeat the attacks.

Design exception: the honeytoken `svc_sql_backup` keeps RC4 on purpose — it is the bait that makes Kerberoasting visible.

---

## 🔭 Future projects

Kept out of this lab on purpose, to keep it focused and within the resources of a single laptop:

- **Lightweight SOAR with case management** — TheHive (and MISP for threat intelligence) receiving alerts, with human-approved response actions.
- **AI-assisted detection engineering** — generating Sigma rules with Claude and validating each one against real attacks before accepting it.

---

## 🧰 Tech stack

`Windows Server 2022` · `Active Directory` · `DNS` · `PowerShell` · `Group Policy` · `Wazuh` · `Suricata` · `Kali Linux` · `VirtualBox` · `MITRE ATT&CK` · `Python` · `Claude API`

---

## 👤 Author

**Daniel Díaz** — Advanced Cybersecurity Technician focused on Blue Team / SOC · Costa Rica
[LinkedIn](https://linkedin.com/in/danieldiazcr) · [GitHub](https://github.com/ddiazcr)

*This project is for educational purposes only, built entirely within an isolated home lab environment.*
