# Sysmon setup for DC01 and domain workstations

Sysmon gives process-level visibility (process creation with command line,
network connections, image loads) that the Security log alone does not. It is
the single biggest detection upgrade for this lab: without it there is no
reliable way to see lateral movement, tooling execution, or the LSASS access
that precedes credential theft.

## 1. Install

Use the helper script (downloads Sysmon and a vetted config, installs, and
confirms the service):

```powershell
# Run on DC01 and on each domain workstation, as Administrator
.\scripts\Install-Sysmon.ps1
```

Or manually:

```powershell
# Sysinternals Sysmon + SwiftOnSecurity base config
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon
Invoke-WebRequest `
  https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml `
  -OutFile C:\Sysmon\sysmonconfig.xml
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

> **Config choice.** SwiftOnSecurity's config is the standard starting point.
> For heavier DNS/network coverage, Olaf Hartong's `sysmon-modular` is the
> other common choice. Pin whichever you use in the repo so the detection is
> reproducible.

Verify:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

## 2. Ship Sysmon to Wazuh

The Wazuh agent must forward the Sysmon channel. Add this inside
`<ossec_config>` in the agent's `ossec.conf` (`C:\Program Files
(x86)\ossec-agent\ossec.conf`) and restart the agent:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

```powershell
Restart-Service WazuhSvc
```

Wazuh 4.9.2 ships Sysmon decoders and the `0595-win-sysmon_rules.xml`
ruleset, so events are parsed and classified out of the box.

## 3. Events worth detecting

| Sysmon ID | Meaning | Why it matters |
|---|---|---|
| 1 | Process creation (with command line) | Tooling, LOLBins, encoded PowerShell |
| 3 | Network connection | C2 beacons, lateral movement |
| 7 | Image loaded | Unsigned DLLs, injection |
| 8 | CreateRemoteThread | Process injection |
| 10 | ProcessAccess | **LSASS access** (credential dumping) |
| 11 | File created | Dropped payloads |
| 22 | DNS query | C2 domains, enumeration |

A natural next custom rule is Sysmon **event 10 targeting `lsass.exe`** from a
non-system process — the tell for credential dumping (T1003.001).

## 4. What you run in the lab

- Install Sysmon on DC01 and the workstation (playbook/script above).
- Confirm Sysmon events reach the manager (`rule.groups` contains `sysmon`).
- Capture one process-creation and one LSASS-access event for the report.
