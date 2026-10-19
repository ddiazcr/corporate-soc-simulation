# Adding a domain workstation (OU `Estaciones`)

The `Estaciones` OU is currently empty, so there are no user logons, no
lateral movement, and no endpoint telemetry to investigate. A single Windows
10/11 client joined to `lab.local` unlocks interactive logons (4624 type 2),
Pass-the-Hash and lateral-movement scenarios, and realistic Sysmon data.

## 1. Build the VM

- Windows 10/11, Host-Only adapter on the lab network (`192.168.56.0/24`).
- Static IP, e.g. `192.168.56.20`, DNS pointing at **DC01**
  (`192.168.56.10`) — joining fails if DNS does not resolve `lab.local`.

```powershell
# On the workstation, as local admin
Rename-Computer -NewName "WS01" -Restart
```

## 2. Join the domain

```powershell
Add-Computer -DomainName lab.local -OUPath "OU=Estaciones,DC=lab,DC=local" `
    -Credential (Get-Credential) -Restart
```

Verify after reboot:

```powershell
Test-ComputerSecureChannel -Verbose
whoami /fqdn
```

## 3. Onboard to Wazuh + Sysmon

- Install the Wazuh agent pointing at the manager (`192.168.56.102`) and
  register it (`agent-auth` or the dashboard).
- Install Sysmon with the same config as DC01
  ([`sysmon-setup.md`](sysmon-setup.md)).
- Confirm the agent is active:
  ```bash
  sudo /var/ossec/bin/agent_control -l
  ```

## 4. Enable the same audit policies

Run [`../scripts/Enable-AuditPolicies.ps1`](../scripts/Enable-AuditPolicies.ps1)
on the workstation (ideally push it by GPO from DC01 so it is reproducible and
documented as a GPO — the lab's stack lists GPOs but none are documented yet).

## 5. Scenarios this unlocks

- **Interactive / RDP logons** (4624 type 2 / 10) to baseline normal user
  activity.
- **Lateral movement** DC ↔ WS01 (4624 type 3, Sysmon 1/3) and
  Pass-the-Hash from Kali against WS01.
- **Local credential theft** — Sysmon 10 on `lsass.exe`.

## What you run in the lab

- Build WS01, join it to `lab.local`, confirm the secure channel.
- Onboard the Wazuh agent + Sysmon; confirm both report to the manager.
- Capture one interactive logon and one lateral-movement event for evidence.
