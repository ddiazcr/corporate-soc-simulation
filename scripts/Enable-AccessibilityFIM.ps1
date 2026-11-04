<#
.SYNOPSIS
    Puts the logon-screen accessibility helpers under Wazuh file integrity
    monitoring (FIM) so rule 100240 (T1546.008) can fire.

.DESCRIPTION
    Adds one <directories> entry PER FILE to the Wazuh agent's ossec.conf,
    inside <syscheck>, for sethc / utilman / osk / Magnify / Narrator /
    DisplaySwitch, then restarts the agent.

    Two details make this work (both found during validation, 2026-11-04):
      * %WINDIR%\SysNative, not System32: the Windows agent is 32-bit and a
        plain System32 path is redirected to SysWOW64.
      * One entry per file: Wazuh's default config already has a
        %WINDIR%\SysNative directory entry with its own restrict list; a
        second entry for the same directory would not take effect.

    Idempotent (removes any earlier helper entries first) and backs up
    ossec.conf. Run on DC01 in an elevated PowerShell session.

    Note: metadata-only changes (owner/permissions) were reported by FIM scans,
    not in real time. To test, change something, then from the manager run:
        sudo /var/ossec/bin/agent_control -r -u <agent_id>

.NOTES
    Project : Corporate SOC Simulation - Nimbrek S.A.
    Rule    : 100240 (rules/local_rules.xml)
#>
#Requires -RunAsAdministrator
$conf  = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$files = 'sethc','utilman','osk','Magnify','Narrator','DisplaySwitch'
Copy-Item $conf "$conf.bak-fim" -Force

$xml = [IO.File]::ReadAllText($conf)
# drop earlier helper entries (directory+restrict form or per-file form)
$xml = ($xml -split "`r?`n" | Where-Object {
    $_ -notmatch 'DisplaySwitch\.exe\$' -and
    $_ -notmatch 'SysNative\\(sethc|utilman|osk|Magnify|Narrator|DisplaySwitch)\.exe<'
}) -join "`r`n"

$lines = ($files | ForEach-Object {
    "    <directories check_all=`"yes`" whodata=`"yes`">%WINDIR%\SysNative\$_.exe</directories>"
}) -join "`r`n"
$xml = ([regex]'<syscheck>').Replace($xml, "<syscheck>`r`n$lines", 1)
[IO.File]::WriteAllText($conf, $xml)
Write-Host "FIM entries for $($files.Count) accessibility helpers written to ossec.conf"

# Stop-Service can fail while the agent is mid-scan; fall back to ending the process.
try { Stop-Service WazuhSvc -Force -ErrorAction Stop }
catch { Stop-Process -Name wazuh-agent -Force -ErrorAction SilentlyContinue }
Start-Sleep 5
Start-Service WazuhSvc
Get-Service WazuhSvc | Select-Object Name, Status
Select-String -Path $conf -Pattern 'SysNative\\osk'
