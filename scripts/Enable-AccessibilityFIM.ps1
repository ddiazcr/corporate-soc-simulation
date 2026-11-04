<#
.SYNOPSIS
    Puts the logon-screen accessibility helpers under Wazuh file integrity
    monitoring (FIM) so rule 100240 (T1546.008) can fire.

.DESCRIPTION
    Adds one <directories> line to the Wazuh agent's ossec.conf, inside
    <syscheck>, watching sethc / utilman / osk / Magnify / Narrator /
    DisplaySwitch in real time. Uses %WINDIR%\SysNative because the Windows
    agent is 32-bit and a plain System32 path would be redirected to SysWOW64.
    Backs up ossec.conf first, is idempotent, and restarts the agent.

    Run on DC01 in an elevated PowerShell session.

.NOTES
    Project : Corporate SOC Simulation - Nimbrek S.A.
    Rule    : 100240 (rules/local_rules.xml)
#>
#Requires -RunAsAdministrator
$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
Copy-Item $conf "$conf.bak-fim" -Force
$line = '    <directories check_all="yes" realtime="yes" recursion_level="0" restrict="sethc.exe$|utilman.exe$|osk.exe$|Magnify.exe$|Narrator.exe$|DisplaySwitch.exe$">%WINDIR%\SysNative</directories>'
$xml  = [IO.File]::ReadAllText($conf)
if ($xml -notmatch 'sethc\.exe\$') {
    $xml = ([regex]'<syscheck>').Replace($xml, "<syscheck>`r`n$line", 1)
    [IO.File]::WriteAllText($conf, $xml)
    Write-Host 'FIM line added to ossec.conf'
} else {
    Write-Host 'FIM line already present, nothing to add'
}
Restart-Service WazuhSvc
Get-Service WazuhSvc | Select-Object Name, Status
Select-String -Path $conf -Pattern 'SysNative' | Select-Object -Last 1
