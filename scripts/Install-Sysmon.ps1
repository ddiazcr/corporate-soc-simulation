<#
.SYNOPSIS
    Installs Sysinternals Sysmon with the SwiftOnSecurity base config and
    confirms the service and event channel. Run on DC01 and each domain
    workstation as Administrator. Lab use (lab.local).

.DESCRIPTION
    Supports the detection-visibility upgrade for Phase 3+. Sysmon surfaces
    process creation, network connections and LSASS access that the Security
    log does not. Pair with the Wazuh agent eventchannel block in
    docs/sysmon-setup.md so the data reaches the manager.

.PARAMETER ConfigUrl
    URL of the Sysmon config XML. Defaults to SwiftOnSecurity's export.

.PARAMETER InstallDir
    Local install directory. Defaults to C:\Sysmon.

.EXAMPLE
    .\Install-Sysmon.ps1
#>

[CmdletBinding()]
param(
    [string]$ConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',
    [string]$InstallDir = 'C:\Sysmon'
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

Write-Host "[*] Downloading Sysmon..."
Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' `
    -OutFile "$InstallDir\Sysmon.zip"
Expand-Archive "$InstallDir\Sysmon.zip" -DestinationPath $InstallDir -Force

Write-Host "[*] Downloading config..."
Invoke-WebRequest $ConfigUrl -OutFile "$InstallDir\sysmonconfig.xml"

$sysmon = Join-Path $InstallDir 'Sysmon64.exe'
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    Write-Host "[*] Sysmon already installed - updating config..."
    & $sysmon -c "$InstallDir\sysmonconfig.xml"
} else {
    Write-Host "[*] Installing Sysmon..."
    & $sysmon -accepteula -i "$InstallDir\sysmonconfig.xml"
}

Start-Sleep 3
$svc = Get-Service Sysmon64
Write-Host "[+] Service Sysmon64: $($svc.Status)"
Write-Host "[i] Recent events:"
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 3 |
    Format-Table TimeCreated, Id, Message -Auto

Write-Host ""
Write-Host "[i] Next: add the eventchannel block to the Wazuh agent ossec.conf"
Write-Host "    (docs/sysmon-setup.md), then: Restart-Service WazuhSvc"
