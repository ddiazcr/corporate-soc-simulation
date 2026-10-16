<#
  Corporate SOC Simulation - generate the Phase 3 detection test events.
  All actions target the Nimbrek lab's own domain controller to validate
  Blue Team detections (MITRE T1110.003, T1558.003, T1098). Benign and
  self-contained: wrong-password attempts and a privileged-group change
  that is immediately reverted.
#>
param([string]$DC = '192.168.56.10')
$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory

Write-Host "`n== 1. Password spraying (T1110.003) - 6 accounts, one wrong try each =="
$targets = 'ggomez','mrojas','lsolis','acruz','dvargas','pmendez'
foreach ($u in $targets) {
    cmd /c "net use \\$DC\ipc`$ /user:lab\$u WrongPass#2026 2>&1" | Out-Null
    cmd /c "net use \\$DC\ipc`$ /delete 2>nul" | Out-Null
    Write-Host "  tried $u"
    Start-Sleep -Milliseconds 800
}

Write-Host "`n== 2. Kerberoasting (T1558.003) - request RC4 service ticket for the honeytoken =="
Add-Type -AssemblyName System.IdentityModel
try {
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
        -ArgumentList 'MSSQLSvc/db01.lab.local:1433' | Out-Null
    Write-Host "  requested TGS for MSSQLSvc/db01.lab.local:1433"
} catch { Write-Host "  TGS request error: $($_.Exception.Message)" }

Write-Host "`n== 3. Privileged group change (T1098) - add to Domain Admins then revert =="
# Pick a real, enabled, non-admin lab user so the step never fails on a name.
$da = (Get-ADGroupMember 'Domain Admins' | Select-Object -Expand SamAccountName)
$u  = Get-ADUser -Filter 'Enabled -eq $true' -SearchBase 'OU=Ventas,DC=lab,DC=local' -ErrorAction SilentlyContinue |
      Where-Object { $_.SamAccountName -notin $da } | Select-Object -First 1 -Expand SamAccountName
if (-not $u) {
    $u = Get-ADUser -Filter 'Enabled -eq $true' |
         Where-Object { $_.SamAccountName -notin $da -and $_.SamAccountName -ne 'svc_sql_backup' } |
         Select-Object -First 1 -Expand SamAccountName
}
if ($u) {
    try {
        Add-ADGroupMember -Identity 'Domain Admins' -Members $u
        Write-Host "  added $u to Domain Admins"
        Start-Sleep -Seconds 2
        Remove-ADGroupMember -Identity 'Domain Admins' -Members $u -Confirm:$false
        Write-Host "  removed $u from Domain Admins (reverted)"
    } catch { Write-Host "  group change error: $($_.Exception.Message)" }
} else {
    Write-Host "  no suitable test user found, skipped"
}

Write-Host "`nDone. Check alerts on the Wazuh manager with scripts/verify_detections.sh"
