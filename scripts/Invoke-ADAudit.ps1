<#
.SYNOPSIS
    Read-only security audit of the Nimbrek S.A. domain. Run it before and
    after hardening to measure the change.

.DESCRIPTION
    Checks the settings that the Phase 3 attacks abused (or that commonly
    enable AD attacks) and prints PASS / FAIL per check plus a score. Changes
    nothing. Results are also saved as JSON so the before/after runs can be
    compared and committed as evidence.

    Run on DC01 in an elevated PowerShell session:
        .\Invoke-ADAudit.ps1 -Label before
        .\Invoke-ADAudit.ps1 -Label after

.NOTES
    Project : Corporate SOC Simulation - Nimbrek S.A.
    Phase   : 5 - Hardening
#>

#Requires -RunAsAdministrator
param(
    [string]$Label = 'audit',
    [string]$Honeytoken = 'svc_sql_backup'   # intentional RC4 tripwire, reported as an exception
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$results = New-Object System.Collections.Generic.List[object]
function Add-Check($Id, $Name, $Pass, $Detail, $Mitre) {
    $results.Add([pscustomobject]@{
        Id = $Id; Check = $Name; Result = $(if ($Pass) { 'PASS' } else { 'FAIL' })
        Detail = $Detail; Mitigates = $Mitre
    })
}
function Get-Reg($Path, $Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

$pol    = Get-ADDefaultDomainPasswordPolicy
$domain = Get-ADDomain

# --- Password and lockout policy ------------------------------------------
Add-Check 'P1' 'Account lockout threshold set (1-10)' `
    ($pol.LockoutThreshold -ge 1 -and $pol.LockoutThreshold -le 10) `
    "LockoutThreshold=$($pol.LockoutThreshold)" 'T1110.001 brute force'
Add-Check 'P2' 'Minimum password length >= 12' ($pol.MinPasswordLength -ge 12) `
    "MinPasswordLength=$($pol.MinPasswordLength)" 'T1110 password guessing / spraying'
Add-Check 'P3' 'Password complexity enabled' $pol.ComplexityEnabled `
    "ComplexityEnabled=$($pol.ComplexityEnabled)" 'T1110'

# --- Kerberos ---------------------------------------------------------------
$spnUsers = Get-ADUser -Filter 'ServicePrincipalName -like "*"' `
    -Properties ServicePrincipalName, 'msDS-SupportedEncryptionTypes' |
    Where-Object { $_.SamAccountName -ne 'krbtgt' }
# RC4 allowed when the attribute is empty/0 (defaults) or has bit 0x4 set
$rc4 = $spnUsers | Where-Object {
    $e = $_.'msDS-SupportedEncryptionTypes'; (-not $e) -or ($e -band 4)
}
$rc4Real = $rc4 | Where-Object { $_.SamAccountName -ne $Honeytoken }
Add-Check 'K1' 'No Kerberoastable account allows RC4 (honeytoken excepted)' (-not $rc4Real) `
    ("RC4 allowed: " + (($rc4 | ForEach-Object SamAccountName) -join ', ') +
     " | honeytoken exception: $Honeytoken") 'T1558.003 Kerberoasting'

$asrep = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth
Add-Check 'K2' 'No account without Kerberos pre-authentication' (-not $asrep) `
    ("AS-REP roastable: " + (($asrep | ForEach-Object SamAccountName) -join ', ')) 'T1558.004 AS-REP roasting'

$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
$krbAge = [int]((Get-Date) - $krbtgt.PasswordLastSet).TotalDays
Add-Check 'K3' 'krbtgt password changed in the last 180 days' ($krbAge -le 180) `
    "krbtgt age = $krbAge days" 'T1558.001 Golden Ticket'

# --- Privileged accounts ----------------------------------------------------
$da = Get-ADGroupMember 'Domain Admins' -Recursive
Add-Check 'A1' 'Domain Admins has 2 or fewer members' ($da.Count -le 2) `
    ("Members: " + (($da | ForEach-Object SamAccountName) -join ', ')) 'T1098 / blast radius'

$pu = @(Get-ADGroupMember 'Protected Users' -ErrorAction SilentlyContinue | ForEach-Object SamAccountName)
$daNotProtected = $da | Where-Object { $_.objectClass -eq 'user' -and $pu -notcontains $_.SamAccountName }
Add-Check 'A2' 'Domain Admins are in Protected Users' (-not $daNotProtected) `
    ("Not protected: " + (($daNotProtected | ForEach-Object SamAccountName) -join ', ')) 'T1003 / T1550 credential theft'

$guest = Get-ADUser Guest -Properties Enabled
Add-Check 'A3' 'Guest account disabled' (-not $guest.Enabled) "Guest enabled=$($guest.Enabled)" 'T1078 valid accounts'

$maq = (Get-ADObject $domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
Add-Check 'A4' 'Users cannot join computers (MachineAccountQuota = 0)' ($maq -eq 0) `
    "ms-DS-MachineAccountQuota=$maq" 'T1136 / RBCD abuse'

# --- Protocol hardening on the DC -----------------------------------------
$lm = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
Add-Check 'N1' 'NTLMv1/LM refused (LmCompatibilityLevel = 5)' ($lm -eq 5) "LmCompatibilityLevel=$lm" 'T1557 / NTLM relay & cracking'

$ldap = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
Add-Check 'N2' 'LDAP signing required (LDAPServerIntegrity = 2)' ($ldap -eq 2) "LDAPServerIntegrity=$ldap" 'T1557 LDAP relay'

$smb = (Get-SmbServerConfiguration).RequireSecuritySignature
Add-Check 'N3' 'SMB signing required on the DC' $smb "RequireSecuritySignature=$smb" 'T1557 SMB relay'

$spool = Get-Service Spooler -ErrorAction SilentlyContinue
Add-Check 'N4' 'Print Spooler disabled on the DC' (-not $spool -or $spool.StartType -eq 'Disabled') `
    "Spooler: $($spool.Status) / $($spool.StartType)" 'T1187 forced authentication (PrinterBug)'

# --- Report -----------------------------------------------------------------
$pass  = ($results | Where-Object Result -eq 'PASS').Count
$total = $results.Count
Write-Host "`n== Nimbrek S.A. AD audit [$Label] $(Get-Date -Format 'yyyy-MM-dd HH:mm') ==" -ForegroundColor Cyan
foreach ($r in $results) {
    $c = if ($r.Result -eq 'PASS') { 'Green' } else { 'Red' }
    Write-Host ("[{0}] {1,-3} {2}" -f $r.Result, $r.Id, $r.Check) -ForegroundColor $c
    Write-Host ("            {0}" -f $r.Detail) -ForegroundColor DarkGray
}
Write-Host ("`nScore: {0}/{1} checks passed ({2}%)" -f $pass, $total, [int](100 * $pass / $total)) -ForegroundColor Cyan

$out = Join-Path $PSScriptRoot "ad_audit_$Label.json"
[pscustomobject]@{ label = $Label; date = (Get-Date).ToString('s'); score = "$pass/$total"; checks = $results } |
    ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $out
Write-Host "Saved: $out"
