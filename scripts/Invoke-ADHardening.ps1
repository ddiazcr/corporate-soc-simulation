<#
.SYNOPSIS
    Hardens the Nimbrek S.A. domain against the attacks simulated in Phase 3.
    Dry run by default: it only prints what it WOULD change. Use -Apply to
    make the changes.

.DESCRIPTION
    Take a VirtualBox snapshot of DC01 first, then:
        .\Invoke-ADAudit.ps1 -Label before
        .\Invoke-ADHardening.ps1            # review the plan
        .\Invoke-ADHardening.ps1 -Apply     # apply it
        .\Invoke-ADAudit.ps1 -Label after

    Deliberately NOT automated (reported only, they can lock you out or need a
    planned procedure): Domain Admins membership, adding admins to Protected
    Users, and the krbtgt double password reset.

    Design exception: the honeytoken svc_sql_backup KEEPS RC4. It is a
    tripwire: its weak encryption is the bait that makes Kerberoasting visible
    (rules 100210/100212). Every real service account is moved to AES only.

.NOTES
    Project : Corporate SOC Simulation - Nimbrek S.A.
    Phase   : 5 - Hardening
#>

#Requires -RunAsAdministrator
param(
    [switch]$Apply,
    [string]$Honeytoken = 'svc_sql_backup'
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$mode = if ($Apply) { 'APPLY' } else { 'DRY RUN (nothing changes; use -Apply)' }
Write-Host "== Nimbrek S.A. AD hardening - $mode ==" -ForegroundColor Cyan
$log = New-Object System.Collections.Generic.List[string]

function Step($Id, $What, [scriptblock]$Action) {
    $line = "[$Id] $What"
    if ($Apply) {
        try { & $Action; Write-Host "APPLIED $line" -ForegroundColor Green; $log.Add("APPLIED $line") }
        catch { Write-Host "FAILED  $line : $_" -ForegroundColor Red; $log.Add("FAILED $line : $_") }
    } else {
        Write-Host "WOULD   $line" -ForegroundColor Yellow; $log.Add("WOULD $line")
    }
}

$domain = Get-ADDomain

# H1 - lockout + password length (T1110). 5 attempts / 15 min.
Step 'H1' 'Lockout 5 attempts / 15 min window / 15 min duration; min password length 12' {
    Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot `
        -LockoutThreshold 5 -LockoutObservationWindow '00:15:00' -LockoutDuration '00:15:00' `
        -MinPasswordLength 12 -ComplexityEnabled $true
}

# H2 - AES only for every real SPN account (T1558.003)
$spnUsers = Get-ADUser -Filter 'ServicePrincipalName -like "*"' |
    Where-Object { $_.SamAccountName -notin @('krbtgt', $Honeytoken) }
foreach ($u in $spnUsers) {
    Step 'H2' "AES128/AES256 only for service account $($u.SamAccountName)" {
        Set-ADUser $u -KerberosEncryptionType AES128, AES256
    }
}
Write-Host "      (honeytoken $Honeytoken keeps RC4 on purpose - it is the Kerberoasting tripwire)" -ForegroundColor DarkGray

# H3 - require Kerberos pre-authentication (T1558.004)
foreach ($u in (Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true')) {
    Step 'H3' "Require Kerberos pre-auth for $($u.SamAccountName)" {
        Set-ADAccountControl $u -DoesNotRequirePreAuth $false
    }
}

# H4 - Guest disabled
Step 'H4' 'Disable Guest account' { Disable-ADAccount -Identity Guest }

# H5 - users cannot add computers to the domain
Step 'H5' 'ms-DS-MachineAccountQuota = 0' {
    Set-ADDomain -Identity $domain -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }
}

# H6 - refuse LM/NTLMv1
Step 'H6' 'LmCompatibilityLevel = 5 (NTLMv2 only, refuse LM & NTLM)' {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord
}

# H7 - LDAP signing required (unsigned simple binds will be rejected)
Step 'H7' 'Require LDAP signing (LDAPServerIntegrity = 2)' {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -Value 2 -Type DWord
}

# H8 - SMB signing required
Step 'H8' 'Require SMB signing on the DC' {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
}

# H9 - Print Spooler off on the DC (PrinterBug / forced authentication)
Step 'H9' 'Stop and disable Print Spooler' {
    Stop-Service Spooler -Force -ErrorAction SilentlyContinue
    Set-Service Spooler -StartupType Disabled
}

# --- Reported only ------------------------------------------------------------
Write-Host "`n== Manual follow-up (not automated on purpose) ==" -ForegroundColor Cyan
$da = Get-ADGroupMember 'Domain Admins' -Recursive | ForEach-Object SamAccountName
Write-Host "Domain Admins: $($da -join ', ')  -> remove anyone who does not need standing membership."
Write-Host "Protected Users: add admin accounts only after confirming they log on with Kerberos (it blocks NTLM, RC4 and delegation)."
Write-Host "krbtgt: reset twice, at least 10 h apart (replication + ticket lifetime), in a planned window."

$out = Join-Path $PSScriptRoot ("ad_hardening_{0}.log" -f $(if ($Apply) { 'applied' } else { 'plan' }))
$log | Set-Content -Encoding UTF8 $out
Write-Host "`nLog: $out"
if ($Apply) { Write-Host "Reboot DC01 so the LSA, LDAP and SMB settings take full effect." -ForegroundColor Yellow }
