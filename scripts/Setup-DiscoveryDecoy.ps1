<#
.SYNOPSIS
    Creates a decoy user object whose every read is audited, so domain account
    discovery (T1087.002) - LDAP enumeration, BloodHound/SharpHound, netexec
    --users - produces event 4662 that Wazuh can alert on.

.DESCRIPTION
    Event 4662 ("An operation was performed on an object") is only logged when
    the object carries a SACL; enabling the "Directory Service Access" audit
    subcategory alone is not enough. Auditing reads on every user would flood
    the SIEM, so only ONE decoy account gets a "Read Property" SACL. No
    legitimate process has a reason to read it; an enumeration tool that dumps
    all users will.

    The decoy is disabled, has a long random password, and no group
    memberships, so it cannot be used to log on.

    Run on DC01 in an elevated PowerShell session.

.NOTES
    Project : Corporate SOC Simulation - Nimbrek S.A.
    Phase   : 3 - Attack & detection (T1087.002)
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$name = 'adm_backup_legacy'
$ou   = 'OU=Servidores,DC=lab,DC=local'

# 1. Decoy account (looks valuable to an attacker, unusable for logon)
if (-not (Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue)) {
    $bytes = New-Object byte[] 48
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $pw = ConvertTo-SecureString ([Convert]::ToBase64String($bytes) + 'aA1!') -AsPlainText -Force
    New-ADUser -Name $name -SamAccountName $name -Path $ou -AccountPassword $pw `
        -Enabled $false -Description 'Legacy backup admin - do not delete (decoy, lab)'
    Write-Host "Created decoy account $name (disabled)." -ForegroundColor Green
} else {
    Write-Host "Decoy account $name already exists." -ForegroundColor Yellow
}
$decoy = Get-ADUser $name -Properties ObjectGUID

# 2. Audit policy: Directory Service Access (success) must be on for 4662
auditpol /set /subcategory:"Directory Service Access" /success:enable | Out-Null

# 3. SACL on the decoy only: Everyone, Read Property, Success
$path = "AD:\$($decoy.DistinguishedName)"
$acl  = Get-Acl -Path $path -Audit
$everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
$already = $acl.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier]) |
    Where-Object { $_.IdentityReference -eq $everyone -and $_.ActiveDirectoryRights -match 'ReadProperty' }
if (-not $already) {
    $rule = New-Object DirectoryServices.ActiveDirectoryAuditRule($everyone, 'ReadProperty', 'Success')
    $acl.AddAuditRule($rule)
    Set-Acl -Path $path -AclObject $acl
    Write-Host "SACL added: Everyone / ReadProperty / Success on $name" -ForegroundColor Green
} else {
    Write-Host "SACL already present on $name." -ForegroundColor Yellow
}

# 4. Show what was configured
Write-Host "`n== Verification ==" -ForegroundColor Cyan
auditpol /get /subcategory:"Directory Service Access"
(Get-Acl -Path $path -Audit).Audit |
    Format-Table IdentityReference, ActiveDirectoryRights, AuditFlags -AutoSize
Write-Host "Decoy ObjectGUID: $($decoy.ObjectGUID)" -ForegroundColor Cyan
Write-Host "In event 4662 the object appears as ObjectName = %{$($decoy.ObjectGUID)}"
Write-Host "`nIf a GPO later reverts the audit setting, re-check with:"
Write-Host '  gpupdate /force; auditpol /get /subcategory:"Directory Service Access"'
