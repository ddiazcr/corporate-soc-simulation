<#
.SYNOPSIS
    Creates a Kerberoasting honeytoken: a domain service account with an SPN
    and (optionally) a deliberately weak password, so any Kerberos service
    ticket (4769) requested for it is suspicious by design.

.DESCRIPTION
    Supports Phase 3 technique T1558.003. The account exists only to be
    roasted in the lab: it is non-interactive, placed in a dedicated OU, and
    its ticket requests feed Wazuh rules 100210/100211. Run on DC01 as a
    Domain Admin. Lab use only (lab.local).

.PARAMETER SamAccountName
    Service account name, e.g. svc-sql.

.PARAMETER Spn
    Service Principal Name to register, e.g. MSSQLSvc/dc01.lab.local:1433.

.PARAMETER OuPath
    OU for the account. Defaults to the Service Accounts OU.

.PARAMETER WeakPassword
    If set, assigns a weak password so offline cracking can be demonstrated.
    Omit to prompt for a password instead.

.EXAMPLE
    .\New-KerberoastHoneytoken.ps1 -SamAccountName svc-sql `
        -Spn 'MSSQLSvc/dc01.lab.local:1433' -WeakPassword
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$SamAccountName,
    [Parameter(Mandatory)] [string]$Spn,
    [string]$OuPath = "OU=ServiceAccounts,DC=lab,DC=local",
    [switch]$WeakPassword
)

Import-Module ActiveDirectory -ErrorAction Stop

# Create the OU if it does not exist (idempotent)
$ouName = ($OuPath -split ',')[0] -replace '^OU=', ''
$parent = ($OuPath -split ',', 2)[1]
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -SearchBase $parent -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $ouName -Path $parent -ProtectedFromAccidentalDeletion $false
    Write-Host "[+] Created OU $OuPath"
}

if ($WeakPassword) {
    # Intentionally weak — honeytoken for offline cracking in the lab
    $pw = ConvertTo-SecureString 'Summer2024' -AsPlainText -Force
    Write-Warning "Using a weak lab password by design (honeytoken)."
} else {
    $pw = Read-Host -AsSecureString "Password for $SamAccountName"
}

New-ADUser -Name $SamAccountName -SamAccountName $SamAccountName `
    -UserPrincipalName "$SamAccountName@lab.local" -Path $OuPath `
    -AccountPassword $pw -Enabled $true `
    -PasswordNeverExpires $true -CannotChangePassword $true `
    -Description "Lab Kerberoasting honeytoken - do not use interactively"

# Register the SPN -> makes the account roastable
Set-ADUser -Identity $SamAccountName -ServicePrincipalNames @{Add = $Spn}

Write-Host "[+] Created $SamAccountName with SPN $Spn"
Write-Host "[i] Verify:  Get-ADUser $SamAccountName -Properties ServicePrincipalNames"
Write-Host "[i] Roast from Kali:  GetUserSPNs.py lab.local/<user>:<pw> -dc-ip 192.168.56.10 -request"
