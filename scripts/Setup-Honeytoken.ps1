<#
  Corporate SOC Simulation - honeytoken service account for Kerberoasting detection.
  Creates a decoy service account with an SPN and RC4-only encryption so any
  Kerberos service-ticket request for it (event 4769, 0x17) is a strong
  Kerberoasting signal. Safe for the Nimbrek lab only.
#>
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$name = 'svc_sql_backup'
$spn  = 'MSSQLSvc/db01.lab.local:1433'
$ou   = 'OU=Servidores,DC=lab,DC=local'
$pw   = ConvertTo-SecureString 'Nimbrek.Honey.2026!' -AsPlainText -Force

if (Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue) {
    Write-Host "Honeytoken $name already exists."
} else {
    New-ADUser -Name $name -SamAccountName $name -Path $ou `
        -AccountPassword $pw -Enabled $true `
        -Description 'Decoy service account - Kerberoasting honeytoken (lab)' `
        -ServicePrincipalNames $spn
    Write-Host "Created honeytoken $name with SPN $spn"
}
# Force RC4 so a roast request produces the 0x17 tell the rule looks for.
Set-ADUser -Identity $name -Replace @{ 'msDS-SupportedEncryptionTypes' = 4 }
Write-Host "RC4-only encryption set. Honeytoken ready."
