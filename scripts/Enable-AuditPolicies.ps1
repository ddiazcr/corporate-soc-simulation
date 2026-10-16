<#
.SYNOPSIS
    Enables the advanced audit policies required to detect identity-based
    attacks against the Nimbrek S.A. domain, and raises the Security log size.

.DESCRIPTION
    Run on the domain controller (DC01) in an elevated PowerShell session.
    It configures the audit subcategories that produce the Windows events
    Wazuh correlates in Phase 3 (logon failures, Kerberos service tickets,
    account and group management). In a single-DC lab auditpol is applied
    locally; in a multi-DC domain the same subcategories would be set through
    a GPO linked to the Domain Controllers OU.

.NOTES
    Project : Corporate SOC Simulation - Nimbrek S.A.
    Phase   : 2 - Visibility
    Target  : Windows Server 2022, domain lab.local
#>

#Requires -RunAsAdministrator

Write-Host "== Nimbrek S.A. | Enabling advanced audit policies ==" -ForegroundColor Cyan

# Subcategory -> MITRE technique it supports
$subcategories = @(
    "Logon",                          # 4624 / 4625  - T1110 brute force / spraying
    "Logoff",                         # 4634
    "Account Lockout",                # 4740         - T1110 lockout from spraying
    "Kerberos Authentication Service",# 4768 / 4771  - T1110.003 / AS-REP
    "Kerberos Service Ticket Operations", # 4769     - T1558.003 Kerberoasting
    "User Account Management",        # 4720 / 4722 / 4725 / 4726 - T1136 / T1098
    "Security Group Management",      # 4728 / 4732 / 4756 - T1098 privileged group add
    "Directory Service Access"        # 4662         - T1087.002 AD discovery
)

foreach ($sub in $subcategories) {
    Write-Host ("Enabling Success+Failure for: {0}" -f $sub) -ForegroundColor Gray
    auditpol /set /subcategory:"$sub" /success:enable /failure:enable | Out-Null
}

# The Security log fills quickly once auditing is on; give it room.
Write-Host "Raising Security event log to 256 MB..." -ForegroundColor Gray
wevtutil sl Security /ms:268435456

Write-Host "`n== Current audit configuration ==" -ForegroundColor Cyan
auditpol /get /category:"Logon/Logoff","Account Management","DS Access","Account Logon"

Write-Host "`nDone. Generate a failed logon and confirm event 4625 reaches Wazuh." -ForegroundColor Green
