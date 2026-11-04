<#
.SYNOPSIS
    Restores the owner of a protected Windows system file to TrustedInstaller.

.DESCRIPTION
    After a test or a recovery that used takeown, the file's owner stays set to
    an administrator. Assigning ownership to ANOTHER principal (here
    NT SERVICE\TrustedInstaller) requires SeRestorePrivilege. Elevated
    administrators hold that privilege but it is disabled by default, and
    icacls /setowner does not enable it - which is why it fails with
    "Access is denied", even when run as SYSTEM.

    This script enables SeRestorePrivilege in its own process token and sets
    the owner through the .NET security API. It only changes the owner; the
    DACL is written back unchanged.

    Run in an elevated PowerShell session on the affected host.

.EXAMPLE
    .\Restore-SystemFileOwner.ps1 -Path C:\Windows\System32\osk.exe

.NOTES
    Project : Corporate SOC Simulation - Nimbrek S.A.
    Context : cleanup after validating rule 100240 (T1546.008)
#>
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory)] [string[]] $Path,
    [string] $Owner = 'NT SERVICE\TrustedInstaller'
)

$def = @'
using System;
using System.Runtime.InteropServices;
public static class TokenPrivilege {
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct TOKEN_PRIVILEGES { public int Count; public long Luid; public int Attributes; }
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string system, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES newState, int length, IntPtr previous, IntPtr returnLength);
    public static bool Enable(string privilege) {
        IntPtr token;
        // TOKEN_ADJUST_PRIVILEGES (0x20) | TOKEN_QUERY (0x08)
        if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x28, out token)) return false;
        TOKEN_PRIVILEGES tp; tp.Count = 1; tp.Attributes = 2; // SE_PRIVILEGE_ENABLED
        if (!LookupPrivilegeValue(null, privilege, out tp.Luid)) return false;
        return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)
               && Marshal.GetLastWin32Error() == 0;
    }
}
'@
if (-not ('TokenPrivilege' -as [type])) { Add-Type -TypeDefinition $def }

if (-not [TokenPrivilege]::Enable('SeRestorePrivilege')) {
    throw 'Could not enable SeRestorePrivilege - run from an elevated session.'
}

$account = [System.Security.Principal.NTAccount]$Owner
foreach ($p in $Path) {
    $before = (Get-Acl $p).Owner
    $acl = Get-Acl $p
    $acl.SetOwner($account)
    Set-Acl -Path $p -AclObject $acl
    [pscustomobject]@{ Path = $p; Before = $before; After = (Get-Acl $p).Owner }
}
