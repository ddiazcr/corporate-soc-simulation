<#
.SYNOPSIS
    Export the DC01 Security log around the live Kerberoasting alert (rule 100212)
    for offline analysis. Read-only on the log: nothing is cleared or changed.

.DESCRIPTION
    Run on DC01 in an elevated PowerShell. It:
      1. checks that the alerted record (EventRecordID) is still in the Security log
         (the log may have rolled over since the alert);
      2. exports the time window to an .evtx with wevtutil (raw records, for Hayabusa);
      3. writes its SHA-256 (chain of custody: hash taken on the DC, before copying);
      4. writes the Kerberos/logon events of that window as JSON, parsed by Windows
         itself (Get-WinEvent), so the correlation does not depend on a single parser.

    Times are UTC. The DC clock was ~2 h behind on 2026-11-15; the alerted event's
    own systemTime (2026-11-15T21:37:36Z) is DC time, so the default window is wide.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\export_dc01_evtx.ps1
#>
param(
    [long]  $RecordId = 256462,
    [string]$Start    = '2026-11-15T19:00:00.000Z',
    [string]$End      = '2026-11-15T23:59:59.999Z',
    [string]$OutDir   = 'C:\IR\kerberoast-2026-11-15'
)
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an elevated PowerShell (Run as administrator): the Security log needs it.'
}

# 1. Is the alerted record still there?
$alerted = Get-WinEvent -LogName Security -FilterXPath "*[System[EventRecordID=$RecordId]]" -ErrorAction SilentlyContinue
if (-not $alerted) {
    $oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1
    Write-Warning ("Record $RecordId is no longer in the Security log (oldest record: {0} at {1:o}). " -f `
        $oldest.RecordId, $oldest.TimeCreated.ToUniversalTime())
    Write-Warning 'The live event cannot be exported. Stop here and report this result.'
    exit 2
}
'Record {0}: event {1} at {2:o} on {3}' -f $alerted.RecordId, $alerted.Id, `
    $alerted.TimeCreated.ToUniversalTime(), $alerted.MachineName

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$evtx = Join-Path $OutDir 'DC01-Security-window.evtx'
$json = Join-Path $OutDir 'DC01-kerberos-logon-window.json'

# 2. Raw export of the window (all event IDs, so the timeline has context).
$query = "*[System[TimeCreated[@SystemTime>='$Start' and @SystemTime<='$End']]]"
wevtutil epl Security $evtx "/q:$query" /ow:true
if ($LASTEXITCODE -ne 0) { throw "wevtutil failed with exit code $LASTEXITCODE" }

# 3. Hash on the DC, before the file leaves it.
$hash = Get-FileHash -Algorithm SHA256 -Path $evtx
"{0}  {1}" -f $hash.Hash.ToLower(), (Split-Path $evtx -Leaf) |
    Out-File -Encoding ascii (Join-Path $OutDir 'SHA256SUMS.txt')

# 4. Kerberos + logon events of the window, parsed by Windows (EventData by name).
$ids = 4768, 4769, 4770, 4771, 4624, 4625, 4634, 4672
$filter = '*[System[(' + (($ids | ForEach-Object { "EventID=$_" }) -join ' or ') + ')]]'
$events = Get-WinEvent -Path $evtx -FilterXPath $filter -ErrorAction SilentlyContinue | ForEach-Object {
    $x = [xml]$_.ToXml()
    $data = [ordered]@{}
    foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    [ordered]@{
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
        RecordId    = $_.RecordId
        EventId     = $_.Id
        Computer    = $_.MachineName
        EventData   = $data
    }
}
ConvertTo-Json -InputObject @($events) -Depth 4 | Out-File -Encoding utf8 $json

$n = @($events).Count
$inWindow = @($events | Where-Object { $_.RecordId -eq $RecordId }).Count
"Exported: $evtx"
"SHA-256 : $($hash.Hash.ToLower())"
"JSON    : $json ($n Kerberos/logon events; alerted record present: $([bool]$inWindow))"
if (-not $inWindow) { Write-Warning "Record $RecordId is outside -Start/-End: widen the window and run again." ; exit 3 }
