<#
.SYNOPSIS
    Extract chosen records from an exported .evtx with their native fields,
    including the audit result (Keywords: Audit Success / Audit Failure).

.DESCRIPTION
    Runs on any Windows host against a copy of the export (no DC access needed).
    Selects records by EventRecordID and/or every event whose SubjectLogonId or
    TargetLogonId is one of the given logon sessions, so the scope of a session
    (e.g. all 4662 directory accesses) is visible, not only Hayabusa's hits.
    Output: JSON array, one object per record, sorted by RecordId.

.EXAMPLE
    .\extract_native_records.ps1 -Evtx .\DC01-Security-window.evtx `
        -RecordId 256272,256286,256460,256462 -LogonId 0x37072c,0x39e0f5,0x9f14e `
        -Out .\DC01-native-records.json
#>
param(
    [Parameter(Mandatory)] [string]  $Evtx,
    [long[]]   $RecordId = @(),
    [string[]] $LogonId  = @(),
    [Parameter(Mandatory)] [string]  $Out
)
$ErrorActionPreference = 'Stop'
$path = (Resolve-Path $Evtx).Path
$queries = @()
if ($RecordId.Count) {
    $queries += '*[System[(' + (($RecordId | ForEach-Object { "EventRecordID=$_" }) -join ' or ') + ')]]'
}
foreach ($lid in $LogonId) {
    $queries += "*[EventData[Data[@Name='SubjectLogonId']='$lid']]"
    $queries += "*[EventData[Data[@Name='TargetLogonId']='$lid']]"
}
if (-not $queries.Count) { throw 'Give -RecordId and/or -LogonId.' }

$seen = @{}
$rows = foreach ($q in $queries) {
    Get-WinEvent -Path $path -FilterXPath $q -ErrorAction SilentlyContinue | ForEach-Object {
        if ($seen.ContainsKey($_.RecordId)) { return }
        $seen[$_.RecordId] = $true
        $x = [xml]$_.ToXml()
        $data = [ordered]@{}
        foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        [ordered]@{
            TimeCreated          = $_.TimeCreated.ToUniversalTime().ToString('o')
            RecordId             = $_.RecordId
            EventId              = $_.Id
            Computer             = $_.MachineName
            Keywords             = ('0x{0:x}' -f $_.Keywords)        # 0x8020... success, 0x8010... failure
            KeywordsDisplayNames = ($_.KeywordsDisplayNames -join ', ')
            TaskDisplayName      = $_.TaskDisplayName
            EventData            = $data
        }
    }
}
$rows = @($rows | Sort-Object { $_.RecordId })
ConvertTo-Json -InputObject $rows -Depth 4 | Out-File -Encoding utf8 $Out
"$($rows.Count) records -> $Out"
$rows | Group-Object { "$($_.EventId) $($_.KeywordsDisplayNames)" } | Sort-Object Name |
    ForEach-Object { "  {0,4} x {1}" -f $_.Count, $_.Name }
