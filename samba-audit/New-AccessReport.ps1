<#
.SYNOPSIS
    Joins share permissions, NTFS permissions and AD group membership into one CSV:
    who can reach which folder, and through which group.

.DESCRIPTION
    Reads the three CSVs of one export set:
        Share_Permissions_<Server>_<date>.csv     (SMB share ACLs)
        NTFS_Permissions_<Server>_<date>.csv      (NTFS ACLs at permission boundaries)
        AD_Group_Members_<Server>_<date>.csv      (from Get-ADGroupMembers.ps1)
    and writes Access_Report_<Server>_<date>.csv with one row per folder, permission entry
    and person. An entry granted to a group is repeated for every member, nested groups
    included, so you can filter on a person and see every folder they reach, or filter on
    a folder and see every person.

    Run Get-ADGroupMembers.ps1 first; this script does not talk to Active Directory and
    can be run anywhere that has the CSVs. Run it by hand - nothing calls it automatically.

        .\New-AccessReport.ps1 -InputDirectory 'C:\scripts\VNET_Samba_Audit\q report'

    Columns
      Layer           Share (SMB share permission) or NTFS (folder permission)
      ShareName, FolderPath, RelativePath, BoundaryType
                      where the permission sits. NTFS rows exist only at permission
                      boundaries: the share root, folders that block inheritance and
                      folders with their own entries. Their ACL applies to everything
                      below until the next boundary.
      Trustee         who the ACL names (a group, a user, BUILTIN\Users, ...)
      TrusteeKind     Group | User | Other (local, BUILTIN, Everyone, other domains)
      AccessType      Allow | Deny
      Rights          Share: Full | Change | Read.  NTFS: FullControl | Modify | ReadExecute | ...
      RightsDetail    the raw NTFS right names
      AppliesTo, IsInherited, InheritedFrom
      GroupStatus     for group trustees: Expanded | Truncated | Empty | Skipped | NotFound | Error
                      for entries that could not be expanded: NotExpanded
      Person          the account that gets the access (DOMAIN\name); empty when the group
                      has no members or was not expanded
      PersonName, PersonType (User | Computer | Foreign | ...), Enabled
      Via             Direct (named in the ACL) | Group (direct member) | NestedGroup
      NestingLevel, ParentGroup, MembershipPath
                      how the person is in the group (see Get-ADGroupMembers.ps1)

    Access to a folder needs BOTH layers: the share permission and the NTFS permission.
    The effective right is the more restrictive of the two, and a Deny wins over an Allow.
    This report lists the layers side by side and does not compute that for you.

    Size: every group entry becomes one row per member, so a large share can run to
    millions of rows. Output is split into parts of -MaxRowsPerFile rows (default 1,000,000,
    which stays under the Excel row limit): ..._part2.csv, ..._part3.csv. Use -ShareName or
    -ExplicitOnly to get a smaller report.

.PARAMETER NtfsCsv
    NTFS permissions CSV. With it, give -ShareCsv and -MembersCsv too.

.PARAMETER ShareCsv
    Share permissions CSV.

.PARAMETER MembersCsv
    AD group membership CSV from Get-ADGroupMembers.ps1.

.PARAMETER InputDirectory
    Pick the newest export set in this folder (it must have all three CSVs).

.PARAMETER ScanDate
    With -InputDirectory, use this export date (yyyyMMdd) instead of the newest.

.PARAMETER OutputDirectory
    Where the report is written. Defaults to the folder of the NTFS CSV.

.PARAMETER ShareName
    Only these shares (wildcards accepted).

.PARAMETER ExplicitOnly
    NTFS: only entries set directly on a folder (not inherited), plus everything on the
    share root. Much smaller, but a folder's inherited groups are then not listed there.

.PARAMETER MaxRowsPerFile
    Start a new file after this many rows. 0 = never split.

.EXAMPLE
    .\New-AccessReport.ps1 -InputDirectory 'C:\scripts\VNET_Samba_Audit\q report'

.EXAMPLE
    .\New-AccessReport.ps1 -InputDirectory .\Reports -ShareName 'Hodnotenie*' -ExplicitOnly
#>
[CmdletBinding(DefaultParameterSetName = 'Directory')]
param(
    [Parameter(ParameterSetName = 'Files', Mandatory)] [string]$NtfsCsv,
    [Parameter(ParameterSetName = 'Files', Mandatory)] [string]$ShareCsv,
    [Parameter(ParameterSetName = 'Files', Mandatory)] [string]$MembersCsv,

    [Parameter(ParameterSetName = 'Directory')]
    [string]$InputDirectory = (Join-Path $PSScriptRoot 'Reports'),

    [Parameter(ParameterSetName = 'Directory')]
    [ValidatePattern('^\d{8}$')]
    [string]$ScanDate,

    [string]  $OutputDirectory,
    [string[]]$ShareName,
    [switch]  $ExplicitOnly,
    [ValidateRange(0, 2000000000)][int]$MaxRowsPerFile = 1000000
)

$ErrorActionPreference = 'Stop'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

#region ---------------------------------------------------------------- helpers

function Format-CsvField($Value) {
    $s = if ($null -eq $Value) { '' } else { [string]$Value }
    if ($s.IndexOfAny([char[]]@(',', '"', "`r", "`n")) -ge 0) { '"' + $s.Replace('"', '""') + '"' } else { $s }
}

function Join-CsvRow([object[]]$Fields) {
    ($Fields | ForEach-Object { Format-CsvField $_ }) -join ','
}

function Open-CsvParser([string]$Path) {
    Add-Type -AssemblyName Microsoft.VisualBasic
    $p = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($Path, [System.Text.Encoding]::UTF8, $true)
    $p.TextFieldType = 'Delimited'
    $p.SetDelimiters(',')
    $p.HasFieldsEnclosedInQuotes = $true
    $p
}

function Get-ColumnIndex([string[]]$Header, [string[]]$Required, [string]$Path) {
    $ix = @{}
    for ($i = 0; $i -lt $Header.Length; $i++) { $ix[$Header[$i]] = $i }
    foreach ($c in $Required) { if (-not $ix.ContainsKey($c)) { throw "Column '$c' not found in $Path" } }
    $ix
}

function Find-ReportSet {
    # Newest NTFS + share pair; the membership CSV must then exist for the same date.
    param([string]$Directory, [string]$Date)
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { throw "Input directory not found: $Directory" }
    $sets = foreach ($f in Get-ChildItem -LiteralPath $Directory -Filter 'NTFS_Permissions_*.csv' -File) {
        if ($f.Name -notmatch '^NTFS_Permissions_(?<srv>.+)_(?<date>\d{8})\.csv$') { continue }
        if ($Date -and $Matches['date'] -ne $Date) { continue }
        $share = Join-Path $Directory ('Share_Permissions_{0}_{1}.csv' -f $Matches['srv'], $Matches['date'])
        if (-not (Test-Path -LiteralPath $share -PathType Leaf)) { continue }
        [pscustomobject]@{
            Server = $Matches['srv']; Date = $Matches['date']; NtfsCsv = $f.FullName; ShareCsv = $share
            MembersCsv = (Join-Path $Directory ('AD_Group_Members_{0}_{1}.csv' -f $Matches['srv'], $Matches['date']))
        }
    }
    @($sets | Sort-Object -Property Date, Server -Descending)
}

# one tail = the nine person-level columns, already CSV-formatted:
# GroupStatus, Person, PersonName, PersonType, Enabled, Via, NestingLevel, ParentGroup, MembershipPath
function New-Tail($Status, $Person, $Name, $Type, $Enabled, $Via, $Level, $Parent, $Path) {
    Join-CsvRow @($Status, $Person, $Name, $Type, $Enabled, $Via, $Level, $Parent, $Path)
}

#endregion

#region ------------------------------------------------------------------ inputs

if ($PSCmdlet.ParameterSetName -eq 'Files') {
    foreach ($p in $NtfsCsv, $ShareCsv, $MembersCsv) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "File not found: $p" }
    }
    $ntfsCsv = (Resolve-Path -LiteralPath $NtfsCsv).ProviderPath
    $shareCsv = (Resolve-Path -LiteralPath $ShareCsv).ProviderPath
    $membersCsv = (Resolve-Path -LiteralPath $MembersCsv).ProviderPath
}
else {
    $sets = @(Find-ReportSet -Directory $InputDirectory -Date $ScanDate)
    if ($sets.Count -eq 0) {
        throw "No export set (NTFS + share CSV with the same server and date) found in $InputDirectory$(if ($ScanDate) { " for $ScanDate" })."
    }
    $pick = $sets[0]
    if (-not (Test-Path -LiteralPath $pick.MembersCsv -PathType Leaf)) {
        throw ("The membership CSV for {0} {1} is missing:`n  {2}`nRun Get-ADGroupMembers.ps1 -InputDirectory '{3}' first." -f
            $pick.Server, $pick.Date, $pick.MembersCsv, $InputDirectory)
    }
    $ntfsCsv = $pick.NtfsCsv; $shareCsv = $pick.ShareCsv; $membersCsv = $pick.MembersCsv
}

if ((Split-Path $ntfsCsv -Leaf) -match '^NTFS_Permissions_(?<srv>.+)_(?<date>\d{8})\.csv$') {
    $server = $Matches['srv']; $date = $Matches['date']
}
else {
    $server = $env:COMPUTERNAME; $date = (Get-Date).ToString('yyyyMMdd')
}
$outDir = if ($OutputDirectory) { $OutputDirectory } else { Split-Path $ntfsCsv -Parent }
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$outFile = Join-Path $outDir "Access_Report_${server}_${date}.csv"

Write-Host ''
Write-Host "Building access report for $server ($date)" -ForegroundColor Cyan
Write-Host "  Share   : $shareCsv"
Write-Host "  NTFS    : $ntfsCsv"
Write-Host "  Members : $membersCsv"

#endregion

#region ------------------------------------------------------------ membership

# group -> @{ Status; Tails }, account -> @{ Name; Enabled }
$groups = @{}
$people = @{}
$knownDomains = @{}

$memberRows = @(Import-Csv -LiteralPath $membersCsv -Encoding UTF8)
foreach ($c in 'Group', 'GroupStatus', 'MemberType', 'Member') {
    if ($memberRows.Count -gt 0 -and -not ($memberRows[0].PSObject.Properties.Name -contains $c)) {
        throw "Column '$c' not found in $membersCsv - was it made by Get-ADGroupMembers.ps1?"
    }
}
foreach ($r in $memberRows) {
    $g = $groups[$r.Group]
    if (-not $g) {
        $g = @{ Status = $r.GroupStatus; Tails = [System.Collections.Generic.List[string]]::new() }
        $groups[$r.Group] = $g
    }
    $g.Status = $r.GroupStatus
    $dom = $r.Group.Split('\')[0]
    if ($r.Group.Contains('\')) { $knownDomains[$dom.ToUpperInvariant()] = $true }

    if (-not $r.MemberType -or $r.MemberType -eq 'Group') { continue }   # nested group rows are not people
    if ($r.Member.Contains('\')) { $knownDomains[$r.Member.Split('\')[0].ToUpperInvariant()] = $true }
    $people[$r.Member] = @{ Name = $r.DisplayName; Enabled = $r.Enabled }
    $level = 0; [void][int]::TryParse($r.NestingLevel, [ref]$level)
    $via = if ($level -le 1) { 'Group' } else { 'NestedGroup' }
    $g.Tails.Add((New-Tail $r.GroupStatus $r.Member $r.DisplayName $r.MemberType $r.Enabled $via $r.NestingLevel $r.ParentGroup $r.MembershipPath))
}
foreach ($k in @($groups.Keys)) {
    $g = $groups[$k]
    # empty, missing or unexpanded groups still get one row so they stay visible
    if ($g.Tails.Count -eq 0) { $g.Tails.Add((New-Tail $g.Status '' '' '' '' '' '' '' '')) }
}
Write-Host ("  {0:N0} groups, {1:N0} distinct people in the membership file" -f $groups.Count, $people.Count)
if ($knownDomains.Count -eq 0) {
    Write-Warning 'The membership file names no domain, so every non-group trustee is reported as Other.'
}

$trusteeCache = @{}
function Get-TrusteeInfo([string]$Trustee) {
    $hit = $trusteeCache[$Trustee]
    if ($hit) { return $hit }
    if ($groups.ContainsKey($Trustee)) {
        $info = @{ Kind = 'Group'; Tails = $groups[$Trustee].Tails }
    }
    else {
        $dom = if ($Trustee.Contains('\')) { $Trustee.Split('\')[0].ToUpperInvariant() } else { '' }
        if ($dom -and $knownDomains.ContainsKey($dom)) {
            $p = $people[$Trustee]
            $info = @{
                Kind  = 'User'
                Tails = [System.Collections.Generic.List[string]]@(
                    (New-Tail '' $Trustee $(if ($p) { $p.Name } else { '' }) 'User' $(if ($p) { $p.Enabled } else { '' }) 'Direct' '' '' ''))
            }
        }
        else {
            # local, BUILTIN, Everyone, other domain: we cannot say who is behind it
            $info = @{ Kind = 'Other'; Tails = [System.Collections.Generic.List[string]]@((New-Tail 'NotExpanded' '' '' '' '' '' '' '' '')) }
        }
    }
    $trusteeCache[$Trustee] = $info
    $info
}

#endregion

#region ----------------------------------------------------------------- output

$header = 'Server,Layer,ShareName,FolderPath,RelativePath,BoundaryType,Trustee,TrusteeKind,AccessType,Rights,RightsDetail,AppliesTo,IsInherited,InheritedFrom,GroupStatus,Person,PersonName,PersonType,Enabled,Via,NestingLevel,ParentGroup,MembershipPath'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$parts = [System.Collections.Generic.List[object]]::new()
$script:writer = $null
$script:rowsInFile = 0

function Open-ReportPart {
    if ($script:writer) { $script:writer.Flush(); $script:writer.Dispose() }
    $n = $parts.Count + 1
    $final = if ($n -eq 1) { $outFile } else { $outFile -replace '\.csv$', "_part$n.csv" }
    $partial = "$final.partial"
    $script:writer = New-Object System.IO.StreamWriter($partial, $false, $utf8)
    $script:writer.WriteLine($header)
    $script:rowsInFile = 0
    $parts.Add([pscustomobject]@{ Partial = $partial; Final = $final })
}

$shareFilter = @($ShareName | Where-Object { $_ })
function Test-ShareWanted([string]$Name) {
    if ($shareFilter.Count -eq 0) { return $true }
    foreach ($w in $shareFilter) { if ($Name -like $w) { return $true } }
    $false
}

$stats = @{ Share = 0; Ntfs = 0; Rows = 0; Skipped = 0; Malformed = 0 }
$folders = @{}
$done = $false
Open-ReportPart
try {
    # emits the rows for one permission entry; $head already holds the columns up to InheritedFrom
    $emit = {
        param($Head, $Tails)
        $need = $Tails.Count
        if ($MaxRowsPerFile -gt 0 -and $script:rowsInFile -gt 0 -and ($script:rowsInFile + $need) -gt $MaxRowsPerFile) {
            Open-ReportPart
        }
        $w = $script:writer
        foreach ($t in $Tails) { $w.WriteLine($Head + ',' + $t) }
        $script:rowsInFile += $need
        $stats.Rows += $need
    }

    # --- share layer ---
    $parser = Open-CsvParser $shareCsv
    try {
        $h = $parser.ReadFields()
        if ($h) {
            $ix = Get-ColumnIndex $h @('ShareName', 'SharePath', 'Trustee', 'AccessType', 'AccessRight') $shareCsv
            while (-not $parser.EndOfData) {
                $f = $null
                try { $f = $parser.ReadFields() } catch [Microsoft.VisualBasic.FileIO.MalformedLineException] { $stats.Malformed++; continue }
                if ($null -eq $f -or $f.Length -lt $h.Length) { $stats.Malformed++; continue }
                if (-not (Test-ShareWanted $f[$ix.ShareName])) { $stats.Skipped++; continue }
                $info = Get-TrusteeInfo $f[$ix.Trustee]
                $head = Join-CsvRow @($server, 'Share', $f[$ix.ShareName], $f[$ix.SharePath], '', 'Share',
                    $f[$ix.Trustee], $info.Kind, $f[$ix.AccessType], $f[$ix.AccessRight], '', '', '', '')
                & $emit $head $info.Tails
                $stats.Share++
            }
        }
    }
    finally { $parser.Dispose() }

    # --- NTFS layer ---
    $parser = Open-CsvParser $ntfsCsv
    try {
        $h = $parser.ReadFields()
        if (-not $h) { throw "NTFS CSV is empty: $ntfsCsv" }
        $ix = Get-ColumnIndex $h @('ShareName', 'FolderPath', 'RelativePath', 'BoundaryType', 'Trustee', 'AccessType',
                                   'RightsSimple', 'RightsRaw', 'AppliesTo', 'IsInherited', 'InheritedFrom') $ntfsCsv
        $iShare = $ix.ShareName; $iFolder = $ix.FolderPath; $iRel = $ix.RelativePath; $iBound = $ix.BoundaryType
        $iTrustee = $ix.Trustee; $iType = $ix.AccessType; $iRights = $ix.RightsSimple; $iRaw = $ix.RightsRaw
        $iApplies = $ix.AppliesTo; $iInh = $ix.IsInherited; $iFrom = $ix.InheritedFrom

        $lastFolderKey = $null; $folderPart = ''
        $aceCache = @{}
        $sep = [string][char]1
        $seen = 0
        while (-not $parser.EndOfData) {
            $f = $null
            try { $f = $parser.ReadFields() } catch [Microsoft.VisualBasic.FileIO.MalformedLineException] { $stats.Malformed++; continue }
            if ($null -eq $f -or $f.Length -lt $h.Length) { $stats.Malformed++; continue }
            $seen++
            if ($seen % 100000 -eq 0) { Write-Host ("  {0:N0} NTFS rows read, {1:N0} report rows written" -f $seen, $stats.Rows) }

            if (-not (Test-ShareWanted $f[$iShare])) { $stats.Skipped++; continue }
            if ($ExplicitOnly -and $f[$iInh] -eq 'True' -and $f[$iBound] -ne 'Root') { $stats.Skipped++; continue }

            # consecutive rows are the ACL of one folder: format its columns once
            $folderKey = $f[$iFolder] + $sep + $f[$iBound] + $sep + $f[$iShare]
            if ($folderKey -ne $lastFolderKey) {
                $folderPart = Join-CsvRow @($server, 'NTFS', $f[$iShare], $f[$iFolder], $f[$iRel], $f[$iBound])
                $lastFolderKey = $folderKey
                $folders[$f[$iFolder]] = $true
            }

            $trustee = $f[$iTrustee]
            $aceKey = $trustee + $sep + $f[$iType] + $sep + $f[$iRights] + $sep + $f[$iRaw] + $sep + $f[$iApplies] + $sep + $f[$iInh] + $sep + $f[$iFrom]
            $acePart = $aceCache[$aceKey]
            $info = Get-TrusteeInfo $trustee
            if ($null -eq $acePart) {
                $acePart = Join-CsvRow @($trustee, $info.Kind, $f[$iType], $f[$iRights], $f[$iRaw], $f[$iApplies], $f[$iInh], $f[$iFrom])
                $aceCache[$aceKey] = $acePart
            }
            & $emit ($folderPart + ',' + $acePart) $info.Tails
            $stats.Ntfs++
        }
    }
    finally { $parser.Dispose() }
    $done = $true
}
finally {
    if ($script:writer) { $script:writer.Flush(); $script:writer.Dispose() }
    foreach ($p in $parts) {
        if ($done) { Move-Item -LiteralPath $p.Partial -Destination $p.Final -Force }
        else       { Remove-Item -LiteralPath $p.Partial -Force -ErrorAction SilentlyContinue }
    }
}

#endregion

#region -------------------------------------------------------------- summary

$byStatus = @{}
foreach ($kv in $trusteeCache.GetEnumerator()) {
    $k = if ($kv.Value.Kind -eq 'Group') { 'Group:' + $groups[$kv.Key].Status } else { $kv.Value.Kind }
    $byStatus[$k] = 1 + [int]$byStatus[$k]
}

Write-Host ''
Write-Host 'Access report complete.' -ForegroundColor Green
Write-Host ("  share entries    : {0:N0}" -f $stats.Share)
Write-Host ("  NTFS entries     : {0:N0} in {1:N0} folders" -f $stats.Ntfs, $folders.Count)
Write-Host ("  report rows      : {0:N0}" -f $stats.Rows)
if ($stats.Skipped -gt 0) { Write-Host ("  left out by filters: {0:N0}" -f $stats.Skipped) }
if ($stats.Malformed -gt 0) { Write-Warning ("{0:N0} malformed line(s) skipped" -f $stats.Malformed) }
Write-Host ("  trustees         : " + ((($byStatus.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0} {1}' -f $_.Name, $_.Value }) -join ', ')))
Write-Host ("  elapsed          : {0:hh\:mm\:ss}" -f $stopwatch.Elapsed)
Write-Host ''
foreach ($p in $parts) { Write-Host "  $($p.Final)" }
if ($parts.Count -gt 1) {
    Write-Host ''
    Write-Host ("Split into {0} files of up to {1:N0} rows. Use -ShareName or -ExplicitOnly for a smaller report." -f $parts.Count, $MaxRowsPerFile) -ForegroundColor Yellow
}
Write-Host ''

#endregion

$parts[0].Final
