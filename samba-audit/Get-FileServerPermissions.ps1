<#
.SYNOPSIS
    Scans local shares for NTFS permission boundaries and writes the Phase 1 CSVs.

.DESCRIPTION
    Run this ON the file server. It is strictly read-only - it never modifies an ACL,
    a share or a file.

    Rather than dumping an ACL for every folder (which produces millions of redundant
    inherited rows), it walks the whole tree but emits rows only at permission
    boundaries:

      * the share root                                  - the baseline
      * any folder that blocks inheritance              - BoundaryType 'Blocked'
      * any folder carrying a non-inherited ACE         - BoundaryType 'Explicit'

    At a boundary the COMPLETE ACL is written, inherited entries included, each tagged
    with IsInherited and InheritedFrom, so you can see the full picture at that folder
    and still filter to explicit grants.

    Output feeds New-PermissionReport.ps1, which turns it into a browsable HTML report.

.PARAMETER Path
    Scan these roots instead of auto-discovering shares.

.PARAMETER ShareName
    Restrict auto-discovery to these shares. Wildcards accepted.

.PARAMETER OutputDirectory
    Where the CSVs are written. Created if missing.

.PARAMETER MaxDepth
    Stop descending past this depth below the share root. 0 = unlimited.

.PARAMETER ThrottleLimit
    Parallel worker runspaces. ACL reads are I/O bound, so more helps up to a point.
    Use 1 to force a single-threaded scan.

.PARAMETER ExcludePrincipal
    Trustees omitted from the output. Matched against both the full account name and
    the part after the backslash. Overrides the default list entirely.

.PARAMETER IncludeGenericPrincipals
    Report every trustee, disabling the exclusion list.

.PARAMETER ListSharesOnly
    Dry run. Lists what WOULD be scanned - shares, paths, share ACLs, top-level folder
    counts and accessibility - then exits without walking any tree. Run this first.

.PARAMETER Resume
    Continue a previous run, skipping work items already recorded as complete and
    appending to the existing CSVs.

.EXAMPLE
    .\Get-FileServerPermissions.ps1 -ListSharesOnly
    Confirm the target list before committing to a full crawl.

.EXAMPLE
    .\Get-FileServerPermissions.ps1 -OutputDirectory D:\Reports
    Scan every non-special share.

.EXAMPLE
    .\Get-FileServerPermissions.ps1 -Path E:\Shares\Finance -MaxDepth 6 -ThrottleLimit 16

.EXAMPLE
    .\Get-FileServerPermissions.ps1 -Resume
    Pick up where an interrupted scan left off.

.NOTES
    Requires: PowerShell 5.1+ (Windows Server 2016+ stock). No modules beyond SmbShare,
    which falls back to WMI when unavailable.
    Run as an account that can read ACLs everywhere - typically a member of the local
    Administrators group or Backup Operators. Folders it cannot read are logged to the
    error CSV rather than aborting the scan.
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [string[]]$ShareName,
    [string]  $OutputDirectory = (Join-Path $PSScriptRoot 'Reports'),
    [int]     $MaxDepth = 0,
    [ValidateRange(1, 64)][int]$ThrottleLimit = 8,
    [string[]]$ExcludePrincipal,
    [switch]  $IncludeGenericPrincipals,
    [switch]  $ListSharesOnly,
    [switch]  $Resume
)

$ErrorActionPreference = 'Stop'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$Server    = $env:COMPUTERNAME
$scanStamp = (Get-Date).ToString('s')

$DefaultExclude = @(
    'NT AUTHORITY\SYSTEM'
    'CREATOR OWNER'
    'BUILTIN\Administrators'
    'Domain Admins'
    'NT SERVICE\TrustedInstaller'
    'BUILTIN\Server Operators'
)
$excludeList = if ($IncludeGenericPrincipals) { @() }
               elseif ($ExcludePrincipal)     { $ExcludePrincipal }
               else                            { $DefaultExclude }

#region -------------------------------------------------------- share discovery

function Get-TargetShare {
    $result = [System.Collections.Generic.List[object]]::new()

    if ($Path) {
        foreach ($p in $Path) {
            if (-not (Test-Path -LiteralPath $p)) {
                Write-Warning "Path not found, skipping: $p"
                continue
            }
            $full = (Resolve-Path -LiteralPath $p).ProviderPath.TrimEnd('\')
            # if this path is (or sits under) a real share, borrow that share's name
            $match = $null
            try {
                $match = Get-SmbShare -ErrorAction Stop | Where-Object {
                    -not $_.Special -and $_.Path -and
                    ($full -eq $_.Path.TrimEnd('\') -or $full.StartsWith($_.Path.TrimEnd('\') + '\', 'OrdinalIgnoreCase'))
                } | Select-Object -First 1
            } catch { }
            $result.Add([pscustomobject]@{
                Name        = if ($match) { $match.Name } else { Split-Path $full -Leaf }
                Path        = $full
                Description = if ($match) { $match.Description } else { 'Explicit -Path target' }
                IsRealShare = [bool]$match
            })
        }
        return $result
    }

    $shares = $null
    try {
        $shares = Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special }
    } catch {
        Write-Verbose "SmbShare module unavailable, falling back to WMI."
        $shares = Get-CimInstance -ClassName Win32_Share -ErrorAction Stop |
            Where-Object { $_.Type -eq 0 } |
            ForEach-Object { [pscustomobject]@{ Name = $_.Name; Path = $_.Path; Description = $_.Description } }
    }

    foreach ($s in $shares) {
        if ($s.Name -in @('NETLOGON', 'SYSVOL')) { continue }
        if (-not $s.Path) { continue }
        if ($ShareName -and -not ($ShareName | Where-Object { $s.Name -like $_ })) { continue }
        $result.Add([pscustomobject]@{
            Name = $s.Name; Path = $s.Path.TrimEnd('\'); Description = $s.Description; IsRealShare = $true
        })
    }
    $result
}

function Get-ShareAccessRow {
    param([object]$Share)
    if (-not $Share.IsRealShare) { return @() }
    try {
        Get-SmbShareAccess -Name $Share.Name -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Server = $Server; ShareName = $Share.Name; SharePath = $Share.Path
                Description = $Share.Description
                Trustee = $_.AccountName
                AccessType = [string]$_.AccessControlType
                AccessRight = [string]$_.AccessRight
                ScanTimestamp = $scanStamp
            }
        }
    } catch {
        Write-Warning "Could not read share ACL for '$($Share.Name)': $($_.Exception.Message)"
        @()
    }
}

$targets = Get-TargetShare
if (-not $targets -or $targets.Count -eq 0) { throw "No shares or paths to scan." }

#endregion

#region ------------------------------------------------------------- dry run

if ($ListSharesOnly) {
    Write-Host ""
    Write-Host "Targets that WOULD be scanned on $Server" -ForegroundColor Cyan
    Write-Host ("-" * 78)
    foreach ($t in $targets) {
        $topCount = $null; $readable = $true; $note = ''
        try {
            $topCount = ([System.IO.Directory]::EnumerateDirectories($t.Path)  | Measure-Object).Count
        } catch { $readable = $false; $note = $_.Exception.Message }

        Write-Host ("{0,-22} {1}" -f $t.Name, $t.Path) -ForegroundColor White
        if ($readable) {
            Write-Host ("{0,-22} {1:N0} top-level folders" -f '', $topCount) -ForegroundColor DarkGray
        } else {
            Write-Host ("{0,-22} UNREADABLE - {1}" -f '', $note) -ForegroundColor Red
        }
        foreach ($a in (Get-ShareAccessRow $t)) {
            Write-Host ("{0,-22} share ACL: {1} = {2} ({3})" -f '', $a.Trustee, $a.AccessRight, $a.AccessType) -ForegroundColor DarkGray
        }
    }
    Write-Host ("-" * 78)
    Write-Host ("{0} target(s). Excluded trustees: {1}" -f $targets.Count,
        $(if ($excludeList) { $excludeList -join ', ' } else { '(none - reporting everything)' }))
    Write-Host ""
    Write-Host "Top-level counts only - the full crawl descends the entire tree." -ForegroundColor Yellow
    Write-Host "Re-run without -ListSharesOnly to scan." -ForegroundColor Yellow
    return
}

#endregion

#region ------------------------------------------------------------- worker

# Runs inside each runspace. Self-contained: everything it needs is defined here,
# because runspaces do not inherit the caller's functions.
$WorkerScript = {
    param($Job, $Cfg, $Queue, $ErrQueue, $Counters)

    $ACC = [System.Security.AccessControl.AccessControlSections]::Access
    $OWN = [System.Security.AccessControl.AccessControlSections]::Owner
    $SID = [System.Security.Principal.SecurityIdentifier]
    $sidCache = @{}

    function ConvertTo-LongPath([string]$p) {
        if ($p.StartsWith('\\?\')) { return $p }
        if ($p.StartsWith('\\'))   { return '\\?\UNC\' + $p.Substring(2) }
        '\\?\' + $p
    }
    function Format-CsvField($v) {
        $s = if ($null -eq $v) { '' } else { [string]$v }
        if ($s.IndexOfAny([char[]]@(',', '"', "`r", "`n")) -ge 0) { '"' + $s.Replace('"', '""') + '"' } else { $s }
    }
    function Get-DirSecurity([System.IO.DirectoryInfo]$d, $sections) {
        if ($Cfg.UseAclExt) { [System.IO.FileSystemAclExtensions]::GetAccessControl($d, $sections) }
        else                { $d.GetAccessControl($sections) }
    }
    function Resolve-Sid($ref) {
        $key = $ref.Value
        if ($sidCache.ContainsKey($key)) { return $sidCache[$key] }
        $out = try {
            @{ Name = $ref.Translate([System.Security.Principal.NTAccount]).Value; Resolved = $true }
        } catch {
            @{ Name = $key; Resolved = $false }
        }
        $sidCache[$key] = $out
        $out
    }
    function Get-SimpleRights([int]$v) {
        # generic rights first - they show up as large negative integers
        if ($v -band 0x10000000) { return 'FullControl' }         # GENERIC_ALL
        if (($v -band 2032127) -eq 2032127) { return 'FullControl' }
        if (($v -band 197055)  -eq 197055)  { return 'Modify' }
        $canRead  = ($v -band 131209) -eq 131209
        $canWrite = ($v -band 278)    -eq 278
        $canExec  = ($v -band 32)     -eq 32
        if ($canRead -and $canWrite -and $canExec) { return 'ReadWriteNoDelete' }
        if ($canRead -and $canExec)  { return 'ReadExecute' }
        if ($canRead)                { return 'ReadExecute' }
        if ($canWrite)               { return 'Write' }
        if ($v -band 1)              { return 'ListOnly' }
        'Special'
    }
    function Get-AppliesTo($inheritFlags, $propFlags) {
        $c = ($inheritFlags -band 1) -ne 0   # ContainerInherit
        $o = ($inheritFlags -band 2) -ne 0   # ObjectInherit
        $io = ($propFlags -band 2) -ne 0     # InheritOnly
        $np = ($propFlags -band 1) -ne 0     # NoPropagateInherit
        $t = if (-not $c -and -not $o) { 'This folder only' }
             elseif ($c -and $o -and -not $io) { 'This folder, subfolders and files' }
             elseif ($c -and $o -and $io)      { 'Subfolders and files only' }
             elseif ($c -and -not $io)         { 'This folder and subfolders' }
             elseif ($c -and $io)              { 'Subfolders only' }
             elseif ($o -and -not $io)         { 'This folder and files' }
             else                              { 'Files only' }
        if ($np) { "$t (this level only)" } else { $t }
    }
    function Test-Excluded([string]$account) {
        if (-not $Cfg.Exclude -or $Cfg.Exclude.Count -eq 0) { return $false }
        $leaf = $account
        $k = $account.LastIndexOf('\')
        if ($k -ge 0) { $leaf = $account.Substring($k + 1) }
        foreach ($e in $Cfg.Exclude) {
            if ($account -eq $e -or $leaf -eq $e) { return $true }
            $ek = $e.LastIndexOf('\')
            if ($ek -ge 0 -and $leaf -eq $e.Substring($ek + 1)) { return $true }
        }
        $false
    }

    $localCount = 0
    # stack frames: display path, relative path, depth, nearest ancestor boundary
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push(@{ P = $Job.Start; Rel = $Job.Rel; D = $Job.Depth; From = $Job.From })

    while ($stack.Count -gt 0) {
        $f = $stack.Pop()
        $localCount++

        $di = $null; $sec = $null
        try {
            $di  = New-Object System.IO.DirectoryInfo((ConvertTo-LongPath $f.P))
            $sec = Get-DirSecurity $di $ACC
        } catch {
            $ErrQueue.Enqueue((@(
                $Cfg.Server, $f.P,
                $(if ($_.Exception -is [System.UnauthorizedAccessException]) { 'AccessDenied' }
                  elseif ($_.Exception -is [System.IO.PathTooLongException]) { 'PathTooLong' }
                  elseif ($_.Exception -is [System.IO.DirectoryNotFoundException]) { 'NotFound' }
                  else { 'IOError' }),
                $_.Exception.Message, $Cfg.Stamp
            ) | ForEach-Object { Format-CsvField $_ }) -join ',')
            continue
        }

        $protected = $sec.AreAccessRulesProtected
        $rules = @($sec.GetAccessRules($true, $true, $SID))
        $hasExplicit = $false
        foreach ($r in $rules) { if (-not $r.IsInherited) { $hasExplicit = $true; break } }

        $isRoot = ($f.Rel -eq '' -and $Job.IsRoot)
        $isBoundary = $isRoot -or $protected -or $hasExplicit

        if ($isBoundary) {
            $bType = if ($isRoot) { 'Root' } elseif ($protected) { 'Blocked' } else { 'Explicit' }

            $owner = ''
            try   { $owner = (Get-DirSecurity $di ($ACC -bor $OWN)).GetOwner([System.Security.Principal.NTAccount]).Value }
            catch { try { $owner = $sec.GetOwner($SID).Value } catch { $owner = '' } }

            $depth = if ($f.Rel) { ($f.Rel -split '\\').Count } else { 0 }
            $emitted = 0

            foreach ($r in $rules) {
                $acct = Resolve-Sid $r.IdentityReference
                if (Test-Excluded $acct.Name) { continue }

                $dom = ''; $nm = $acct.Name
                $k = $nm.IndexOf('\')
                if ($k -ge 0) { $dom = $nm.Substring(0, $k); $nm = $nm.Substring($k + 1) }

                $rv = [int]$r.FileSystemRights
                $Queue.Enqueue((@(
                    $Cfg.Server, $Job.ShareName, $Job.SharePath, $f.P, $f.Rel, $depth,
                    $bType, $protected, $owner,
                    $acct.Name, $dom, $nm, $acct.Resolved,
                    [string]$r.AccessControlType,
                    (Get-SimpleRights $rv), [string]$r.FileSystemRights,
                    $r.IsInherited, $(if ($r.IsInherited) { $f.From } else { '' }),
                    (Get-AppliesTo ([int]$r.InheritanceFlags) ([int]$r.PropagationFlags)),
                    $Cfg.Stamp
                ) | ForEach-Object { Format-CsvField $_ }) -join ',')
                $emitted++
            }

            # a boundary whose every ACE was filtered still matters - record that it exists
            if ($emitted -eq 0) {
                $Queue.Enqueue((@(
                    $Cfg.Server, $Job.ShareName, $Job.SharePath, $f.P, $f.Rel, $depth,
                    $bType, $protected, $owner,
                    '(all trustees filtered)', '', '(all trustees filtered)', $true,
                    'Allow', 'Special', '', $false, '', '', $Cfg.Stamp
                ) | ForEach-Object { Format-CsvField $_ }) -join ',')
            }
        }

        # descend
        # the share-root work item covers the root only; its children are separate
        # work items, so descending here would scan the whole tree twice
        if ($Job.RootOnly) { continue }
        if ($Cfg.MaxDepth -gt 0 -and $f.D -ge $Cfg.MaxDepth) { continue }
        try {
            foreach ($sub in [System.IO.Directory]::EnumerateDirectories((ConvertTo-LongPath $f.P))) {
                $name = [System.IO.Path]::GetFileName($sub)
                $childDisplay = $f.P.TrimEnd('\') + '\' + $name
                try {
                    $attr = [System.IO.File]::GetAttributes($sub)
                    if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }  # junction / symlink
                } catch { }
                $stack.Push(@{
                    P    = $childDisplay
                    Rel  = if ($f.Rel) { "$($f.Rel)\$name" } else { $name }
                    D    = $f.D + 1
                    From = if ($isBoundary) { $f.Rel } else { $f.From }
                })
            }
        } catch {
            $ErrQueue.Enqueue((@(
                $Cfg.Server, $f.P,
                $(if ($_.Exception -is [System.UnauthorizedAccessException]) { 'AccessDenied' } else { 'IOError' }),
                $_.Exception.Message, $Cfg.Stamp
            ) | ForEach-Object { Format-CsvField $_ }) -join ',')
        }

        if ($localCount -ge 500) {
            [System.Threading.Monitor]::Enter($Counters.SyncRoot)
            try { $Counters.Folders += $localCount } finally { [System.Threading.Monitor]::Exit($Counters.SyncRoot) }
            $localCount = 0
        }
    }

    [System.Threading.Monitor]::Enter($Counters.SyncRoot)
    try { $Counters.Folders += $localCount; $Counters.Done++ } finally { [System.Threading.Monitor]::Exit($Counters.SyncRoot) }
}

#endregion

#region --------------------------------------------------------------- setup

if (-not (Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

$stateFile = Join-Path $OutputDirectory ".scanstate_$Server.json"
$state = $null
if ($Resume -and (Test-Path $stateFile)) {
    $state = Get-Content $stateFile -Raw | ConvertFrom-Json
    Write-Host "Resuming previous scan ($($state.Completed.Count) work items already done)." -ForegroundColor Yellow
}

$stampDate = (Get-Date).ToString('yyyyMMdd')
$ntfsCsv  = if ($state) { $state.NtfsCsv }  else { Join-Path $OutputDirectory "NTFS_Permissions_${Server}_${stampDate}.csv" }
$shareCsv = if ($state) { $state.ShareCsv } else { Join-Path $OutputDirectory "Share_Permissions_${Server}_${stampDate}.csv" }
$errCsv   = if ($state) { $state.ErrorCsv } else { Join-Path $OutputDirectory "Scan_Errors_${Server}_${stampDate}.csv" }

$completed = New-Object System.Collections.Generic.HashSet[string]
if ($state) { foreach ($c in $state.Completed) { [void]$completed.Add($c) } }

# share-level ACLs (rewritten in full each run - cheap)
if (-not $Resume -or -not (Test-Path $shareCsv)) {
    $shareRows = foreach ($t in $targets) { Get-ShareAccessRow $t }
    if ($shareRows) { $shareRows | Export-Csv -Path $shareCsv -NoTypeInformation -Encoding UTF8 }
    else { 'Server,ShareName,SharePath,Description,Trustee,AccessType,AccessRight,ScanTimestamp' |
             Set-Content -Path $shareCsv -Encoding UTF8 }
}

$append = $Resume -and (Test-Path $ntfsCsv)
$enc = [System.Text.UTF8Encoding]::new($false)
$ntfsWriter = [System.IO.StreamWriter]::new($ntfsCsv, $append, $enc)
$errWriter  = [System.IO.StreamWriter]::new($errCsv,  $append, $enc)
if (-not $append) {
    $ntfsWriter.WriteLine('Server,ShareName,SharePath,FolderPath,RelativePath,Depth,BoundaryType,InheritanceBroken,Owner,Trustee,TrusteeDomain,TrusteeName,SidResolved,AccessType,RightsSimple,RightsRaw,IsInherited,InheritedFrom,AppliesTo,ScanTimestamp')
    $errWriter.WriteLine('Server,Path,ErrorType,Message,ScanTimestamp')
}

# build work items: the share root, then one per top-level subfolder
$jobs = [System.Collections.Generic.List[object]]::new()
foreach ($t in $targets) {
    $rootKey = "$($t.Name)|<root>"
    if (-not $completed.Contains($rootKey)) {
        $jobs.Add([pscustomobject]@{
            Key = $rootKey; ShareName = $t.Name; SharePath = $t.Path
            Start = $t.Path; Rel = ''; Depth = 0; From = ''; IsRoot = $true; RootOnly = $true
        })
    }
    try {
        foreach ($sub in [System.IO.Directory]::EnumerateDirectories($t.Path)) {
            $name = [System.IO.Path]::GetFileName($sub)
            $key = "$($t.Name)|$name"
            if ($completed.Contains($key)) { continue }
            $jobs.Add([pscustomobject]@{
                Key = $key; ShareName = $t.Name; SharePath = $t.Path
                Start = $t.Path.TrimEnd('\') + '\' + $name; Rel = $name; Depth = 1; From = ''
                IsRoot = $false; RootOnly = $false
            })
        }
    } catch {
        $errWriter.WriteLine(('{0},{1},{2},{3},{4}' -f $Server, $t.Path, 'AccessDenied',
            '"' + $_.Exception.Message.Replace('"','""') + '"', $scanStamp))
    }
}

Write-Host ""
Write-Host "Scanning $($targets.Count) target(s) on $Server" -ForegroundColor Cyan
Write-Host ("  work items   : {0:N0}" -f $jobs.Count)
Write-Host ("  parallelism  : {0}" -f $ThrottleLimit)
Write-Host ("  max depth    : {0}" -f $(if ($MaxDepth -gt 0) { $MaxDepth } else { 'unlimited' }))
Write-Host ("  excluding    : {0}" -f $(if ($excludeList) { $excludeList -join ', ' } else { '(nothing)' }))
Write-Host ""

#endregion

#region ----------------------------------------------------------- run scan

$cfg = @{
    Server   = $Server
    Stamp    = $scanStamp
    MaxDepth = $MaxDepth
    Exclude  = $excludeList
    UseAclExt = ($null -ne ([System.Management.Automation.PSTypeName]'System.IO.FileSystemAclExtensions').Type)
}

$queue    = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$errQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$counters = [hashtable]::Synchronized(@{ Folders = 0; Done = 0 })

$pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
$pool.Open()
$handles = [System.Collections.Generic.List[object]]::new()

foreach ($j in $jobs) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($WorkerScript).AddArgument($j).AddArgument($cfg).
        AddArgument($queue).AddArgument($errQueue).AddArgument($counters)
    $handles.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Job = $j; Drained = $false })
}

$rowsWritten = 0; $errWritten = 0
$doneKeys = [System.Collections.Generic.List[string]]::new()
if ($state) { foreach ($c in $state.Completed) { $doneKeys.Add($c) } }

function Save-State {
    @{
        NtfsCsv = $ntfsCsv; ShareCsv = $shareCsv; ErrorCsv = $errCsv
        Completed = @($doneKeys); Updated = (Get-Date).ToString('s')
    } | ConvertTo-Json -Depth 3 | Set-Content -Path $stateFile -Encoding UTF8
}

$line = $null
$lastSave = [datetime]::Now
while ($true) {
    while ($queue.TryDequeue([ref]$line))    { $ntfsWriter.WriteLine($line); $rowsWritten++ }
    while ($errQueue.TryDequeue([ref]$line)) { $errWriter.WriteLine($line);  $errWritten++ }

    $finished = 0
    foreach ($h in $handles) {
        if ($h.Handle.IsCompleted) {
            $finished++
            if (-not $h.Drained) {
                $h.Drained = $true
                try { $h.PS.EndInvoke($h.Handle) } catch {
                    Write-Warning "Worker for '$($h.Job.Key)' failed: $($_.Exception.Message)"
                }
                $h.PS.Dispose()
                $doneKeys.Add($h.Job.Key)
            }
        }
    }

    Write-Progress -Activity "Scanning permissions on $Server" `
        -Status ("{0:N0} folders  |  {1:N0} boundary rows  |  {2}/{3} work items" -f `
            $counters.Folders, $rowsWritten, $finished, $handles.Count) `
        -PercentComplete ([math]::Min(100, [int](100 * $finished / [math]::Max(1, $handles.Count))))

    if (([datetime]::Now - $lastSave).TotalSeconds -ge 30) {
        $ntfsWriter.Flush(); $errWriter.Flush(); Save-State; $lastSave = [datetime]::Now
    }
    if ($finished -eq $handles.Count) { break }
    Start-Sleep -Milliseconds 250
}

# final drain
while ($queue.TryDequeue([ref]$line))    { $ntfsWriter.WriteLine($line); $rowsWritten++ }
while ($errQueue.TryDequeue([ref]$line)) { $errWriter.WriteLine($line);  $errWritten++ }

$ntfsWriter.Flush(); $ntfsWriter.Dispose()
$errWriter.Flush();  $errWriter.Dispose()
$pool.Close(); $pool.Dispose()
Write-Progress -Activity "Scanning permissions on $Server" -Completed

if (Test-Path $stateFile) { Remove-Item $stateFile -Force }

#endregion

#region -------------------------------------------------------------- summary

Write-Host ""
Write-Host "Scan complete." -ForegroundColor Green
Write-Host ("  folders walked : {0:N0}" -f $counters.Folders)
Write-Host ("  boundary rows  : {0:N0}" -f $rowsWritten)
Write-Host ("  errors logged  : {0:N0}" -f $errWritten)
Write-Host ("  elapsed        : {0:hh\:mm\:ss}" -f $stopwatch.Elapsed)
Write-Host ""
Write-Host "  $ntfsCsv"
Write-Host "  $shareCsv"
Write-Host "  $errCsv"
Write-Host ""
if ($errWritten -gt 0) {
    Write-Host "Some folders could not be read - review the error CSV. Those folders'" -ForegroundColor Yellow
    Write-Host "permissions are NOT in this report." -ForegroundColor Yellow
    Write-Host ""
}
Write-Host "Next:" -ForegroundColor Cyan
Write-Host "  .\New-PermissionReport.ps1 -InputDirectory '$OutputDirectory' -Open"

#endregion
