<#
.SYNOPSIS
    Offline tests for New-AccessReport.ps1. Runs the real script over small made-up CSVs.

    Run:  pwsh -File tests\Test-NewAccessReport.ps1      (or powershell.exe -File ...)
#>
$ErrorActionPreference = 'Stop'
$script = (Resolve-Path (Join-Path $PSScriptRoot '..\New-AccessReport.ps1')).Path
$ps = (Get-Process -Id $PID).Path

$script:failed = 0; $script:passed = 0
function Assert-Equal($Actual, $Expected, [string]$Name) {
    if ("$Actual" -ceq "$Expected") { $script:passed++; return }
    $script:failed++
    Write-Host "FAIL  $Name" -ForegroundColor Red
    Write-Host "      expected: $Expected"
    Write-Host "      actual  : $Actual"
}

function Invoke-Report {
    param([string[]]$Arguments)
    $out = & $ps -NoProfile -File $script @Arguments 2>&1 | Out-String
    [pscustomobject]@{ Code = $LASTEXITCODE; Text = $out }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("accrep-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $enc = New-Object System.Text.UTF8Encoding($true)

    # --- made-up export set -------------------------------------------------------
    $members = @(
        'Server,Group,GroupSid,GroupScope,GroupStatus,MemberType,Member,MemberSid,DisplayName,UserPrincipalName,Enabled,NestingLevel,ParentGroup,MembershipPath,Note,ScanTimestamp'
        'SRV020,HQ\GrpA,S-1,Global,Expanded,User,HQ\u1,S-11,Ján Novák,u1@hq,True,1,HQ\GrpA,HQ\GrpA,,2026-10-08T10:00:00'
        'SRV020,HQ\GrpA,S-1,Global,Expanded,Group,HQ\GrpB,S-2,GrpB,,,1,HQ\GrpA,HQ\GrpA,,2026-10-08T10:00:00'
        'SRV020,HQ\GrpA,S-1,Global,Expanded,User,HQ\u2,S-12,"Peter, ""Petrov""",u2@hq,False,1,HQ\GrpA,HQ\GrpA,,2026-10-08T10:00:00'
        'SRV020,HQ\GrpA,S-1,Global,Expanded,User,HQ\u3,S-13,Žofia Šťastná,u3@hq,True,2,HQ\GrpB,HQ\GrpA > HQ\GrpB,,2026-10-08T10:00:00'
        'SRV020,HQ\GrpEmpty,S-3,Global,Empty,,,,,,,,,,,2026-10-08T10:00:00'
        'SRV020,HQ\GrpGhost,,,NotFound,,,,,,,,,,No such account,2026-10-08T10:00:00'
    )
    [System.IO.File]::WriteAllLines((Join-Path $tmp 'AD_Group_Members_SRV020_20260825.csv'), $members, (New-Object System.Text.UTF8Encoding($false)))

    $share = @(
        'Server,ShareName,SharePath,Description,Trustee,AccessType,AccessRight,ScanTimestamp'
        'SRV020,Data,E:\Data,,HQ\GrpA,Allow,Change,2026-08-25T10:00:00'
        'SRV020,Data,E:\Data,,Everyone,Allow,Full,2026-08-25T10:00:00'
        'SRV020,Priv,E:\Priv,,HQ\GrpEmpty,Allow,Read,2026-08-25T10:00:00'
    )
    [System.IO.File]::WriteAllLines((Join-Path $tmp 'Share_Permissions_SRV020_20260825.csv'), $share, $enc)

    $hdr = 'Server,ShareName,SharePath,FolderPath,RelativePath,Depth,BoundaryType,InheritanceBroken,Owner,Trustee,TrusteeDomain,TrusteeName,SidResolved,AccessType,RightsSimple,RightsRaw,IsInherited,InheritedFrom,AppliesTo,ScanTimestamp'
    function N($share, $folder, $rel, $bound, $trustee, $type, $rights, $raw, $inh) {
        $f = { param($v) Format-Cell $v }
        '{0},{1},E:\{1},{2},{3},1,{4},False,HQ\admin,{5},,,True,{6},{7},{8},{9},,This folder,2026-08-25T10:00:00' -f
            'SRV020', $share, (Format-Cell $folder), (Format-Cell $rel), $bound, (Format-Cell $trustee), $type, $rights, (Format-Cell $raw), $inh
    }
    function Format-Cell($v) { if ($v -match '[,"]') { '"' + $v.Replace('"', '""') + '"' } else { $v } }
    $ntfs = @(
        $hdr
        (N 'Data' 'E:\Data' '' 'Root' 'HQ\GrpA' 'Allow' 'Modify' 'Modify, Synchronize' 'True')
        (N 'Data' 'E:\Data' '' 'Root' 'BUILTIN\Users' 'Allow' 'ReadExecute' 'ReadAndExecute' 'True')
        (N 'Data' 'E:\Data' '' 'Root' 'HQ\u1' 'Allow' 'Modify' 'Modify' 'True')
        (N 'Data' 'E:\Data\Folder X' 'Folder X' 'Explicit' 'HQ\GrpA' 'Allow' 'Modify' 'Modify' 'False')
        (N 'Data' 'E:\Data\Folder X' 'Folder X' 'Explicit' 'HQ\GrpA' 'Allow' 'ReadExecute' 'ReadAndExecute' 'True')
        (N 'Data' 'E:\Data\Folder X' 'Folder X' 'Explicit' 'HQ\GrpEmpty' 'Allow' 'Modify' 'Modify' 'False')
        (N 'Data' 'E:\Data\Folder X' 'Folder X' 'Explicit' 'HQ\GrpGhost' 'Allow' 'Modify' 'Modify' 'False')
        (N 'Data' 'E:\Data\Folder X' 'Folder X' 'Explicit' 'HQ\old' 'Allow' 'Modify' 'Modify' 'False')
        (N 'Data' 'E:\Data\Folder X' 'Folder X' 'Explicit' 'OTHERDOM\bob' 'Allow' 'Modify' 'Modify' 'False')
        (N 'Data' 'E:\Data\Plan, "Q3"' 'Plan, "Q3"' 'Explicit' 'HQ\GrpA' 'Deny' 'Write' 'Write' 'False')
        (N 'Priv' 'E:\Priv' '' 'Root' 'HQ\GrpEmpty' 'Allow' 'Modify' 'Modify' 'True')
    )
    [System.IO.File]::WriteAllLines((Join-Path $tmp 'NTFS_Permissions_SRV020_20260825.csv'), $ntfs, $enc)

    $expectedHeader = 'Server,Layer,ShareName,FolderPath,RelativePath,BoundaryType,Trustee,TrusteeKind,AccessType,Rights,RightsDetail,AppliesTo,IsInherited,InheritedFrom,GroupStatus,Person,PersonName,PersonType,Enabled,Via,NestingLevel,ParentGroup,MembershipPath'
    $outFile = Join-Path $tmp 'Access_Report_SRV020_20260825.csv'

    # --- full report ---------------------------------------------------------------
    $r = Invoke-Report @('-InputDirectory', $tmp)
    Assert-Equal $r.Code 0 'full: exit code'
    if ($r.Code -ne 0) { Write-Host $r.Text }
    Assert-Equal (Test-Path $outFile) $true 'full: report written'
    Assert-Equal (@(Get-ChildItem $tmp -Filter '*.partial').Count) 0 'full: no .partial left'
    Assert-Equal (Get-Content -LiteralPath $outFile -TotalCount 1) $expectedHeader 'full: header'
    $rows = @(Import-Csv -LiteralPath $outFile -Encoding UTF8)
    Assert-Equal $rows.Count 24 'full: row count (5 share + 19 NTFS)'
    Assert-Equal @($rows | Where-Object Layer -eq 'Share').Count 5 'full: share rows'

    $a = @($rows | Where-Object { $_.Layer -eq 'Share' -and $_.Trustee -eq 'HQ\GrpA' })
    Assert-Equal $a.Count 3 'share: group entry expands to 3 people'
    Assert-Equal $a[0].Rights 'Change' 'share: right carried'
    $u3 = $rows | Where-Object { $_.Layer -eq 'Share' -and $_.Person -eq 'HQ\u3' }
    Assert-Equal $u3.Via 'NestedGroup' 'nested member: Via'
    Assert-Equal $u3.NestingLevel 2 'nested member: level'
    Assert-Equal $u3.MembershipPath 'HQ\GrpA > HQ\GrpB' 'nested member: path'
    Assert-Equal $u3.ParentGroup 'HQ\GrpB' 'nested member: parent'
    Assert-Equal $u3.PersonName 'Žofia Šťastná' 'diacritics survive'
    $u2 = $rows | Where-Object { $_.Layer -eq 'Share' -and $_.Person -eq 'HQ\u2' }
    Assert-Equal $u2.PersonName 'Peter, "Petrov"' 'comma and quotes in a name survive'
    Assert-Equal $u2.Enabled 'False' 'disabled account flagged'
    Assert-Equal $u2.Via 'Group' 'direct group member: Via'

    $every = $rows | Where-Object { $_.Layer -eq 'Share' -and $_.Trustee -eq 'Everyone' }
    Assert-Equal $every.TrusteeKind 'Other' 'Everyone: kind Other'
    Assert-Equal $every.GroupStatus 'NotExpanded' 'Everyone: not expanded'
    Assert-Equal $every.Person '' 'Everyone: no person invented'

    $empty = @($rows | Where-Object { $_.Layer -eq 'Share' -and $_.Trustee -eq 'HQ\GrpEmpty' })
    Assert-Equal $empty.Count 1 'empty group: one visible row'
    Assert-Equal $empty[0].GroupStatus 'Empty' 'empty group: status'
    Assert-Equal $empty[0].Person '' 'empty group: no person'

    $ghost = @($rows | Where-Object { $_.Trustee -eq 'HQ\GrpGhost' })
    Assert-Equal $ghost[0].GroupStatus 'NotFound' 'missing group: status'
    Assert-Equal $ghost[0].TrusteeKind 'Group' 'missing group: still a group'

    $direct = @($rows | Where-Object { $_.Layer -eq 'NTFS' -and $_.Trustee -eq 'HQ\u1' })
    Assert-Equal $direct.Count 1 'direct user: one row'
    Assert-Equal $direct[0].Via 'Direct' 'direct user: Via'
    Assert-Equal $direct[0].PersonName 'Ján Novák' 'direct user: name looked up from membership file'
    $old = $rows | Where-Object { $_.Trustee -eq 'HQ\old' }
    Assert-Equal $old.TrusteeKind 'User' 'unknown account in a known domain: User'
    Assert-Equal $old.Person 'HQ\old' 'unknown account: person is the trustee'
    $bob = $rows | Where-Object { $_.Trustee -eq 'OTHERDOM\bob' }
    Assert-Equal $bob.TrusteeKind 'Other' 'account in an unknown domain: Other'
    $bu = $rows | Where-Object { $_.Trustee -eq 'BUILTIN\Users' }
    Assert-Equal $bu.TrusteeKind 'Other' 'BUILTIN: Other'

    $plan = @($rows | Where-Object { $_.Layer -eq 'NTFS' -and $_.RelativePath -eq 'Plan, "Q3"' })
    Assert-Equal $plan.Count 3 'folder with comma and quotes: rows'
    Assert-Equal $plan[0].FolderPath 'E:\Data\Plan, "Q3"' 'folder with comma and quotes: path round-trips'
    Assert-Equal $plan[0].AccessType 'Deny' 'Deny preserved'
    $mod = $rows | Where-Object { $_.Layer -eq 'NTFS' -and $_.Trustee -eq 'HQ\GrpA' -and $_.RelativePath -eq '' } | Select-Object -First 1
    Assert-Equal $mod.RightsDetail 'Modify, Synchronize' 'raw rights with comma survive'
    Assert-Equal $mod.BoundaryType 'Root' 'boundary type carried'
    Assert-Equal @($rows | Where-Object { $_.Layer -eq 'NTFS' -and $_.RelativePath -eq 'Folder X' -and $_.Trustee -eq 'HQ\GrpA' -and $_.IsInherited -eq 'True' }).Count 3 'inherited entry kept by default'
    Assert-Equal ($r.Text -match 'report rows\s+: 24') $true 'full: summary reports 24 rows'

    # --- filters -------------------------------------------------------------------
    Remove-Item $outFile
    $r = Invoke-Report @('-InputDirectory', $tmp, '-ExplicitOnly')
    $rows = @(Import-Csv -LiteralPath $outFile -Encoding UTF8)
    Assert-Equal $rows.Count 21 'ExplicitOnly: row count'
    Assert-Equal @($rows | Where-Object { $_.Layer -eq 'NTFS' -and $_.IsInherited -eq 'True' -and $_.BoundaryType -ne 'Root' }).Count 0 'ExplicitOnly: no inherited non-root entries'
    Assert-Equal @($rows | Where-Object { $_.BoundaryType -eq 'Root' -and $_.Trustee -eq 'HQ\GrpA' }).Count 3 'ExplicitOnly: share root kept in full'

    Remove-Item $outFile
    $r = Invoke-Report @('-InputDirectory', $tmp, '-ShareName', 'Priv')
    $rows = @(Import-Csv -LiteralPath $outFile -Encoding UTF8)
    Assert-Equal $rows.Count 2 'ShareName filter: row count'
    Assert-Equal (@($rows.ShareName | Select-Object -Unique) -join ',') 'Priv' 'ShareName filter: only that share'

    # --- splitting -----------------------------------------------------------------
    Remove-Item (Join-Path $tmp 'Access_Report_*') -Force
    $r = Invoke-Report @('-InputDirectory', $tmp, '-MaxRowsPerFile', '10')
    $files = @(Get-ChildItem $tmp -Filter 'Access_Report_SRV020_20260825*.csv' | Sort-Object Name)
    Assert-Equal ($files.Count -gt 1) $true 'split: several files'
    $total = 0
    foreach ($f in $files) {
        $n = @(Import-Csv -LiteralPath $f.FullName -Encoding UTF8).Count
        $total += $n
        Assert-Equal ($n -le 10) $true "split: $($f.Name) within limit ($n rows)"
        Assert-Equal (Get-Content -LiteralPath $f.FullName -TotalCount 1) $expectedHeader "split: $($f.Name) has header"
    }
    Assert-Equal $total 24 'split: no row lost or duplicated'
    Assert-Equal ($files[1].Name) 'Access_Report_SRV020_20260825_part2.csv' 'split: part naming'

    # --- explicit files and errors -------------------------------------------------
    Remove-Item (Join-Path $tmp 'Access_Report_*') -Force
    $r = Invoke-Report @('-NtfsCsv', (Join-Path $tmp 'NTFS_Permissions_SRV020_20260825.csv'), '-ShareCsv', (Join-Path $tmp 'Share_Permissions_SRV020_20260825.csv'),
                         '-MembersCsv', (Join-Path $tmp 'AD_Group_Members_SRV020_20260825.csv'), '-OutputDirectory', (Join-Path $tmp 'out'))
    Assert-Equal $r.Code 0 'explicit files: exit code'
    Assert-Equal (Test-Path (Join-Path $tmp 'out\Access_Report_SRV020_20260825.csv')) $true 'explicit files: -OutputDirectory honoured'

    Move-Item (Join-Path $tmp 'AD_Group_Members_SRV020_20260825.csv') (Join-Path $tmp 'hidden.csv')
    $r = Invoke-Report @('-InputDirectory', $tmp)
    Assert-Equal ($r.Code -ne 0) $true 'missing members file: fails'
    Assert-Equal ($r.Text -match 'Get-ADGroupMembers\.ps1') $true 'missing members file: tells you what to run'
    Assert-Equal (Test-Path $outFile) $false 'missing members file: no report written'
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:failed -eq 0) { Write-Host "All $script:passed checks passed." -ForegroundColor Green; exit 0 }
Write-Host "$script:failed of $($script:passed + $script:failed) checks FAILED." -ForegroundColor Red
exit 1
