<#
.SYNOPSIS
    Runs New-AccessReport.ps1 the way you do - one command, CSVs in, report out - with a fake
    Active Directory. Makes a temporary copy of the script with the four AD-facing functions
    replaced, so the real argument handling, step 1 (membership) and step 2 (report) all run.

    Not covered: the real LDAP calls. Use  New-AccessReport.ps1 -Group 'DOMAIN\SomeGroup'  for that.

    Run:  pwsh -File tests\Test-EndToEnd.ps1      (or powershell.exe -File ...)
#>
$ErrorActionPreference = 'Stop'
$real = (Resolve-Path (Join-Path $PSScriptRoot '..\New-AccessReport.ps1')).Path
$ps = (Get-Process -Id $PID).Path

$script:failed = 0; $script:passed = 0
function Assert-Equal($Actual, $Expected, [string]$Name) {
    if ("$Actual" -ceq "$Expected") { $script:passed++; return }
    $script:failed++
    Write-Host "FAIL  $Name" -ForegroundColor Red
    Write-Host "      expected: $Expected"
    Write-Host "      actual  : $Actual"
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("e2e-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    # --- a copy of the script whose AD layer is a small in-memory directory ---------------------
    $fakeAd = @'
$script:fake = @{}
function Add-Fake($kind, $sam, $display, $enabled, $scope) {
    $script:fake[$sam] = [pscustomobject]@{
        Kind = $kind; Dn = "CN=$sam,DC=hq,DC=local"; Sid = "S-1-5-21-$($script:fake.Count + 1)"; Account = "HQ\$sam"
        DisplayName = $display; Upn = "$sam@hq.local"; Enabled = $enabled; Scope = $scope; IsSecurity = ($kind -eq 'Group')
    }
}
Add-Fake 'Group' 'GrpA' '' '' 'Global'
Add-Fake 'Group' 'GrpB' '' '' 'Global'
Add-Fake 'User' 'jnovak' 'Ján Novák' $true ''
Add-Fake 'User' 'zsast' 'Žofia Šťastná' $true ''
$script:members = @{ 'GrpA' = @('jnovak', 'GrpB'); 'GrpB' = @('zsast') }
function New-AdContext { param([string]$DomainController) [pscustomobject]@{ DomainMap = @{ HQ = 'DC=hq,DC=local' } } }
function Test-AdDomain { param($Ctx, [string]$Domain) $Domain -eq 'HQ' }
function Find-AdAccount { param($Ctx, [string]$Domain, [string]$Name) $script:fake[$Name] }
function Get-AdGroupMemberRecords { param($Ctx, $Group) foreach ($m in $script:members[$Group.Account.Split('\')[-1]]) { $script:fake[$m] } }

'@
    $text = Get-Content -LiteralPath $real -Raw
    $marker = '# Dot-sourcing (the tests do this)'
    if (-not $text.Contains($marker)) { throw 'marker not found in New-AccessReport.ps1' }
    $copy = Join-Path $tmp 'New-AccessReport.fake-ad.ps1'
    [System.IO.File]::WriteAllText($copy, $text.Replace($marker, $fakeAd + $marker), (New-Object System.Text.UTF8Encoding($true)))

    function Invoke-Copy([string[]]$Arguments) {
        $out = & $ps -NoProfile -File $copy @Arguments 2>&1 | Out-String
        [pscustomobject]@{ Code = $LASTEXITCODE; Text = $out }
    }

    # --- made-up export set --------------------------------------------------------------------
    $inbox = Join-Path $tmp 'q report'
    New-Item -ItemType Directory -Path $inbox | Out-Null
    $enc = New-Object System.Text.UTF8Encoding($true)
    $hdr = 'Server,ShareName,SharePath,FolderPath,RelativePath,Depth,BoundaryType,InheritanceBroken,Owner,Trustee,TrusteeDomain,TrusteeName,SidResolved,AccessType,RightsSimple,RightsRaw,IsInherited,InheritedFrom,AppliesTo,ScanTimestamp'
    function Row($folder, $rel, $bound, $trustee, $resolved = 'True') {
        "SRV020,Data,E:\Data,$folder,$rel,1,$bound,False,HQ\admin,$trustee,,,$resolved,Allow,Modify,Modify,False,,This folder,2026-08-25T10:00:00"
    }
    [System.IO.File]::WriteAllLines((Join-Path $inbox 'NTFS_Permissions_SRV020_20260825.csv'), @(
        $hdr
        (Row 'E:\Data' '' 'Root' 'HQ\GrpA')
        (Row 'E:\Data' '' 'Root' 'BUILTIN\Users')
        (Row 'E:\Data\HR' 'HR' 'Explicit' 'HQ\jnovak')
        (Row 'E:\Data\HR' 'HR' 'Explicit' 'HQ\Missing')
        (Row 'E:\Data\HR' 'HR' 'Explicit' 'S-1-5-21-9-9-9-1' 'False')
    ), $enc)
    [System.IO.File]::WriteAllLines((Join-Path $inbox 'Share_Permissions_SRV020_20260825.csv'), @(
        'Server,ShareName,SharePath,Description,Trustee,AccessType,AccessRight,ScanTimestamp'
        'SRV020,Data,E:\Data,,Everyone,Allow,Full,2026-08-25T10:00:00'
        'SRV020,Data,E:\Data,,HQ\GrpA,Allow,Change,2026-08-25T10:00:00'
    ), $enc)
    # an older set must be ignored, and so must a newer one without its share CSV
    Set-Content -LiteralPath (Join-Path $inbox 'NTFS_Permissions_SRV020_20260725.csv') -Value 'x'
    Set-Content -LiteralPath (Join-Path $inbox 'Share_Permissions_SRV020_20260725.csv') -Value 'x'
    Set-Content -LiteralPath (Join-Path $inbox 'NTFS_Permissions_SRV020_20260901.csv') -Value 'x'

    # Windows PowerShell 5.1 leaves $PSScriptRoot empty in a param default, which broke -Group on the server
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($real, [ref]$tokens, [ref]$errors)
    Assert-Equal ($ast.ParamBlock.Extent.Text -match 'PSScriptRoot') $false 'param block does not use $PSScriptRoot'

    # --- one command, the way it is run -------------------------------------------------------
    $r = Invoke-Copy @('-InputDirectory', $inbox)
    if ($r.Code -ne 0) { Write-Host $r.Text }
    Assert-Equal $r.Code 0 'e2e: exit code'
    Assert-Equal ($r.Text -match 'Step 1/2') $true 'e2e: step 1 ran'
    Assert-Equal ($r.Text -match 'Step 2/2') $true 'e2e: step 2 ran'
    Assert-Equal ($r.Text -match 'AD groups\s+: 2\s+\(expanded 1, empty 0, skipped 0, not found 1') $true 'e2e: summary counts one expanded group and one missing'
    Assert-Equal ($r.Text -match 'No trustee matched') $false 'e2e: no domain-mismatch warning when the domain matches'

    $members = Join-Path $inbox 'AD_Group_Members_SRV020_20260825.csv'
    $report = Join-Path $inbox 'Access_Report_SRV020_20260825.csv'
    Assert-Equal (Test-Path $members) $true 'e2e: membership CSV written, named after the newest complete set'
    Assert-Equal (Test-Path $report) $true 'e2e: report written'
    Assert-Equal (@(Get-ChildItem $inbox -Filter '*.partial').Count) 0 'e2e: no .partial left'

    $m = @(Import-Csv -LiteralPath $members -Encoding UTF8)
    $mu = @($m | Where-Object MemberType -eq 'User' | ForEach-Object Member | Sort-Object)
    Assert-Equal ($mu -join ',') 'HQ\jnovak,HQ\zsast' 'e2e: membership CSV lists both people, nested one included'

    $rows = @(Import-Csv -LiteralPath $report -Encoding UTF8)
    $z = @($rows | Where-Object { $_.Layer -eq 'NTFS' -and $_.Person -eq 'HQ\zsast' })
    Assert-Equal $z.Count 1 'e2e: nested member reaches the NTFS root'
    Assert-Equal $z[0].MembershipPath 'HQ\GrpA > HQ\GrpB' 'e2e: path through the nested group'
    Assert-Equal $z[0].PersonName 'Žofia Šťastná' 'e2e: diacritics survive both steps'
    $sh = @($rows | Where-Object { $_.Layer -eq 'Share' -and $_.Trustee -eq 'HQ\GrpA' })
    Assert-Equal $sh.Count 2 'e2e: share entry for the group expands to its two people'
    $direct = $rows | Where-Object { $_.Layer -eq 'NTFS' -and $_.Trustee -eq 'HQ\jnovak' }
    Assert-Equal $direct.Via 'Direct' 'e2e: user named in the ACL is Direct'
    $miss = $rows | Where-Object { $_.Trustee -eq 'HQ\Missing' }
    Assert-Equal $miss.GroupStatus 'NotFound' 'e2e: deleted group stays visible as NotFound'
    $orphan = @($rows | Where-Object { $_.Trustee -like 'S-1-5-21-*' })
    Assert-Equal ($orphan.Count -gt 0) $true 'e2e: an orphaned SID in the ACL still shows up in the report'
    Assert-Equal "$($orphan[0].TrusteeKind)/$($orphan[0].GroupStatus)/$($orphan[0].Person)" 'Other/NotExpanded/' 'e2e: orphaned SID is Other, not looked up, no person invented'
    Assert-Equal @($m | Where-Object { $_.Group -like 'S-1-5-21-*' }).Count 0 'e2e: orphaned SID is not sent to AD'
    Assert-Equal (@($rows | Where-Object { $_.Trustee -eq 'BUILTIN\Users' }).TrusteeKind) 'Other' 'e2e: BUILTIN stays Other'

    # --- test mode: no CSVs --------------------------------------------------------------------
    $adhocDir = Join-Path $tmp 'adhoc'
    $r = Invoke-Copy @('-Group', 'HQ\GrpA', '-OutputDirectory', $adhocDir)
    Assert-Equal $r.Code 0 'test mode: exit code'
    $adhoc = @(Get-ChildItem $adhocDir -Filter 'AD_Group_Members_*_adhoc.csv')
    Assert-Equal $adhoc.Count 1 'test mode: adhoc file written'
    Assert-Equal ($r.Text -match 'HQ\\zsast') $true 'test mode: members printed on screen'

    # --- wrong domain name in the CSV: say so instead of silently producing nothing --------------
    $wrong = Join-Path $tmp 'wrong'
    New-Item -ItemType Directory -Path $wrong | Out-Null
    [System.IO.File]::WriteAllLines((Join-Path $wrong 'NTFS_Permissions_SRV020_20260825.csv'), @($hdr, (Row 'E:\Data' '' 'Root' 'VNET\GrpA')), $enc)
    [System.IO.File]::WriteAllLines((Join-Path $wrong 'Share_Permissions_SRV020_20260825.csv'), @('Server,ShareName,SharePath,Description,Trustee,AccessType,AccessRight,ScanTimestamp'), $enc)
    $r = Invoke-Copy @('-InputDirectory', $wrong)
    Assert-Equal $r.Code 0 'wrong domain: still finishes'
    Assert-Equal ($r.Text -match 'No trustee matched a domain of this forest \(HQ\)') $true 'wrong domain: warns and names the real domain'

    # --- the default: one command scans, asks AD and writes the report --------------------------
    # (on Linux the ACL calls fail, so the scan logs errors instead of rows; the wiring is what is checked here)
    $tree = Join-Path $tmp 'tree'
    New-Item -ItemType Directory -Path (Join-Path $tree 'a\b') -Force | Out-Null
    $scanOut = Join-Path $tmp 'scan-out'
    $r = Invoke-Copy @('-Path', $tree, '-OutputDirectory', $scanOut)
    if ($r.Code -ne 0) { Write-Host $r.Text }
    Assert-Equal $r.Code 0 'scan mode: exit code'
    Assert-Equal ($r.Text -match 'Step 1/3') $true 'scan mode: three steps'
    Assert-Equal ($r.Text -match 'Step 3/3') $true 'scan mode: last step is the report'
    Assert-Equal ($r.Text.IndexOf('Checking Active Directory access first') -lt $r.Text.IndexOf('Step 1/3')) $true 'scan mode: AD is checked before the scan starts'
    foreach ($prefix in 'Share_Permissions_', 'NTFS_Permissions_', 'Scan_Errors_', 'AD_Group_Members_', 'Access_Report_') {
        Assert-Equal @(Get-ChildItem -LiteralPath $scanOut -Filter "$prefix*.csv").Count 1 "scan mode: $prefix file is written"
    }
    Assert-Equal @(Get-ChildItem -LiteralPath $scanOut -Filter '*.partial').Count 0 'scan mode: no .partial left'

    # default folder = 'q report' next to the script
    $before = @(Get-ChildItem -LiteralPath $inbox -Filter 'Access_Report_*.csv').Count     # $inbox is the folder 'q report' next to the copy
    $r = Invoke-Copy @('-Path', $tree)
    Assert-Equal $r.Code 0 'default folder: exit code'
    Assert-Equal @(Get-ChildItem -LiteralPath $inbox -Filter 'Access_Report_*.csv').Count ($before + 1) "default folder: report lands in 'q report' next to the script"

    # -SkipAd = the old scan only
    $scanOnly = Join-Path $tmp 'scan-only'
    $r = Invoke-Copy @('-Path', $tree, '-OutputDirectory', $scanOnly, '-SkipAd')
    Assert-Equal $r.Code 0 'SkipAd: exit code'
    Assert-Equal @(Get-ChildItem -LiteralPath $scanOnly -Filter '*_Permissions_*.csv').Count 2 'SkipAd: share and NTFS CSV written'
    Assert-Equal @(Get-ChildItem -LiteralPath $scanOnly -Filter 'AD_Group_Members_*').Count 0 'SkipAd: no AD step'
    Assert-Equal @(Get-ChildItem -LiteralPath $scanOnly -Filter 'Access_Report_*').Count 0 'SkipAd: no report'

    # -ListSharesOnly writes nothing
    $dry = Join-Path $tmp 'dry'
    $r = Invoke-Copy @('-Path', $tree, '-OutputDirectory', $dry, '-ListSharesOnly')
    Assert-Equal $r.Code 0 'ListSharesOnly: exit code'
    Assert-Equal ($r.Text -match 'WOULD be scanned') $true 'ListSharesOnly: shows the targets'
    Assert-Equal (Test-Path $dry) $false 'ListSharesOnly: writes nothing'

    # -InputDirectory still means "do not scan"
    $r = Invoke-Copy @('-InputDirectory', $inbox)
    Assert-Equal ($r.Text -match 'Scanning this server') $false 'InputDirectory: does not scan'

    # with the real AD layer on a machine that has none, the problem shows before any scan work
    if ($PSVersionTable.Platform -eq 'Unix') {
        $early = Join-Path $tmp 'early'
        $r = & $ps -NoProfile -File $real -Path $tree -OutputDirectory $early 2>&1 | Out-String
        Assert-Equal ($LASTEXITCODE -ne 0) $true 'no AD: fails'
        Assert-Equal (Test-Path $early) $false 'no AD: fails before the scan wrote anything'
    }

    # --- errors you can make --------------------------------------------------------------------
    $r = Invoke-Copy @('-InputDirectory', (Join-Path $tmp 'does-not-exist'))
    Assert-Equal ($r.Code -ne 0 -and $r.Text -match 'Input directory not found') $true 'bad folder: clear error'
    $empty = Join-Path $tmp 'empty'; New-Item -ItemType Directory -Path $empty | Out-Null
    $r = Invoke-Copy @('-InputDirectory', $empty)
    Assert-Equal ($r.Code -ne 0 -and $r.Text -match 'No export set') $true 'empty folder: clear error'
    Assert-Equal ($r.Text -match 'contains no CSV files') $true 'empty folder: says it is empty'
    Set-Content -LiteralPath (Join-Path $empty 'something.csv') -Value 'x'
    $r = Invoke-Copy @('-InputDirectory', $empty)
    Assert-Equal ($r.Text -match 'CSV files in the folder: something\.csv') $true 'folder without a set: lists what is there'
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:failed -eq 0) { Write-Host "All $script:passed checks passed." -ForegroundColor Green; exit 0 }
Write-Host "$script:failed of $($script:passed + $script:failed) checks FAILED." -ForegroundColor Red
exit 1
