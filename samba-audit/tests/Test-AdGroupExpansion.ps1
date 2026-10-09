<#
.SYNOPSIS
    Offline tests for the AD group expansion inside New-AccessReport.ps1. No Active Directory needed.

.DESCRIPTION
    Replaces the three functions that talk to AD with a small in-memory directory, then
    runs the real input reading, group expansion and CSV writing against it.
    What this does NOT cover is the LDAP layer itself (New-AdContext, Find-AdAccount,
    Get-AdGroupMemberRecords and the helpers under them) - use
    .\New-AccessReport.ps1 -Group 'DOMAIN\SomeGroup' on a domain-joined machine for that.

    Run:  pwsh -File tests\Test-AdGroupExpansion.ps1      (or powershell.exe -File ...)
#>
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\New-AccessReport.ps1')

$script:failed = 0
$script:passed = 0
function Assert-Equal($Actual, $Expected, [string]$Name) {
    if ("$Actual" -ceq "$Expected") { $script:passed++; return }
    $script:failed++
    Write-Host "FAIL  $Name" -ForegroundColor Red
    Write-Host "      expected: $Expected"
    Write-Host "      actual  : $Actual"
}

#region ---------------------------------------------------- fake directory

$script:nextRid = 1000
function New-Rec($Kind, $Sam, $Display = '', $Enabled = '', $Scope = '', $Security = $false) {
    $script:nextRid++
    [pscustomobject]@{
        Kind = $Kind; Dn = "CN=$Sam,DC=vnet,DC=local"; Sid = "S-1-5-21-1-2-3-$($script:nextRid)"
        Account = "VNET\$Sam"; DisplayName = $(if ($Display) { $Display } else { $Sam }); Upn = "$Sam@vnet.local"
        Enabled = $Enabled; Scope = $Scope; IsSecurity = $Security
    }
}
$script:dir = @{}
foreach ($n in 'A', 'B', 'C', 'D', 'E') { $script:dir[$n] = New-Rec 'Group' $n '' '' 'Global' $true }
$script:dir['jnovak']  = New-Rec 'User' 'jnovak'  'Ján Novák'      $true
$script:dir['mkrasna'] = New-Rec 'User' 'mkrasna' 'Mária Krásna'   $true
$script:dir['petrov']  = New-Rec 'User' 'petrov'  'Peter, "Petrov"' $false   # comma and quotes in a name
$script:dir['zuzka']   = New-Rec 'User' 'zuzka'   'Žofia Šťastná'  $true
$script:dir['pc01']    = New-Rec 'Computer' 'pc01$' '' $true

# A -> jnovak, B, mkrasna        B -> mkrasna, petrov, C        C -> A (cycle), zuzka
# D is empty                     E -> pc01$, A
$script:members = @{
    'A' = @('jnovak', 'B', 'mkrasna')
    'B' = @('mkrasna', 'petrov', 'C')
    'C' = @('A', 'zuzka')
    'D' = @()
    'E' = @('pc01', 'A')
}
$script:lookups = 0

# shadow the AD-facing functions
function Test-AdDomain { param($Ctx, [string]$Domain) $Domain -eq 'VNET' }
function Find-AdAccount {
    param($Ctx, [string]$Domain, [string]$Name)
    if ($Name -eq 'Boom') { throw 'LDAP exploded' }
    $script:dir[$Name]
}
function Get-AdGroupMemberRecords {
    param($Ctx, $Group)
    $script:lookups++
    $key = $Group.Account.Split('\')[-1]
    foreach ($m in $script:members[$key]) { $script:dir[$m] }
}

#endregion

#region ---------------------------------------------------------- helpers

Assert-Equal (ConvertTo-LdapFilterValue 'a(b)*\c') 'a\28b\29\2a\5cc' 'LDAP filter escaping'
Assert-Equal (ConvertTo-LdapFilterValue 'CN=Smith\, John') 'CN=Smith\5c, John' 'LDAP filter escaping keeps comma, doubles backslash once'
Assert-Equal (Format-CsvField 'a,"b"') '"a,""b"""' 'CSV quoting'
Assert-Equal (Split-Account 'VNET\HRteam_write').Name 'HRteam_write' 'Split-Account name'
Assert-Equal (Split-Account 'Everyone').Domain '' 'Split-Account without domain'

#endregion

#region ------------------------------------------------------ input files

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("adgm-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $hdr = 'Server,ShareName,SharePath,FolderPath,RelativePath,Depth,BoundaryType,InheritanceBroken,Owner,Trustee,TrusteeDomain,TrusteeName,SidResolved,AccessType,RightsSimple,RightsRaw,IsInherited,InheritedFrom,AppliesTo,ScanTimestamp'
    function Ntfs-Row($trustee, $resolved = 'True', $folder = 'E:\Data\x') {
        $dom, $nm = if ($trustee.Contains('\')) { $trustee.Split('\', 2) } else { '', $trustee }
        "SRV020,Data,E:\Data,$folder,x,1,Explicit,False,VNET\admin,$(Format-CsvField $trustee),$dom,$(Format-CsvField $nm),$resolved,Allow,Modify,Modify,False,,This folder,2026-08-25T10:00:00"
    }
    $ntfsLines = @(
        $hdr
        (Ntfs-Row 'VNET\A')
        (Ntfs-Row 'VNET\A' 'True' '"E:\Data\with, comma"')      # duplicate trustee, quoted comma in another column
        (Ntfs-Row 'VNET\D')
        (Ntfs-Row 'VNET\Ghost')
        (Ntfs-Row 'VNET\jnovak')
        (Ntfs-Row 'BUILTIN\Users')
        (Ntfs-Row 'S-1-5-21-9-9-9-1234' 'False')                 # unresolved SID: must be ignored
        (Ntfs-Row 'VNET\Boom')
        (Ntfs-Row 'OTHERDOM\Foreign')
    )
    $shareLines = @(
        'Server,ShareName,SharePath,Description,Trustee,AccessType,AccessRight,ScanTimestamp'
        'SRV020,Data,E:\Data,,Everyone,Allow,Full,2026-08-25T10:00:00'
        'SRV020,Data,E:\Data,,VNET\E,Allow,Change,2026-08-25T10:00:00'
    )
    $enc = New-Object System.Text.UTF8Encoding($true)   # BOM, as PowerShell 5.1 Export-Csv writes it
    [System.IO.File]::WriteAllLines((Join-Path $tmp 'NTFS_Permissions_SRV020_20260825.csv'), $ntfsLines, $enc)
    [System.IO.File]::WriteAllLines((Join-Path $tmp 'Share_Permissions_SRV020_20260825.csv'), $shareLines, $enc)

    $list = @(Get-TrusteeList -NtfsCsv (Join-Path $tmp 'NTFS_Permissions_SRV020_20260825.csv') -ShareCsv (Join-Path $tmp 'Share_Permissions_SRV020_20260825.csv'))
    # distinct, BOM-safe, quoted commas handled, unresolved SID dropped; compared sorted to stay locale-independent
    Assert-Equal (($list | Sort-Object) -join '|') ((@('BUILTIN\Users', 'Everyone', 'OTHERDOM\Foreign', 'VNET\A', 'VNET\Boom', 'VNET\D', 'VNET\E', 'VNET\Ghost', 'VNET\jnovak') | Sort-Object) -join '|') 'Trustee set from NTFS + share CSV'

    # export-set discovery: newest date with BOTH files wins
    foreach ($f in 'NTFS_Permissions_SRV020_20260901.csv',                                         # newest, but no share CSV
                   'NTFS_Permissions_SRV020_20260725.csv', 'Share_Permissions_SRV020_20260725.csv') {
        Set-Content -LiteralPath (Join-Path $tmp $f) -Value 'x'
    }
    $sets = @(Find-ExportSet -Directory $tmp)
    Assert-Equal $sets[0].Date '20260825' 'Find-ExportSet skips newer incomplete set'
    Assert-Equal $sets.Count 2 'Find-ExportSet lists complete sets only'
    Assert-Equal (@(Find-ExportSet -Directory $tmp -Date '20260725')[0].Date) '20260725' 'Find-ExportSet honours -ScanDate'
    Assert-Equal (@(Find-ExportSet -Directory $tmp -Date '20991231')).Count 0 'Find-ExportSet no match'

#endregion

#region -------------------------------------------------------- expansion

    $cache = @{}
    $tree = Expand-AdGroupTree -Ctx $null -Root ($script:dir['A'] | Select-Object *) -Cache $cache -SkipSet @{} -MaxDepth 10
    $byMember = @{}; foreach ($r in $tree.Rows) { $byMember[$r.Member] = $r }
    Assert-Equal $tree.Rows.Count 6 'A: row count (jnovak, B, mkrasna, petrov, C, zuzka; cycle back to A skipped)'
    Assert-Equal $byMember['VNET\jnovak'].NestingLevel 1 'A: direct member level'
    Assert-Equal $byMember['VNET\mkrasna'].NestingLevel 1 'A: direct beats nested (mkrasna is also in B)'
    Assert-Equal $byMember['VNET\petrov'].MembershipPath 'VNET\A > VNET\B' 'A: nested path'
    Assert-Equal $byMember['VNET\petrov'].ParentGroup 'VNET\B' 'A: parent group'
    Assert-Equal $byMember['VNET\zuzka'].MembershipPath 'VNET\A > VNET\B > VNET\C' 'A: two-level nesting path'
    Assert-Equal $byMember['VNET\zuzka'].NestingLevel 3 'A: two-level nesting level'
    Assert-Equal $byMember['VNET\C'].MemberType 'Group' 'A: nested group listed as Group'
    Assert-Equal ($tree.Rows | Where-Object { $_.Member -eq 'VNET\A' }).Count 0 'A: cycle does not list the root'
    Assert-Equal $tree.Notes.Count 0 'A: no notes'

    # depth limit: C is listed but not entered, so zuzka is missing and the group is flagged
    $deep = Expand-AdGroupTree -Ctx $null -Root ($script:dir['A'] | Select-Object *) -Cache @{} -SkipSet @{} -MaxDepth 2
    Assert-Equal ($deep.Rows | Where-Object { $_.Member -eq 'VNET\zuzka' }).Count 0 'MaxDepth stops descent'
    Assert-Equal ($deep.Rows | Where-Object { $_.Member -eq 'VNET\C' }).Count 1 'MaxDepth still lists the group at the limit'
    Assert-Equal $deep.Notes.Count 1 'MaxDepth records a note'

    # -DoNotExpand on a nested group
    $skip = Expand-AdGroupTree -Ctx $null -Root ($script:dir['A'] | Select-Object *) -Cache @{} -SkipSet @{ 'b' = $true } -MaxDepth 10
    Assert-Equal ($skip.Rows | Where-Object { $_.Member -eq 'VNET\petrov' }).Count 0 'DoNotExpand (name only) skips nested group contents'
    Assert-Equal ($skip.Rows | Where-Object { $_.Member -eq 'VNET\B' }).Count 1 'DoNotExpand still lists the group'

#endregion

#region ------------------------------------------------------ full export

    $script:lookups = 0
    $out = Join-Path $tmp 'AD_Group_Members_SRV020_20260825.csv'
    $res = Invoke-GroupMemberExport -Ctx $null -Trustee $list -OutFile $out -Server 'SRV020' -DoNotExpand @() -MaxDepth 10 6>$null
    Assert-Equal (Test-Path $out) $true 'Export: file published'
    Assert-Equal (Test-Path "$out.partial") $false 'Export: no .partial left behind'
    $csv = @(Import-Csv -LiteralPath $out -Encoding UTF8)

    $header = (Get-Content -LiteralPath $out -TotalCount 1)
    Assert-Equal $header 'Server,Group,GroupSid,GroupScope,GroupStatus,MemberType,Member,MemberSid,DisplayName,UserPrincipalName,Enabled,NestingLevel,ParentGroup,MembershipPath,Note,ScanTimestamp' 'Export: header'

    $status = @{}; foreach ($r in $csv) { $status[$r.Group] = $r.GroupStatus }
    Assert-Equal $status['VNET\A'] 'Expanded' 'Export: A expanded'
    Assert-Equal $status['VNET\D'] 'Empty' 'Export: D empty'
    Assert-Equal $status['VNET\Ghost'] 'NotFound' 'Export: Ghost not found'
    Assert-Equal $status['VNET\Boom'] 'Error' 'Export: AD failure on one group is recorded and does not stop the run'
    Assert-Equal $status['VNET\E'] 'Expanded' 'Export: E (only in share CSV) expanded'
    Assert-Equal $status.ContainsKey('VNET\jnovak') $false 'Export: a user trustee gets no group rows'
    Assert-Equal $status.ContainsKey('BUILTIN\Users') $false 'Export: BUILTIN skipped'
    Assert-Equal $status.ContainsKey('Everyone') $false 'Export: Everyone skipped'
    Assert-Equal $status.ContainsKey('OTHERDOM\Foreign') $false 'Export: other domain skipped'

    $d = @($csv | Where-Object { $_.Group -eq 'VNET\D' })
    Assert-Equal $d.Count 1 'Export: empty group has exactly one marker row'
    Assert-Equal $d[0].Member '' 'Export: marker row has no member'

    $people = @($csv | Where-Object { $_.Group -eq 'VNET\A' -and $_.MemberType -eq 'User' } | ForEach-Object Member | Sort-Object)
    Assert-Equal ($people -join ',') 'VNET\jnovak,VNET\mkrasna,VNET\petrov,VNET\zuzka' 'Export: users effectively in A'
    $petrov = $csv | Where-Object { $_.Group -eq 'VNET\A' -and $_.Member -eq 'VNET\petrov' }
    Assert-Equal $petrov.DisplayName 'Peter, "Petrov"' 'Export: comma and quotes in a name round-trip'
    Assert-Equal $petrov.Enabled 'False' 'Export: disabled account flagged'
    $zuzka = $csv | Where-Object { $_.Group -eq 'VNET\A' -and $_.Member -eq 'VNET\zuzka' }
    Assert-Equal $zuzka.DisplayName 'Žofia Šťastná' 'Export: diacritics survive'
    Assert-Equal (($csv | Where-Object { $_.Group -eq 'VNET\E' -and $_.MemberType -eq 'Computer' }).Member) 'VNET\pc01$' 'Export: computer member typed Computer'

    # shared nested groups are fetched once (A, B, C, D, E, Boom/Ghost never reach the member call)
    Assert-Equal $script:lookups 5 'Export: each group fetched once across roots (cache)'
    Assert-Equal $res.Stats.Rows $csv.Where({ $_.MemberType }).Count 'Export: stats row count matches file'
    Assert-Equal $res.DistinctUsers 4 'Export: distinct user count'

    # the -Group style call: no CSV, explicit list
    $out2 = Join-Path $tmp 'adhoc.csv'
    [void](Invoke-GroupMemberExport -Ctx $null -Trustee @('VNET\B') -OutFile $out2 -Server 'X' -DoNotExpand @('VNET\B') -MaxDepth 5 6>$null)
    $adhoc = @(Import-Csv -LiteralPath $out2 -Encoding UTF8)
    Assert-Equal $adhoc.Count 1 'Ad-hoc: -DoNotExpand on a top-level group yields one marker row'
    Assert-Equal $adhoc[0].GroupStatus 'Skipped' 'Ad-hoc: Skipped status'
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

#endregion

Write-Host ''
if ($script:failed -eq 0) { Write-Host "All $script:passed checks passed." -ForegroundColor Green; exit 0 }
Write-Host "$script:failed of $($script:passed + $script:failed) checks FAILED." -ForegroundColor Red
exit 1
