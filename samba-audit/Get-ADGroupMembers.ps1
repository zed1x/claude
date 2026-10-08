<#
.SYNOPSIS
    Expands the AD groups referenced in the permission CSVs into a group-membership CSV.

.DESCRIPTION
    The Phase 1 CSVs say WHICH groups hold permissions (for example HRteam_write) but not
    WHO is in them. This script closes that gap. It reads the trustees out of the NTFS and
    share CSVs, looks each one up in Active Directory, and for every group writes one row
    per member - including members reached through nested groups.

    Output: AD_Group_Members_<Server>_<yyyyMMdd>.csv, written next to the NTFS CSV and
    named with the same server and date so the four files form one export set. The report
    then needs nothing but CSVs: join NTFS/Share 'Trustee' to this file's 'Group'.

    Run it by hand; nothing calls it automatically. Typical use after a scan:

        .\Get-ADGroupMembers.ps1 -InputDirectory 'C:\scripts\VNET_Samba_Audit\q report'

    To check that AD access works, expand a single group first (nothing else is read):

        .\Get-ADGroupMembers.ps1 -Group 'VNET\HRteam_write'

    Strictly read-only. It only issues LDAP searches as the current user; any authenticated
    domain user can run it. It needs no modules (plain System.DirectoryServices), so it
    works on a stock file server as well as on a DC or admin workstation.

    Columns
      Server, Group, GroupSid, GroupScope, GroupStatus, MemberType, Member, MemberSid,
      DisplayName, UserPrincipalName, Enabled, NestingLevel, ParentGroup, MembershipPath,
      Note, ScanTimestamp

      Group           the trustee exactly as written in the permission CSVs (join key)
      GroupStatus     Expanded | Truncated | Empty | Skipped | NotFound | Error
      MemberType      User | Computer | Group | Foreign | Contact | Unknown
                      ('Group' rows are the nested groups themselves; filter on
                      MemberType = User for the people who actually have access)
      NestingLevel    1 = direct member, 2 = member of a nested group, ...
      ParentGroup     the group that directly contains the member
      MembershipPath  Group > nested group > ... > ParentGroup (shortest path if several)
      Enabled         False for disabled accounts, which hold the permission but cannot log on

    A group with no members, or one that could not be expanded, gets a single row with
    empty member columns so the report can tell "empty" from "never looked up".

    Not expanded: local/BUILTIN groups and anything outside this AD forest (reported as
    skipped in the summary), and members from outside the forest (listed as 'Foreign').

.PARAMETER NtfsCsv
    The NTFS permissions CSV to read. Use together with -ShareCsv.

.PARAMETER ShareCsv
    The matching share permissions CSV. Optional; its trustees are added to the list.

.PARAMETER InputDirectory
    Alternative to -NtfsCsv: pick the newest export set in this folder that has both an
    NTFS and a share CSV with the same server and date.

.PARAMETER Group
    Test mode: expand only these groups ('DOMAIN\Name') and skip the permission CSVs.
    Writes AD_Group_Members_<computer>_<yyyyMMdd>_adhoc.csv (the suffix keeps report
    tooling from mistaking it for part of an export set) and shows the first rows.

.PARAMETER ScanDate
    With -InputDirectory, use this export date (yyyyMMdd) instead of the newest.

.PARAMETER OutputDirectory
    Where the membership CSV is written. Defaults to the folder of the NTFS CSV.

.PARAMETER DomainController
    Query this DC instead of letting Windows pick one.

.PARAMETER DoNotExpand
    Groups to list but not expand (full 'DOMAIN\Name' or just the name). Useful for huge
    catch-all groups such as 'Domain Users' that would add one row per employee.

.PARAMETER MaxNestingDepth
    Stop descending into nested groups past this level. The group is then marked Truncated.

.EXAMPLE
    .\Get-ADGroupMembers.ps1 -InputDirectory C:\scripts\VNET_Samba_Audit\q report
    Build the membership CSV for the newest export set in that folder.

.EXAMPLE
    .\Get-ADGroupMembers.ps1 -InputDirectory .\Reports -ScanDate 20260825 -DoNotExpand 'Domain Users'
#>
[CmdletBinding(DefaultParameterSetName = 'Directory')]
param(
    [Parameter(ParameterSetName = 'Files', Mandatory)]
    [string]$NtfsCsv,

    [Parameter(ParameterSetName = 'Files')]
    [string]$ShareCsv,

    [Parameter(ParameterSetName = 'Groups', Mandatory)]
    [string[]]$Group,

    [Parameter(ParameterSetName = 'Directory')]
    [string]$InputDirectory = (Join-Path $PSScriptRoot 'Reports'),

    [Parameter(ParameterSetName = 'Directory')]
    [ValidatePattern('^\d{8}$')]
    [string]$ScanDate,

    [string]  $OutputDirectory,
    [string]  $DomainController,
    [string[]]$DoNotExpand,
    [ValidateRange(1, 50)][int]$MaxNestingDepth = 10
)

$script:AdProperties = @(
    'distinguishedName', 'objectClass', 'objectSid', 'sAMAccountName', 'displayName',
    'userPrincipalName', 'userAccountControl', 'groupType', 'cn'
)

#region ---------------------------------------------------------------- helpers

function Format-CsvField($Value) {
    $s = if ($null -eq $Value) { '' } else { [string]$Value }
    if ($s.IndexOfAny([char[]]@(',', '"', "`r", "`n")) -ge 0) { '"' + $s.Replace('"', '""') + '"' } else { $s }
}

function ConvertTo-LdapFilterValue([string]$Value) {
    # backslash first, otherwise the escapes added for the other characters get doubled
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Split-Account([string]$Account) {
    $i = $Account.IndexOf('\')
    if ($i -lt 0) { return [pscustomobject]@{ Domain = ''; Name = $Account } }
    [pscustomobject]@{ Domain = $Account.Substring(0, $i); Name = $Account.Substring($i + 1) }
}

#endregion

#region ------------------------------------------------------------- input CSVs

function Find-ExportSet {
    # Newest date that has BOTH an NTFS and a share CSV for the same server.
    param([string]$Directory, [string]$Date)

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw "Input directory not found: $Directory"
    }
    $sets = foreach ($f in Get-ChildItem -LiteralPath $Directory -Filter 'NTFS_Permissions_*.csv' -File) {
        if ($f.Name -notmatch '^NTFS_Permissions_(?<srv>.+)_(?<date>\d{8})\.csv$') { continue }
        if ($Date -and $Matches['date'] -ne $Date) { continue }
        $share = Join-Path $Directory ('Share_Permissions_{0}_{1}.csv' -f $Matches['srv'], $Matches['date'])
        if (-not (Test-Path -LiteralPath $share -PathType Leaf)) { continue }
        [pscustomobject]@{ Server = $Matches['srv']; Date = $Matches['date']; NtfsCsv = $f.FullName; ShareCsv = $share }
    }
    @($sets | Sort-Object -Property Date, Server -Descending)
}

function Add-TrusteesFromCsv {
    # Streams a (possibly 200 MB) CSV and records each distinct value of its Trustee column.
    # TextFieldParser handles quoted commas and embedded line breaks that a naive split would not.
    param([string]$Path, [hashtable]$Into, [switch]$ResolvedOnly)

    Add-Type -AssemblyName Microsoft.VisualBasic
    $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($Path, [System.Text.Encoding]::UTF8, $true)
    $malformed = 0
    try {
        $parser.TextFieldType = 'Delimited'
        $parser.SetDelimiters(',')
        $parser.HasFieldsEnclosedInQuotes = $true

        $header = $parser.ReadFields()
        if (-not $header) { return }
        $iTrustee  = [array]::IndexOf($header, 'Trustee')
        $iResolved = [array]::IndexOf($header, 'SidResolved')
        if ($iTrustee -lt 0) { throw "Column 'Trustee' not found in $Path" }
        if ($ResolvedOnly -and $iResolved -lt 0) { throw "Column 'SidResolved' not found in $Path" }

        while (-not $parser.EndOfData) {
            $f = $null
            try { $f = $parser.ReadFields() }
            catch [Microsoft.VisualBasic.FileIO.MalformedLineException] { $malformed++; continue }
            if ($null -eq $f -or $f.Length -le $iTrustee) { continue }
            # an unresolved SID is a deleted or foreign account - there is nothing to look up
            if ($ResolvedOnly -and $f[$iResolved] -ne 'True') { continue }
            $t = $f[$iTrustee]
            if ($t -and -not $Into.ContainsKey($t)) { $Into[$t] = $true }
        }
    }
    finally { $parser.Dispose() }
    if ($malformed -gt 0) { Write-Warning "$malformed malformed line(s) skipped in $Path" }
}

function Get-TrusteeList {
    param([string]$NtfsCsv, [string]$ShareCsv)
    $set = @{}
    Add-TrusteesFromCsv -Path $NtfsCsv -Into $set -ResolvedOnly
    if ($ShareCsv) { Add-TrusteesFromCsv -Path $ShareCsv -Into $set }
    @($set.Keys | Sort-Object)
}

#endregion

#region ----------------------------------------------------- Active Directory

# These four functions are the only ones that touch AD; the expansion logic below calls
# them by name, which is what lets the tests swap in a fake directory.

function Add-AdAssembly { Add-Type -AssemblyName System.DirectoryServices }

function New-AdSearcher {
    param($Root, [string]$Filter, [string[]]$Property, [string]$Scope = 'Subtree', [int]$PageSize = 0)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot    = $Root
    $s.Filter        = $Filter
    $s.SearchScope   = $Scope
    $s.CacheResults  = $false
    if ($PageSize -gt 0) { $s.PageSize = $PageSize }
    foreach ($p in $Property) { [void]$s.PropertiesToLoad.Add($p) }
    $s
}

function Get-AdEntry {
    param($Ctx, [string]$Dn)
    $dcPart = ''
    # an explicit DC is only right for its own domain; other domains are located by Windows
    if ($Ctx.DomainController -and $Dn.EndsWith($Ctx.DefaultNc, [System.StringComparison]::OrdinalIgnoreCase)) {
        $dcPart = "$($Ctx.DomainController)/"
    }
    New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dcPart$($Dn.Replace('/', '\/'))")
}

function New-AdContext {
    param([string]$DomainController)
    Add-AdAssembly
    $dcPart = if ($DomainController) { "$DomainController/" } else { '' }

    $rootDse   = New-Object System.DirectoryServices.DirectoryEntry("LDAP://${dcPart}RootDSE")
    $defaultNc = [string]$rootDse.Properties['defaultNamingContext'].Value
    $configNc  = [string]$rootDse.Properties['configurationNamingContext'].Value
    $forestNc  = [string]$rootDse.Properties['rootDomainNamingContext'].Value
    if (-not $defaultNc) { throw 'Could not read RootDSE. Is this machine joined to the domain and able to reach a DC?' }
    if (-not $forestNc)  { $forestNc = $defaultNc }

    # NetBIOS name -> naming context, for every domain in the forest. The permission CSVs
    # carry NetBIOS names (VNET\Group); LDAP needs the DN. Anything not in this map is a
    # local, BUILTIN or out-of-forest principal and is skipped.
    $domainMap = @{}
    try {
        $partitions = New-Object System.DirectoryServices.DirectoryEntry("LDAP://${dcPart}CN=Partitions,$configNc")
        $s = New-AdSearcher -Root $partitions -Filter '(&(objectClass=crossRef)(nETBIOSName=*))' `
                -Property @('nETBIOSName', 'nCName') -Scope 'OneLevel'
        $res = $s.FindAll()
        try {
            foreach ($r in $res) {
                $domainMap[([string]$r.Properties['netbiosname'][0]).ToUpperInvariant()] = [string]$r.Properties['ncname'][0]
            }
        }
        finally { $res.Dispose(); $s.Dispose() }
    }
    catch { Write-Verbose "Partitions lookup failed: $($_.Exception.Message)" }

    if ($domainMap.Count -eq 0) {
        $guess = ($defaultNc -replace '^DC=', '').Split(',')[0].ToUpperInvariant()
        Write-Warning "Could not read the domain list from AD; assuming the NetBIOS name of $defaultNc is '$guess'."
        $domainMap[$guess] = $defaultNc
    }

    $ctx = [pscustomobject]@{
        DomainController = $DomainController
        DefaultNc        = $defaultNc
        DomainMap        = $domainMap
        # longest naming context first so a child domain is matched before its parent
        NcList           = @($domainMap.GetEnumerator() | Sort-Object { $_.Value.Length } -Descending |
                              ForEach-Object { [pscustomobject]@{ NetBios = $_.Key; Nc = $_.Value } })
        GcRoot           = New-Object System.DirectoryServices.DirectoryEntry("GC://${dcPart}$forestNc")
    }

    # members can live in any domain of the forest; fail now rather than on the first group
    $probe = New-AdSearcher -Root $ctx.GcRoot -Filter '(objectClass=*)' -Property @('distinguishedName') -Scope 'Base'
    try { [void]$probe.FindOne() }
    catch { throw "Global Catalog is not reachable: $($_.Exception.Message)" }
    finally { $probe.Dispose() }

    $ctx
}

function Test-AdDomain {
    param($Ctx, [string]$Domain)
    $Domain -and $Ctx.DomainMap.ContainsKey($Domain.ToUpperInvariant())
}

function Get-NcOfDn {
    param($Ctx, [string]$Dn)
    foreach ($d in $Ctx.NcList) {
        if ($Dn.EndsWith(",$($d.Nc)", [System.StringComparison]::OrdinalIgnoreCase)) { return $d.Nc }
    }
    $i = $Dn.IndexOf(',DC=', [System.StringComparison]::OrdinalIgnoreCase)
    if ($i -ge 0) { return $Dn.Substring($i + 1) }
    $Ctx.DefaultNc
}

function Get-NetBiosOfDn {
    param($Ctx, [string]$Dn)
    $nc = Get-NcOfDn $Ctx $Dn
    foreach ($d in $Ctx.NcList) { if ($d.Nc -eq $nc) { return $d.NetBios } }
    ($nc -replace '^DC=', '').Split(',')[0].ToUpperInvariant()
}

function Get-FirstValue($Properties, [string]$Name) {
    $v = $Properties[$Name]
    if ($null -ne $v -and $v.Count -gt 0) { $v[0] } else { $null }
}

function Resolve-SidName([string]$Sid) {
    try { (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $Sid }
}

function ConvertTo-AdRecord {
    param($Ctx, $Result)
    $p  = $Result.Properties
    $dn = [string](Get-FirstValue $p 'distinguishedname')
    $classes = @($p['objectclass'] | ForEach-Object { [string]$_ })
    $cn  = [string](Get-FirstValue $p 'cn')
    $sam = [string](Get-FirstValue $p 'samaccountname')

    # read the byte[] straight from the collection; returning it from a helper would unroll it
    $sid = ''
    $sidValues = $p['objectsid']
    if ($null -ne $sidValues -and $sidValues.Count -gt 0) {
        $sid = (New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$sidValues[0]), 0)).Value
    }

    # computer and inetOrgPerson also carry the 'user' class, so test the specific ones first
    $kind = if     ($classes -contains 'foreignSecurityPrincipal') { 'Foreign' }
            elseif ($classes -contains 'group')                    { 'Group' }
            elseif ($classes -contains 'computer')                 { 'Computer' }
            elseif ($classes -contains 'user')                     { 'User' }
            elseif ($classes -contains 'contact')                  { 'Contact' }
            else                                                   { 'Unknown' }

    $scope = ''; $isSecurity = $false
    $gt = Get-FirstValue $p 'grouptype'
    if ($kind -eq 'Group' -and $null -ne $gt) {
        $g = [int]$gt
        $isSecurity = ($g -lt 0)     # the security flag is the sign bit
        $scope = if ($g -band 2) { 'Global' } elseif ($g -band 4) { 'DomainLocal' } elseif ($g -band 8) { 'Universal' } else { '' }
    }

    $enabled = ''
    $uac = Get-FirstValue $p 'useraccountcontrol'
    if ($null -ne $uac -and ($kind -eq 'User' -or $kind -eq 'Computer')) { $enabled = (([int]$uac -band 2) -eq 0) }

    $account = if     ($kind -eq 'Foreign') { Resolve-SidName $sid }
               elseif ($sam)                { '{0}\{1}' -f (Get-NetBiosOfDn $Ctx $dn), $sam }
               else                         { $cn }

    $display = [string](Get-FirstValue $p 'displayname')
    if (-not $display) { $display = $cn }

    [pscustomobject]@{
        Kind = $kind; Dn = $dn; Sid = $sid; Account = $account
        DisplayName = $display; Upn = [string](Get-FirstValue $p 'userprincipalname')
        Enabled = $enabled; Scope = $scope; IsSecurity = $isSecurity
    }
}

function Find-AdAccount {
    # Looks up DOMAIN\Name by sAMAccountName. Returns $null when it does not exist.
    param($Ctx, [string]$Domain, [string]$Name)
    $nc = $Ctx.DomainMap[$Domain.ToUpperInvariant()]
    $s  = New-AdSearcher -Root (Get-AdEntry $Ctx $nc) -Filter "(sAMAccountName=$(ConvertTo-LdapFilterValue $Name))" `
            -Property $script:AdProperties
    try {
        $r = $s.FindOne()
        if ($r) { ConvertTo-AdRecord $Ctx $r }
    }
    finally { $s.Dispose() }
}

function Get-AdGroupMemberDn {
    # The 'member' attribute is capped per read (1500 values by default), so ask for it
    # in ranges until the server says the last range ends in '*'.
    param($Ctx, [string]$GroupDn)
    $dns = [System.Collections.Generic.List[string]]::new()
    $s = New-AdSearcher -Root (Get-AdEntry $Ctx $GroupDn) -Filter '(objectClass=*)' -Property @() -Scope 'Base'
    try {
        $low = 0
        while ($true) {
            $s.PropertiesToLoad.Clear()
            [void]$s.PropertiesToLoad.Add("member;range=$low-*")
            $r = $s.FindOne()
            if (-not $r) { break }
            $key = $null
            foreach ($n in $r.Properties.PropertyNames) {
                if ($n -eq 'member' -or $n -like 'member;range=*') { $key = $n; break }
            }
            if (-not $key) { break }               # empty group: no member attribute at all
            foreach ($v in $r.Properties[$key]) { $dns.Add([string]$v) }
            if ($key -match 'range=\d+-(\d+)$') { $low = [int]$Matches[1] + 1 } else { break }
        }
    }
    finally { $s.Dispose() }
    , $dns.ToArray()
}

function Resolve-AdMemberDn {
    # Turns member DNs into records, 40 per query, through the Global Catalog so members
    # from other domains of the forest resolve too.
    param($Ctx, [string[]]$Dn)
    $out = [System.Collections.Generic.List[object]]::new()
    $batch = 40
    for ($i = 0; $i -lt $Dn.Count; $i += $batch) {
        $last  = [Math]::Min($i + $batch, $Dn.Count) - 1
        $chunk = @($Dn[$i..$last])
        $terms = foreach ($d in $chunk) { '(distinguishedName={0})' -f (ConvertTo-LdapFilterValue $d) }
        $s = New-AdSearcher -Root $Ctx.GcRoot -Filter ('(|' + ($terms -join '') + ')') -Property $script:AdProperties -PageSize 100
        $found = @{}
        $res = $s.FindAll()
        try {
            foreach ($r in $res) {
                $rec = ConvertTo-AdRecord $Ctx $r
                $found[$rec.Dn.ToLowerInvariant()] = $rec
            }
        }
        finally { $res.Dispose(); $s.Dispose() }

        foreach ($d in $chunk) {
            $rec = $found[$d.ToLowerInvariant()]
            if (-not $rec) {
                # dangling link or an object the GC does not hold
                $rec = [pscustomobject]@{
                    Kind = 'Unknown'; Dn = $d; Sid = ''; Account = ($d -replace '^[^=]+=', '' -replace '(?<!\\),.*$', '')
                    DisplayName = ''; Upn = ''; Enabled = ''; Scope = ''; IsSecurity = $false
                }
            }
            $out.Add($rec)
        }
    }
    $out
}

function Get-AdGroupMemberRecords {
    # Direct members of one group: the 'member' attribute plus anyone whose PRIMARY group
    # it is - that membership is not stored in 'member' (it is how 'Domain Users' works).
    param($Ctx, $Group)
    $records = [System.Collections.Generic.List[object]]::new()

    $dns = Get-AdGroupMemberDn -Ctx $Ctx -GroupDn $Group.Dn
    foreach ($r in (Resolve-AdMemberDn -Ctx $Ctx -Dn $dns)) { $records.Add($r) }

    # only global/universal security groups can be a primary group
    if ($Group.IsSecurity -and ($Group.Scope -eq 'Global' -or $Group.Scope -eq 'Universal') -and $Group.Sid) {
        $rid = $Group.Sid.Substring($Group.Sid.LastIndexOf('-') + 1)
        $s = New-AdSearcher -Root (Get-AdEntry $Ctx (Get-NcOfDn $Ctx $Group.Dn)) -Filter "(primaryGroupID=$rid)" `
                -Property $script:AdProperties -PageSize 1000
        $res = $s.FindAll()
        try { foreach ($r in $res) { $records.Add((ConvertTo-AdRecord $Ctx $r)) } }
        finally { $res.Dispose(); $s.Dispose() }
    }
    $records
}

#endregion

#region ------------------------------------------------------------ expansion

function Test-NameInSet([string]$Account, [hashtable]$Set) {
    if ($Set.Count -eq 0 -or -not $Account) { return $false }
    $name = (Split-Account $Account).Name
    $Set.ContainsKey($Account.ToLowerInvariant()) -or $Set.ContainsKey($name.ToLowerInvariant())
}

function New-MemberRow($Member, $Parent, [int]$Level, [string]$Path) {
    [pscustomobject]@{
        MemberType = $Member.Kind; Member = $Member.Account; MemberSid = $Member.Sid
        DisplayName = $Member.DisplayName; UserPrincipalName = $Member.Upn; Enabled = $Member.Enabled
        NestingLevel = $Level; ParentGroup = $Parent.Account; MembershipPath = $Path
    }
}

function Expand-AdGroupTree {
    # Breadth-first, so the first time a member is met is via the shortest path. Each group
    # is visited once per root, which also makes membership cycles harmless.
    param($Ctx, $Root, [hashtable]$Cache, [hashtable]$SkipSet, [int]$MaxDepth)

    $rows  = [System.Collections.Generic.List[object]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()
    $visitedGroups = @{}
    $visitedGroups[$Root.Dn.ToLowerInvariant()] = $true
    $seenMembers = @{}

    $queue = [System.Collections.Generic.Queue[object]]::new()
    $queue.Enqueue([pscustomobject]@{ Group = $Root; Level = 0; Path = $Root.Account })

    while ($queue.Count -gt 0) {
        $node = $queue.Dequeue()
        $key  = $node.Group.Dn.ToLowerInvariant()
        if (-not $Cache.ContainsKey($key)) {
            $Cache[$key] = @(Get-AdGroupMemberRecords -Ctx $Ctx -Group $node.Group)
        }
        $level = $node.Level + 1

        foreach ($m in $Cache[$key]) {
            if ($m.Kind -eq 'Group') {
                $mk = $m.Dn.ToLowerInvariant()
                if ($visitedGroups.ContainsKey($mk)) { continue }
                $visitedGroups[$mk] = $true
                $rows.Add((New-MemberRow $m $node.Group $level $node.Path))

                if (Test-NameInSet $m.Account $SkipSet) {
                    $notes.Add("Nested group $($m.Account) listed but not expanded (-DoNotExpand).")
                }
                elseif ($level -ge $MaxDepth) {
                    $notes.Add("Nested group $($m.Account) not expanded: nesting deeper than $MaxDepth levels.")
                }
                else {
                    $queue.Enqueue([pscustomobject]@{ Group = $m; Level = $level; Path = "$($node.Path) > $($m.Account)" })
                }
            }
            else {
                $id = if ($m.Sid) { $m.Sid } else { $m.Dn.ToLowerInvariant() }
                if ($seenMembers.ContainsKey($id)) { continue }
                $seenMembers[$id] = $true
                $rows.Add((New-MemberRow $m $node.Group $level $node.Path))
            }
        }
    }
    [pscustomobject]@{ Rows = $rows; Notes = $notes }
}

function Write-GroupRow {
    param($Writer, [string]$Server, [string]$Stamp, $Group, [string]$Status, $Row, [string]$Note)
    $fields = @(
        $Server, $Group.Account, $Group.Sid, $Group.Scope, $Status,
        $(if ($Row) { $Row.MemberType } else { '' }),
        $(if ($Row) { $Row.Member } else { '' }),
        $(if ($Row) { $Row.MemberSid } else { '' }),
        $(if ($Row) { $Row.DisplayName } else { '' }),
        $(if ($Row) { $Row.UserPrincipalName } else { '' }),
        $(if ($Row) { $Row.Enabled } else { '' }),
        $(if ($Row) { $Row.NestingLevel } else { '' }),
        $(if ($Row) { $Row.ParentGroup } else { '' }),
        $(if ($Row) { $Row.MembershipPath } else { '' }),
        $Note, $Stamp
    )
    $Writer.WriteLine((($fields | ForEach-Object { Format-CsvField $_ }) -join ','))
}

function Invoke-GroupMemberExport {
    param(
        $Ctx, [string[]]$Trustee, [string]$OutFile, [string]$Server,
        [string[]]$DoNotExpand, [int]$MaxDepth = 10
    )
    $stamp   = (Get-Date).ToString('s')
    $skipSet = @{}
    foreach ($n in $DoNotExpand) { if ($n) { $skipSet[$n.ToLowerInvariant()] = $true } }

    $trustees = @($Trustee)
    $stats = [ordered]@{
        Trustees = $trustees.Count; Groups = 0; Expanded = 0; Empty = 0; Skipped = 0
        NotFound = 0; Failed = 0; NotGroup = 0; NonDomain = 0; Rows = 0
    }
    $problems = [System.Collections.Generic.List[string]]::new()
    $people   = @{}
    $cache    = @{}

    $partial = "$OutFile.partial"
    $writer  = [System.IO.StreamWriter]::new($partial, $false, [System.Text.UTF8Encoding]::new($false))
    $done = $false
    try {
        $writer.WriteLine('Server,Group,GroupSid,GroupScope,GroupStatus,MemberType,Member,MemberSid,DisplayName,UserPrincipalName,Enabled,NestingLevel,ParentGroup,MembershipPath,Note,ScanTimestamp')

        $i = 0
        foreach ($t in $trustees) {
            $i++
            if ($i % 25 -eq 0 -or $i -eq $trustees.Count) {
                Write-Progress -Activity 'Expanding AD groups' -Status "$i of $($trustees.Count) trustees" `
                    -PercentComplete ([int](100 * $i / [math]::Max(1, $trustees.Count)))
            }

            $acct = Split-Account $t
            if (-not (Test-AdDomain -Ctx $Ctx -Domain $acct.Domain)) { $stats.NonDomain++; continue }

            $ghost = [pscustomobject]@{ Account = $t; Sid = ''; Scope = '' }
            try {
                $group = Find-AdAccount -Ctx $Ctx -Domain $acct.Domain -Name $acct.Name
                if (-not $group) {
                    $stats.NotFound++; $stats.Groups++
                    $problems.Add("not found in AD: $t")
                    Write-GroupRow $writer $Server $stamp $ghost 'NotFound' $null 'No such account in Active Directory (deleted or renamed).'
                    continue
                }
                if ($group.Kind -ne 'Group') { $stats.NotGroup++; continue }   # a user: already a direct grant

                # keep the trustee spelling from the CSV as the join key
                $group.Account = $t
                $stats.Groups++

                if (Test-NameInSet $t $skipSet) {
                    $stats.Skipped++
                    Write-GroupRow $writer $Server $stamp $group 'Skipped' $null 'Not expanded (-DoNotExpand).'
                    continue
                }

                $tree = Expand-AdGroupTree -Ctx $Ctx -Root $group -Cache $cache -SkipSet $skipSet -MaxDepth $MaxDepth
                if ($tree.Rows.Count -eq 0) {
                    $stats.Empty++
                    Write-GroupRow $writer $Server $stamp $group 'Empty' $null ''
                    continue
                }

                $status = if ($tree.Notes.Count -gt 0) { 'Truncated' } else { 'Expanded' }
                $stats.Expanded++
                $first = $true
                foreach ($row in $tree.Rows) {
                    Write-GroupRow $writer $Server $stamp $group $status $row $(if ($first) { $tree.Notes -join ' ' } else { '' })
                    $first = $false
                    $stats.Rows++
                    if ($row.MemberType -eq 'User') { $people[$row.MemberSid] = $true }
                }
                if ($tree.Notes.Count -gt 0) { $problems.Add("$t : $($tree.Notes -join ' ')") }
            }
            catch {
                $stats.Failed++
                $problems.Add("failed to expand ${t}: $($_.Exception.Message)")
                Write-GroupRow $writer $Server $stamp $ghost 'Error' $null $_.Exception.Message
            }
        }
        Write-Progress -Activity 'Expanding AD groups' -Completed
        $done = $true
    }
    finally {
        $writer.Flush(); $writer.Dispose()
        # publish only a finished file so a reader never picks up a half-written set
        if ($done) { Move-Item -LiteralPath $partial -Destination $OutFile -Force }
        else       { Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue }
    }

    [pscustomobject]@{ OutFile = $OutFile; Stats = $stats; Problems = $problems; DistinctUsers = $people.Count }
}

#endregion

# Dot-sourcing (the tests do this) loads the functions without running anything.
if ($MyInvocation.InvocationName -eq '.') { return }

$ErrorActionPreference = 'Stop'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

#region ------------------------------------------------------------------- run

$ntfsCsv = ''; $shareCsv = ''; $trustees = @()
$adhoc = $PSCmdlet.ParameterSetName -eq 'Groups'

if ($adhoc) {
    $trustees = @($Group)
    $server = $env:COMPUTERNAME; $date = (Get-Date).ToString('yyyyMMdd')
    $outDir = if ($OutputDirectory) { $OutputDirectory } else { (Get-Location).ProviderPath }
    $outName = "AD_Group_Members_${server}_${date}_adhoc.csv"
}
else {
    if ($PSCmdlet.ParameterSetName -eq 'Files') {
        if (-not (Test-Path -LiteralPath $NtfsCsv -PathType Leaf)) { throw "NTFS CSV not found: $NtfsCsv" }
        if ($ShareCsv -and -not (Test-Path -LiteralPath $ShareCsv -PathType Leaf)) { throw "Share CSV not found: $ShareCsv" }
        $ntfsCsv  = (Resolve-Path -LiteralPath $NtfsCsv).ProviderPath
        $shareCsv = if ($ShareCsv) { (Resolve-Path -LiteralPath $ShareCsv).ProviderPath } else { '' }
    }
    else {
        $sets = @(Find-ExportSet -Directory $InputDirectory -Date $ScanDate)
        if ($sets.Count -eq 0) {
            throw "No export set (NTFS + share CSV with the same server and date) found in $InputDirectory$(if ($ScanDate) { " for $ScanDate" })."
        }
        $pick = $sets[0]
        if (@($sets | Where-Object { $_.Date -eq $pick.Date }).Count -gt 1) {
            Write-Warning "Several servers exported on $($pick.Date); using $($pick.Server). Pass -NtfsCsv to choose another."
        }
        $ntfsCsv = $pick.NtfsCsv; $shareCsv = $pick.ShareCsv
    }

    # name the output after the NTFS CSV so the files of one export set share server and date
    if ((Split-Path $ntfsCsv -Leaf) -match '^NTFS_Permissions_(?<srv>.+)_(?<date>\d{8})\.csv$') {
        $server = $Matches['srv']; $date = $Matches['date']
    }
    else {
        $server = $env:COMPUTERNAME; $date = (Get-Date).ToString('yyyyMMdd')
    }
    $outDir  = if ($OutputDirectory) { $OutputDirectory } else { Split-Path $ntfsCsv -Parent }
    $outName = "AD_Group_Members_${server}_${date}.csv"

    Write-Host ''
    Write-Host "Reading trustees for $server ($date)" -ForegroundColor Cyan
    Write-Host "  NTFS  : $ntfsCsv"
    Write-Host "  Share : $(if ($shareCsv) { $shareCsv } else { '(none)' })"
    $trustees = @(Get-TrusteeList -NtfsCsv $ntfsCsv -ShareCsv $shareCsv)
}
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$outFile = Join-Path $outDir $outName
Write-Host ("  {0:N0} distinct trustee(s) to look up" -f $trustees.Count)

$ctx = New-AdContext -DomainController $DomainController
Write-Host ("  forest domains: {0}" -f (($ctx.DomainMap.Keys | Sort-Object) -join ', '))

$result = Invoke-GroupMemberExport -Ctx $ctx -Trustee $trustees -OutFile $outFile `
            -Server $server -DoNotExpand $DoNotExpand -MaxDepth $MaxNestingDepth

$s = $result.Stats
Write-Host ''
Write-Host 'Group membership export complete.' -ForegroundColor Green
Write-Host ("  trustees read    : {0:N0}" -f $s.Trustees)
Write-Host ("  AD groups        : {0:N0}  (expanded {1:N0}, empty {2:N0}, skipped {3:N0}, not found {4:N0}, failed {5:N0})" -f
    $s.Groups, $s.Expanded, $s.Empty, $s.Skipped, $s.NotFound, $s.Failed)
Write-Host ("  not groups/local : {0:N0} user accounts, {1:N0} local/BUILTIN/other-domain" -f $s.NotGroup, $s.NonDomain)
Write-Host ("  member rows      : {0:N0}  ({1:N0} distinct user accounts)" -f $s.Rows, $result.DistinctUsers)
Write-Host ("  elapsed          : {0:hh\:mm\:ss}" -f $stopwatch.Elapsed)
if ($result.Problems.Count -gt 0) {
    Write-Host ''
    Write-Host 'Needs a look:' -ForegroundColor Yellow
    $result.Problems | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    if ($result.Problems.Count -gt 20) { Write-Host ("  ... and {0:N0} more (see GroupStatus in the CSV)" -f ($result.Problems.Count - 20)) -ForegroundColor Yellow }
}
Write-Host ''

#endregion

if ($adhoc) {
    Write-Host 'First rows:' -ForegroundColor Cyan
    Import-Csv -LiteralPath $result.OutFile | Select-Object -First 30 |
        Format-Table Group, GroupStatus, MemberType, Member, DisplayName, Enabled, NestingLevel, MembershipPath -AutoSize |
        Out-Host
}

$result.OutFile
