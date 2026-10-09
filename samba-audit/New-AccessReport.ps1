<#
.SYNOPSIS
    One script: reads the permission CSVs, asks Active Directory who is in the groups,
    and writes one CSV report of who can reach which folder and through which group.

.DESCRIPTION
    Run it by hand on a domain-joined Windows machine, from any folder:

        powershell -ExecutionPolicy Bypass -File .\New-AccessReport.ps1 -InputDirectory 'C:\scripts\VNET_Samba_Audit\q report'

    It takes the newest export set in that folder (Share_Permissions_*, NTFS_Permissions_*,
    same server and date), looks every group trustee up in Active Directory - nested groups
    included - and writes
        AD_Group_Members_<Server>_<date>.csv    who is in each group (also useful on its own)
        Access_Report_<Server>_<date>.csv       the report
    next to the NTFS CSV. It only reads: LDAP searches as the current user, no modules.

    Check that AD access works before a big run - this needs no CSV at all:

        powershell -ExecutionPolicy Bypass -File .\New-AccessReport.ps1 -Group 'HQ\Domain Admins'

    Report columns
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
                      how the person is in the group

    Access to a folder needs BOTH layers: the share permission and the NTFS permission.
    The effective right is the more restrictive of the two, and a Deny wins over an Allow.
    The report lists the layers side by side and does not compute that for you.

    Membership is read from AD at the moment you run it, not as of the scan date.

    Size: every group entry becomes one row per member, so a large share can run to
    millions of rows. Output is split into parts of -MaxRowsPerFile rows (default 1,000,000,
    which stays under the Excel row limit): ..._part2.csv, ... Use -ShareName or
    -ExplicitOnly to get a smaller report.

.PARAMETER InputDirectory
    Folder with the CSVs; the newest complete export set is used.

.PARAMETER ScanDate
    With -InputDirectory, use this export date (yyyyMMdd) instead of the newest.

.PARAMETER NtfsCsv
    Use this NTFS CSV instead of -InputDirectory.

.PARAMETER ShareCsv
    The matching share CSV (optional).

.PARAMETER MembersCsv
    Use an existing AD_Group_Members CSV and do not query AD.

.PARAMETER Group
    Test mode: expand only these groups ('DOMAIN\Name'), print the members, write
    AD_Group_Members_<computer>_<date>_adhoc.csv. No CSVs needed.

.PARAMETER OutputDirectory
    Where the files are written. Defaults to the folder of the NTFS CSV.

.PARAMETER ShareName
    Only these shares (wildcards accepted).

.PARAMETER ExplicitOnly
    NTFS: only entries set directly on a folder (not inherited), plus everything on the
    share root. Much smaller, but a folder's inherited groups are then not listed there.

.PARAMETER MaxRowsPerFile
    Start a new file after this many rows. 0 = never split.

.PARAMETER DomainController
    Query this DC instead of letting Windows pick one.

.PARAMETER DoNotExpand
    Groups to list but not expand (full 'DOMAIN\Name' or just the name), e.g. 'Domain Users',
    which would add one row per employee.

.PARAMETER MaxNestingDepth
    Stop descending into nested groups past this level; the group is then marked Truncated.

.EXAMPLE
    .\New-AccessReport.ps1 -InputDirectory 'C:\scripts\VNET_Samba_Audit\q report'

.EXAMPLE
    .\New-AccessReport.ps1 -InputDirectory .\Reports -ShareName 'Hodnotenie*' -DoNotExpand 'Domain Users'
#>
[CmdletBinding(DefaultParameterSetName = 'Directory')]
param(
    [Parameter(ParameterSetName = 'Directory')]
    [string]$InputDirectory = (Join-Path $PSScriptRoot 'Reports'),

    [Parameter(ParameterSetName = 'Directory')]
    [ValidatePattern('^\d{8}$')]
    [string]$ScanDate,

    [Parameter(ParameterSetName = 'Files', Mandatory)]
    [string]$NtfsCsv,

    [Parameter(ParameterSetName = 'Files')]
    [string]$ShareCsv,

    [Parameter(ParameterSetName = 'Groups', Mandatory)]
    [string[]]$Group,

    [string]  $MembersCsv,
    [string]  $OutputDirectory,
    [string[]]$ShareName,
    [switch]  $ExplicitOnly,
    [ValidateRange(0, 2000000000)][int]$MaxRowsPerFile = 1000000,
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

# one tail = the nine person-level columns, already CSV-formatted:
# GroupStatus, Person, PersonName, PersonType, Enabled, Via, NestingLevel, ParentGroup, MembershipPath
function New-Tail($Status, $Person, $Name, $Type, $Enabled, $Via, $Level, $Parent, $Path) {
    Join-CsvRow @($Status, $Person, $Name, $Type, $Enabled, $Via, $Level, $Parent, $Path)
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
    # carry NetBIOS names (HQ\Group); LDAP needs the DN. Anything not in this map is a
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

#region ------------------------------------------------------------------ report

function New-AccessReportFiles {
    # Joins the share CSV, NTFS CSV and membership CSV into the report. Returns the file paths.
    param(
        [string]$Server, [string]$ShareCsv, [string]$NtfsCsv, [string]$MembersCsv, [string]$OutFile,
        [string[]]$ShareName, [switch]$ExplicitOnly, [int]$MaxRowsPerFile
    )

    #region ------------------------------------------------------------ membership

    # group -> @{ Status; Tails }, account -> @{ Name; Enabled }
    $groups = @{}
    $people = @{}
    $knownDomains = @{}

    $memberRows = @(Import-Csv -LiteralPath $MembersCsv -Encoding UTF8)
    foreach ($c in 'Group', 'GroupStatus', 'MemberType', 'Member') {
        if ($memberRows.Count -gt 0 -and -not ($memberRows[0].PSObject.Properties.Name -contains $c)) {
            throw "Column '$c' not found in $membersCsv - was it made by New-AccessReport.ps1?"
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
        if ($ShareCsv) {
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

        }

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


    return @($parts | ForEach-Object { $_.Final })
}

#endregion

# Dot-sourcing (the tests do this) loads the functions without running anything.
if ($MyInvocation.InvocationName -eq '.') { return }

$ErrorActionPreference = 'Stop'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

#region ------------------------------------------------------------------- run

# --- test mode: a few groups straight from AD ---
if ($PSCmdlet.ParameterSetName -eq 'Groups') {
    $server  = $env:COMPUTERNAME
    $outDir  = if ($OutputDirectory) { $OutputDirectory } else { (Get-Location).ProviderPath }
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $outFile = Join-Path $outDir ("AD_Group_Members_{0}_{1}_adhoc.csv" -f $server, (Get-Date).ToString('yyyyMMdd'))

    $ctx = New-AdContext -DomainController $DomainController
    Write-Host ("forest domains: {0}" -f (($ctx.DomainMap.Keys | Sort-Object) -join ', '))
    $result = Invoke-GroupMemberExport -Ctx $ctx -Trustee @($Group) -OutFile $outFile -Server $server `
                -DoNotExpand $DoNotExpand -MaxDepth $MaxNestingDepth

    $s = $result.Stats
    Write-Host ''
    Write-Host ("AD groups: {0}  (expanded {1}, empty {2}, skipped {3}, not found {4}, failed {5}); not groups/other domain: {6}" -f
        $s.Groups, $s.Expanded, $s.Empty, $s.Skipped, $s.NotFound, $s.Failed, ($s.NotGroup + $s.NonDomain)) -ForegroundColor Green
    foreach ($p in $result.Problems) { Write-Host "  $p" -ForegroundColor Yellow }
    Write-Host ''
    # as text: Out-Host prints nothing when the output is redirected
    Write-Host (Import-Csv -LiteralPath $result.OutFile -Encoding UTF8 | Select-Object -First 30 |
        Format-Table Group, GroupStatus, MemberType, Member, DisplayName, Enabled, NestingLevel, MembershipPath -AutoSize |
        Out-String -Width 220)
    Write-Host "Written: $($result.OutFile)"
    return
}

# --- find the export set ---
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
if ($MembersCsv -and -not (Test-Path -LiteralPath $MembersCsv -PathType Leaf)) { throw "Membership CSV not found: $MembersCsv" }

if ((Split-Path $ntfsCsv -Leaf) -match '^NTFS_Permissions_(?<srv>.+)_(?<date>\d{8})\.csv$') {
    $server = $Matches['srv']; $date = $Matches['date']
}
else {
    $server = $env:COMPUTERNAME; $date = (Get-Date).ToString('yyyyMMdd')
}
$outDir = if ($OutputDirectory) { $OutputDirectory } else { Split-Path $ntfsCsv -Parent }
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

Write-Host ''
Write-Host "Access report for $server ($date)" -ForegroundColor Cyan
Write-Host "  Share : $(if ($shareCsv) { $shareCsv } else { '(none)' })"
Write-Host "  NTFS  : $ntfsCsv"

# --- step 1: group membership from AD (unless an existing file was given) ---
if ($MembersCsv) {
    $membersCsv = (Resolve-Path -LiteralPath $MembersCsv).ProviderPath
    Write-Host "  Members: $membersCsv (existing file, AD not queried)"
}
else {
    Write-Host ''
    Write-Host 'Step 1/2: reading group membership from Active Directory' -ForegroundColor Cyan
    $trustees = @(Get-TrusteeList -NtfsCsv $ntfsCsv -ShareCsv $shareCsv)
    Write-Host ("  {0:N0} distinct trustee(s) to look up" -f $trustees.Count)

    $ctx = New-AdContext -DomainController $DomainController
    Write-Host ("  forest domains: {0}" -f (($ctx.DomainMap.Keys | Sort-Object) -join ', '))

    $membersCsv = Join-Path $outDir "AD_Group_Members_${server}_${date}.csv"
    $result = Invoke-GroupMemberExport -Ctx $ctx -Trustee $trustees -OutFile $membersCsv -Server $server `
                -DoNotExpand $DoNotExpand -MaxDepth $MaxNestingDepth

    $s = $result.Stats
    Write-Host ''
    Write-Host ("  AD groups        : {0:N0}  (expanded {1:N0}, empty {2:N0}, skipped {3:N0}, not found {4:N0}, failed {5:N0})" -f
        $s.Groups, $s.Expanded, $s.Empty, $s.Skipped, $s.NotFound, $s.Failed)
    Write-Host ("  not groups/local : {0:N0} user accounts, {1:N0} local/BUILTIN/other-domain" -f $s.NotGroup, $s.NonDomain)
    Write-Host ("  member rows      : {0:N0}  ({1:N0} distinct user accounts)" -f $s.Rows, $result.DistinctUsers)
    if ($s.Groups -eq 0) {
        Write-Warning ("No trustee matched a domain of this forest ({0}). Check that the domain names in the CSV match; the report will not list any people." -f
            (($ctx.DomainMap.Keys | Sort-Object) -join ', '))
    }
    if ($result.Problems.Count -gt 0) {
        Write-Host 'Needs a look:' -ForegroundColor Yellow
        $result.Problems | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        if ($result.Problems.Count -gt 20) { Write-Host ("  ... and {0:N0} more (see GroupStatus in the CSV)" -f ($result.Problems.Count - 20)) -ForegroundColor Yellow }
    }
}

# --- step 2: the report ---
Write-Host ''
Write-Host 'Step 2/2: building the report' -ForegroundColor Cyan
$reportFile = Join-Path $outDir "Access_Report_${server}_${date}.csv"
$files = New-AccessReportFiles -Server $server -ShareCsv $shareCsv -NtfsCsv $ntfsCsv -MembersCsv $membersCsv `
            -OutFile $reportFile -ShareName $ShareName -ExplicitOnly:$ExplicitOnly -MaxRowsPerFile $MaxRowsPerFile

#endregion

$files[0]
