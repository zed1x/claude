# Samba audit – kto kde má prístup

## Kde bola chyba

`Get-FileServerPermissions.ps1` skenuje správne, ale z každého ACL záznamu si zoberie iba
**meno** (`IdentityReference`, riadky 319–337) a zapíše ho do `Trustee`. Nikde sa nepýta
Active Directory, kto je členom skupiny. Preto CSV vie povedať, že `HRteam_write` má právo,
ale nie, ktorí zamestnanci v nej sú.

## Súbory

| Súbor | Čo robí |
|---|---|
| `New-AccessReport.ps1` | **všetko v jednom**: sken oprávnení na file serveri, členovia AD skupín (aj vnorených) a report |
| `Get-FileServerPermissions.ps1` | pôvodný samostatný sken, nezmenený; jeho logika je teraz súčasťou `New-AccessReport.ps1`, takže ho nepotrebujete |

## Spustenie – jeden príkaz

Na **file serveri** (musí vidieť lokálne zdieľania aj ich oprávnenia), v PowerShelli spustenom
ako administrátor:

```powershell
$ps = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }; & $ps -ExecutionPolicy Bypass -File 'C:\scripts\VNET_Samba_Audit\New-AccessReport.ps1'
```

Bez parametrov spraví tri veci a všetko uloží do `q report` vedľa skriptu
(`C:\scripts\VNET_Samba_Audit\q report`):

1. **sken** – `Share_Permissions_<server>_<dátum>.csv`, `NTFS_Permissions_<server>_<dátum>.csv`,
   `Scan_Errors_<server>_<dátum>.csv`,
2. **AD** – `AD_Group_Members_<server>_<dátum>.csv` (kto je v ktorej skupine),
3. **report** – `Access_Report_<server>_<dátum>.csv`.

AD sa skontroluje **ešte pred skenom**, takže chyba s AD sa ukáže hneď, nie po hodinách.
Nič sa nemaže ani nemení; staré CSV v priečinku zostávajú (mazanie po čase tu nie je
implementované).

Iné spôsoby: `-ListSharesOnly` (len vypíše, čo by skenoval), `-Resume` (dokončí prerušený sken),
`-SkipAd` (len sken, tri CSV), `-ShareName 'Hodnotenie*'` (len niektoré zdieľania),
`-InputDirectory '<priečinok>'` (bez skenu, z hotových CSV – najnovšia kompletná sada),
`-Group 'HQ\Domain Admins'` (len test AD, nič neskenuje), `-ExplicitOnly`,
`-DoNotExpand 'Domain Users'`, `-MaxRowsPerFile 1000000` (po tomto počte riadkov nový súbor
`_part2.csv`, aby ho zvládol Excel), `-DomainController dc01`, `-MembersCsv <súbor>`.

Členstvo sa číta z AD **v čase spustenia**.

## Report `Access_Report_*.csv`

Pre každý priečinok a zdieľanie, oprávnenie a osobu jeden riadok. Skupinové oprávnenie sa
rozpíše na každého člena (aj z vnorených skupín), takže vo filtri nájdete osobu → všetky jej
priečinky, alebo priečinok → všetkých ľudí.

Stĺpce: `Layer` (Share / NTFS), `ShareName`, `FolderPath`, `RelativePath`, `BoundaryType`,
`Trustee`, `TrusteeKind` (Group / User / Other), `AccessType`, `Rights`, `RightsDetail`,
`AppliesTo`, `IsInherited`, `InheritedFrom`, `GroupStatus`, `Person`, `PersonName`,
`PersonType`, `Enabled`, `Via` (Direct / Group / NestedGroup), `NestingLevel`, `ParentGroup`,
`MembershipPath`.

- NTFS riadky sú len pri hraniciach oprávnení (koreň zdieľania, zablokované dedenie,
  priečinky s vlastným záznamom). Ich ACL platí pre všetko pod nimi až po ďalšiu hranicu.
- Prístup vyžaduje **obe vrstvy**: oprávnenie zdieľania aj NTFS. Výsledné právo je prísnejšie
  z nich a `Deny` vždy vyhráva. Report vrstvy ukazuje vedľa seba, výsledné právo nepočíta.
- `TrusteeKind = Other` (lokálne, `BUILTIN`, `Everyone`, iná doména, osirelý SID) sa nerozbaľuje
  a nemá `Person`. Skupina bez členov alebo nenájdená má jeden riadok s prázdnym `Person`
  a stavom v `GroupStatus` (`Empty`, `NotFound`, `Error`, ...).
- Ak sa žiadny trustee nezhoduje s doménou lesa (napr. v CSV je iný názov domény), skript na to
  upozorní a vypíše skutočný názov domény.
- Veľkosť: každý člen skupiny je jeden riadok, takže veľké zdieľania môžu dať milióny riadkov
  (na 100 tisíc NTFS záznamov so 400 skupinami po 25 členoch vyšlo 2,4 milióna riadkov za 37 s).

## Súbor `AD_Group_Members_*.csv`

`Server`, `Group` (presne ako `Trustee` v CSV – kľúč na spojenie), `GroupSid`, `GroupScope`,
`GroupStatus` (`Expanded` / `Truncated` / `Empty` / `Skipped` / `NotFound` / `Error`),
`MemberType` (`User`, `Computer`, `Group` = vnorená skupina, `Foreign`, ...), `Member`,
`MemberSid`, `DisplayName`, `UserPrincipalName`, `Enabled` (`False` = zablokovaný účet),
`NestingLevel` (1 = priamy člen), `ParentGroup`, `MembershipPath` (najkratšia cesta), `Note`,
`ScanTimestamp`. Skupina bez členov alebo nerozbalená má jeden riadok s prázdnymi členskými
stĺpcami.

## Čo skript rieši navyše

- **Vnorené skupiny** (aj cyklické) – rozbalí do najkratšej cesty.
- **Viac ako 1500 členov** – číta atribút `member` po rozsahoch.
- **Primárna skupina** – `Domain Users` nemá členov v `member`, skript ich nájde cez `primaryGroupID`.
- **Členovia z iných domén lesa** – cez Global Catalog.
- **Hotové súbory naraz** – výstup sa zapisuje ako `.partial` a premenuje až po dokončení.

## Obmedzenia

- Členovia mimo lesa (cudzie domény) sa vypíšu ako `Foreign` a nerozbaľujú sa.
- Lokálne skupiny file servera sa nerozbaľujú.

## Testy

```powershell
pwsh -File tests\Test-EndToEnd.ps1          # celý príkaz (sken, AD, report) s falošným AD
pwsh -File tests\Test-NewAccessReport.ps1   # report nad vymyslenými CSV
pwsh -File tests\Test-AdGroupExpansion.ps1  # rozbaľovanie skupín
```

(alebo `powershell.exe -File ...`). Bežia bez AD a bez Windows, takže **nepokrývajú samotné LDAP
volania ani čítanie ACL zo skutočného file servera**. Prvé spustenie na serveri je ich skutočný test;
chyba AD sa vtedy ukáže pred skenom.
