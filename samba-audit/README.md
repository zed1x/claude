# Samba audit – kto kde má prístup

## Kde bola chyba

`Get-FileServerPermissions.ps1` skenuje správne, ale z každého ACL záznamu si zoberie iba
**meno** (`IdentityReference`, riadky 319–337) a zapíše ho do `Trustee`. Nikde sa nepýta
Active Directory, kto je členom skupiny. Preto CSV vie povedať, že `HRteam_write` má právo,
ale nie, ktorí zamestnanci v nej sú.

## Súbory

| Súbor | Čo robí | Kde beží |
|---|---|---|
| `Get-FileServerPermissions.ps1` | sken oprávnení, vyrobí `Share_Permissions_*`, `NTFS_Permissions_*`, `Scan_Errors_*` (nezmenený) | file server |
| `New-AccessReport.ps1` | **všetko ostatné v jednom súbore**: načíta CSV, opýta sa AD na členov skupín (aj vnorených) a zloží report | ľubovoľný doménový Windows |

Nič sa nespúšťa automaticky.

## Spustenie

Jeden príkaz, z ľubovoľného priečinka, s plnou cestou k skriptu:

```powershell
powershell -ExecutionPolicy Bypass -File 'C:\scripts\VNET_Samba_Audit\New-AccessReport.ps1' -InputDirectory 'C:\scripts\VNET_Samba_Audit\q report'
```

Vezme **najnovšiu kompletnú sadu** CSV v priečinku (Share + NTFS s rovnakým serverom a dátumom),
a vedľa nich zapíše:

- `AD_Group_Members_<server>_<dátum>.csv` – kto je v ktorej skupine (využiteľné aj samostatne),
- `Access_Report_<server>_<dátum>.csv` – report.

**Najprv skúška, či AD funguje** (nepotrebuje žiadne CSV):

```powershell
powershell -ExecutionPolicy Bypass -File 'C:\scripts\VNET_Samba_Audit\New-AccessReport.ps1' -Group 'HQ\Domain Admins'
```

Užitočné prepínače: `-ShareName 'Hodnotenie*'` (len niektoré zdieľania), `-ExplicitOnly`
(z NTFS iba oprávnenia nastavené priamo na priečinku, plus koreň zdieľania),
`-DoNotExpand 'Domain Users'` (skupinu vypíše, ale nerozbalí), `-MaxRowsPerFile 1000000`
(po tomto počte riadkov začne nový súbor `_part2.csv`, aby ho zvládol Excel),
`-ScanDate 20260825` (konkrétna sada), `-MembersCsv <súbor>` (použije hotový súbor členov
a AD sa nepýta), `-DomainController dc01`.

Členstvo sa číta z AD **v čase spustenia**, nie k dátumu skenu.

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
pwsh -File tests\Test-EndToEnd.ps1          # celý príkaz s falošným AD
pwsh -File tests\Test-NewAccessReport.ps1   # report nad vymyslenými CSV
pwsh -File tests\Test-AdGroupExpansion.ps1  # rozbaľovanie skupín
```

(alebo `powershell.exe -File ...`). Bežia bez AD, **nepokrývajú samotné LDAP volania** – tie sa
dajú overiť iba na doménovom stroji, preto je skúška `-Group`.
