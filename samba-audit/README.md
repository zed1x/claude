# Samba audit – členovia AD skupín

## Kde bola chyba

`Get-FileServerPermissions.ps1` je v poriadku, čo robí, ale nerobí všetko: z každého ACL
záznamu si zoberie iba **meno** (`IdentityReference`, riadky 319–337) a zapíše ho do
`Trustee`. Nikde sa nepýta Active Directory, kto je členom skupiny. Preto CSV vie povedať,
že `HRteam_write` má právo, ale nie, ktorí zamestnanci v nej sú.

Chýbajúci údaj dopĺňa nový skript `Get-ADGroupMembers.ps1`. Hlavný exportný skript som
**nemenil** a nič ho nevolá automaticky – spúšťa sa ručne.

## Ručné spustenie

Na doménovom počítači (file server, DC alebo admin stanica), bežný doménový účet stačí,
PowerShell 5.1, žiadne moduly.

1. **Najprv skúška na jednej skupine** (overí prístup k AD, nič iné nečíta):

   ```powershell
   .\Get-ADGroupMembers.ps1 -Group 'HQ\HRteam_write'
   ```

   Vypíše prvých 30 riadkov a uloží `AD_Group_Members_<počítač>_<dátum>_adhoc.csv`.

2. **Celý export** nad existujúcimi CSV (najnovšia kompletná dvojica NTFS + Share v priečinku):

   ```powershell
   .\Get-ADGroupMembers.ps1 -InputDirectory 'C:\scripts\VNET_Samba_Audit\q report'
   ```

   Konkrétny dátum: `-ScanDate 20260825`. Konkrétne súbory: `-NtfsCsv ... -ShareCsv ...`.

Výstup `AD_Group_Members_SRV020_20260825.csv` dostane server a dátum z NTFS CSV, takže patrí
k tej istej sade ako ostatné tri súbory. Zapisuje sa najprv ako `.partial` a premenuje sa
až po dokončení, takže web nikdy neuvidí polovičný súbor.

Užitočné prepínače: `-DoNotExpand 'Domain Users'` (veľké skupiny vypíše, ale nerozbalí),
`-DomainController dc01`, `-MaxNestingDepth 10`.

**Pozor:** členstvo je zo stavu AD **v čase spustenia**, nie v čase skenu (stĺpec
`ScanTimestamp`). Pre augustové CSV spustené dnes dostanete dnešné členstvo.

Čítanie 447-tisíc riadkov NTFS CSV trvá rádovo desiatky sekúnd; potom ide o dotazy do AD,
jeden okruh na každú skupinu z ACL.

## Formát `AD_Group_Members_<Server>_<yyyyMMdd>.csv`

| Stĺpec | Význam |
|---|---|
| `Group` | skupina presne tak, ako je v `Trustee` v NTFS/Share CSV – **kľúč na spojenie** |
| `GroupSid`, `GroupScope` | SID a rozsah (Global / Universal / DomainLocal) |
| `GroupStatus` | `Expanded`, `Truncated` (príliš hlboké vnorenie), `Empty`, `Skipped`, `NotFound`, `Error` |
| `MemberType` | `User`, `Computer`, `Group` (vnorená skupina), `Foreign`, `Contact`, `Unknown` |
| `Member`, `MemberSid`, `DisplayName`, `UserPrincipalName` | člen |
| `Enabled` | `False` = zablokovaný účet (právo má, ale nemôže sa prihlásiť) |
| `NestingLevel` | 1 = priamy člen, 2 = člen vnorenej skupiny, … |
| `ParentGroup` | skupina, ktorá člena priamo obsahuje |
| `MembershipPath` | `Group > vnorená > … > ParentGroup` (najkratšia cesta) |
| `Note` | podrobnosť k stavu (chyba, hĺbka) |
| `ScanTimestamp` | kedy sa členstvo čítalo |

Pravidlá pre report:

- Ľudia s prístupom cez skupinu: `Group = <Trustee>` a `MemberType = User`.
- Skupina bez členov alebo bez výsledku má **jeden riadok** s prázdnymi členskými stĺpcami
  a stavom v `GroupStatus` – rozlíšite „prázdna“ od „nenájdená“.
- Používateľ uvedený priamo v ACL nemá v tomto súbore riadok (je to priamy záznam v NTFS CSV).
- Lokálne a `BUILTIN` skupiny, `Everyone` a iné domény sa nerozbaľujú a v súbore nie sú.
- Súbor je voliteľný: staršie sady bez neho treba v reporte zobraziť ako doteraz.

Ukážka (vymyslené mená, nie skutočné oprávnenia):

```csv
Group,GroupStatus,MemberType,Member,DisplayName,Enabled,NestingLevel,ParentGroup,MembershipPath
HQ\HRteam_write,Expanded,User,HQ\jnovak,Ján Novák,True,1,HQ\HRteam_write,HQ\HRteam_write
HQ\HRteam_write,Expanded,Group,HQ\HR_Managers,HR_Managers,,1,HQ\HRteam_write,HQ\HRteam_write
HQ\HRteam_write,Expanded,User,HQ\mkrasna,Mária Krásna,True,2,HQ\HR_Managers,HQ\HRteam_write > HQ\HR_Managers
HQ\Old_Group,NotFound,,,,,,,
```

## Report „kto kde má prístup“ (`New-AccessReport.ps1`)

Spojí Share CSV, NTFS CSV a `AD_Group_Members_*.csv` do jedného súboru
`Access_Report_<Server>_<dátum>.csv`. Skupinové oprávnenie sa rozpíše na jeden riadok
na každého člena (aj z vnorených skupín), takže vo filtri nájdete osobu → všetky jej
priečinky, alebo priečinok → všetkých ľudí. Beží ručne, s AD nekomunikuje.

```powershell
.\New-AccessReport.ps1 -InputDirectory 'C:\scripts\VNET_Samba_Audit\q report'
```

Najprv musí existovať `AD_Group_Members_*.csv` (krok vyššie), inak skript povie, čo spustiť.

Užitočné prepínače: `-ShareName 'Hodnotenie*'` (len niektoré zdieľania), `-ExplicitOnly`
(z NTFS iba oprávnenia nastavené priamo na priečinku, plus celý koreň zdieľania),
`-MaxRowsPerFile 1000000` (po tomto počte riadkov začne nový súbor `_part2.csv`, aby ho
zvládol Excel).

Stĺpce: `Layer` (Share / NTFS), `ShareName`, `FolderPath`, `RelativePath`, `BoundaryType`,
`Trustee`, `TrusteeKind` (Group / User / Other), `AccessType`, `Rights`, `RightsDetail`,
`AppliesTo`, `IsInherited`, `InheritedFrom`, `GroupStatus`, `Person`, `PersonName`,
`PersonType`, `Enabled`, `Via` (Direct / Group / NestedGroup), `NestingLevel`, `ParentGroup`,
`MembershipPath`.

- NTFS riadky sú len pri hraniciach oprávnení (koreň zdieľania, zablokované dedenie,
  priečinky s vlastným záznamom). Ich ACL platí pre všetko pod nimi až po ďalšiu hranicu.
- Prístup vyžaduje **obe vrstvy**: oprávnenie zdieľania aj NTFS. Výsledné právo je prísnejšie
  z nich a `Deny` vždy vyhráva. Report vrstvy ukazuje vedľa seba, výsledné právo nepočíta.
- `TrusteeKind = Other` (lokálne, `BUILTIN`, `Everyone`, iná doména) sa nerozbaľuje a nemá
  `Person`. Skupina bez členov alebo nenájdená má jeden riadok s prázdnym `Person` a stavom
  v `GroupStatus`.
- Veľkosť: každý člen skupiny je jeden riadok, takže veľké zdieľania môžu dať milióny riadkov
  (na 100 tisíc NTFS záznamov so 400 skupinami po 25 členoch vyšlo 2,4 milióna riadkov za 37 s).

## Čo skript rieši navyše

- **Vnorené skupiny** (aj cyklické) – rozbalí do najkratšej cesty.
- **Viac ako 1500 členov** – číta atribút `member` po rozsahoch.
- **Primárna skupina** – `Domain Users` nemá členov v `member`, skript ich nájde cez `primaryGroupID`.
- **Členovia z iných domén lesa** – cez Global Catalog.

## Obmedzenia

- Členovia mimo lesa (cudzie domény) sa vypíšu ako `Foreign` a nerozbaľujú sa.
- Lokálne skupiny file servera sa nerozbaľujú.
- Nerozpoznaný SID (`SidResolved = False`) sa preskočí – zmazaný alebo cudzí účet.

## Testy

```powershell
pwsh -File tests\Test-GetADGroupMembers.ps1      # alebo powershell.exe -File ...
pwsh -File tests\Test-NewAccessReport.ps1
```

Obe súpravy bežia bez AD nad vymyslenými dátami; prvá nad vymyslenou „databázou“ a overuje čítanie CSV, vnorenie, cykly, najkratšiu
cestu, limity, stavy skupín a zápis CSV (49 kontrol). **Nepokrýva samotné LDAP volania** –
tie sa dajú overiť iba na doménovom stroji, preto je tam krok 1 (`-Group`).
