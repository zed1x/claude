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
   .\Get-ADGroupMembers.ps1 -Group 'VNET\HRteam_write'
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
VNET\HRteam_write,Expanded,User,VNET\jnovak,Ján Novák,True,1,VNET\HRteam_write,VNET\HRteam_write
VNET\HRteam_write,Expanded,Group,VNET\HR_Managers,HR_Managers,,1,VNET\HRteam_write,VNET\HRteam_write
VNET\HRteam_write,Expanded,User,VNET\mkrasna,Mária Krásna,True,2,VNET\HR_Managers,VNET\HRteam_write > VNET\HR_Managers
VNET\Old_Group,NotFound,,,,,,,
```

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
```

Beží bez AD nad vymyslenou „databázou“ a overuje čítanie CSV, vnorenie, cykly, najkratšiu
cestu, limity, stavy skupín a zápis CSV (49 kontrol). **Nepokrýva samotné LDAP volania** –
tie sa dajú overiť iba na doménovom stroji, preto je tam krok 1 (`-Group`).
