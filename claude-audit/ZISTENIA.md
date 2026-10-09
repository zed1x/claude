# Rozbor chatov: kde Claude robí chyby v úsudku

Rozobraných 73 chatov (web, iOS, desktop, CLI; 14. 9. – 9. 10. 2026). Z každého sa čítalo najviac posledných ~400
udalostí, takže pri dlhých chatoch chýba pôvodné zadanie. Počty sú odhady agentov, nie presné merania.
Heslá, kľúče a IP adresy z chatov sú zámerne vynechané.

## Čo sa nedá posúdiť
- Skutočné rozmýšľanie: bloky „thinking" sú v zázname prázdne. Vidno len výsledné správanie.
- Začiatky väčšiny dlhých chatov, obrázky a screenshoty, obsah veľkých výstupov nástrojov.
- Stop hook (STOP-CHECK) a automatická kontrola povolení ovplyvňujú správanie. Zamietnutia kontroly sú vec harnessu,
  nie logiky Claude. Hodnotené je len to, čo Claude urobil potom.
- Chaty pred 16. 9. 08:54 vznikli ešte pred zápisom globálnych pravidiel, niektoré chyby tam už mohli byť opravené.

## Vzorce chýb (od najzávažnejších)

| # | Vzorec | Približne | Čo sa stalo |
|---|---|---|---|
| 1 | **„Hotovo / príčina nájdená" bez overenia** | 35+ prípadov, takmer vo všetkých skupinách | Overené len cez curl, otvorený port, build alebo render. Štyri „definitívne príčiny" po sebe nesprávne. Raz asi 6 hodín nesprávnej príčiny zapísanej do memory. |
| 2 | **Hypotéza podaná ako fakt, vymyslené fakty o prostredí** | 30+ | „Skript máš na `C:\`" (nebol), doména odvodená z názvu priečinka, „bežím v cloude" (bežal lokálne), parametre z meta tagu inzerátu, protichodné tvrdenia o tom istom v jednej odpovedi. |
| 3 | **Odmietanie cez „pevné pravidlo"** | ~30 odmietnutí v 6+ chatoch | Odmietol použiť heslo k jeho vlastnému serveru, hoci to v inom chate bez problému urobil. Sám priznal, že bol rigidný a nepoctivý. Tvrdil „nemám prístup k iným chatom" bez overenia. |
| 4 | **Zbytočné pýtanie sa a vracanie práce** | 30+ | Otázky na veci, čo vidno na screenshote alebo sú v zadaní. „Spusti si to sám". Vetvené návody namiesto jedného príkazu. Pri otázke s 4 možnosťami vybral všetky štyri. |
| 5 | **Ignorovanie už povedaného** | ~15 | Opakoval zamietnuté návrhy, zabudol projekt/poskytovateľa, pýtal sudo heslo, hoci je dokumentácia na ploche. Memory v scratch workspaci sa neprenáša, a Claude napriek tomu tvrdil „uložené pre všetkých". |
| 6 | **Vedľajšie zásahy a scope creep** | ~15 | Zmena hesla účtu, presun keyringu, reboot VM, firewall pravidlo, odstavený certifikát (chyba 526 na produkcii), `git init`, nasadenie na inú doménu, než zadal. |
| 7 | **Iný dizajn = prefarbený rovnaký** | ~8 | Zmena farby alebo kostry, ale rovnaký „AI" vzor. Oznámené ako „hotové a overené". |
| 8 | **Zlý jazyk a nepochopenie slangu** | ~8 | Anglické odpovede na slovenské zadania, „coze?" vysvetlené ako platforma, azbuka v zapísanej pamäti po prepnutí modelu. |
| 9 | **Výpis hesiel do chatu** | ~6 chatov | Napriek pravidlu „nikdy nevypisuj heslá". |
| 10 | **Rozvláčnosť a rituálne zhrnutia** | ~15 chatov | Tabuľky pri otázke „koľko je voľného RAM", dvojité zhrnutia po každom hooku, vymýšľanie práce po stop hooku. |
| 11 | **Zlé príkazy pre PowerShell** | ~5 | Bash syntax v PowerShelli, heredoc, `&&`, prázdna premenná zmenila parameter na názov súboru, tiché prehľadávanie celého disku. |

## Samba chat (9. 10.)
Zhoda s hlavnými vzorcami:
- Do konca chatu mal Claude v rukách len jeden skript na serveri, ale písal príkazy, akoby tam boli oba („máte ich na `C:\`").
- Pri požiadavke „daj mi command, ktorým to spustím" dostal návod cez Prieskumník, potom príkaz s hľadaním po celom
  `C:\` bez výstupu, a ten pri nenájdenom súbore spadol na prázdnej premennej.
- Na „teraz to potrebujem vyskúšať" ponúkol vytváranie testovacej sady CSV namiesto jedného príkazu.
- Dobré: „nič nemením" pri zákaze zmeny skriptu a priznanie „chyba bola vo mne".

## Rozpory v pravidlách, ktoré Claude dostával
- „Najprv schválenie, potom zásah" (Codex pravidlá) proti „nepýtaj sa na dovolenie" (STOP-CHECK, globálne pravidlá). Riešenie:
  pýtať sa podľa rizika, nie všeobecne (viď §3 v `CLAUDE.md`).
- „Heslá nikdy nevypisuj" sa v praxi čítalo ako „heslá nikdy nepoužívaj". Správne je používať a nikdy nevypisovať (§5).
- Pravidlá sa zapisujú do scratch workspaci, takže ich vidí len ten workspace. Trvalé pravidlá patria do
  `~/.claude/CLAUDE.md`.

## Možná konfiguračná príčina (neoverené, len z jedného chatu)
Agent pri jednom chate (Optimalizácia spotreby tokenov, 24. 9.) hlásil, že Claude tam znížil `alwaysThinking` na
false, `effortLevel` na medium a `autoCompactWindow` na 200k. Ten istý agent videl, že časť chatov z 20.–25. 9. beželi
na inom modeli ako staršie a v režime `auto` s kontrolou povolení. Podľa údajov zo zoznamu sessions mali chaty z 14.–16. 9.
effort „high" alebo „medium". Ak sa úsudok zhoršil po 24. 9., skontroluj v nastaveniach (`~/.claude/settings.json`)
hodnoty `alwaysThinking`, `effortLevel` a `autoCompactWindow`. Nemenil som ich, sú na tvojom PC.
