#!/usr/bin/env python3
"""BIAKS Shop - zámerne zraniteľná webová aplikácia (SQL Injection).

BIAKS ZS 2026/27, Zadanie 2. Iba na výučbové účely, server počúva len na 127.0.0.1.

Aplikácia beží ako JEDNA stránka s prepínačom SECURE v hlavičke. Prepínač mení
správanie za behu (bez reštartu):
    SECURE OFF -> ZRANITEĽNÝ režim  (SQL sa skladá reťazcami)
    SECURE ON  -> BEZPEČNÝ režim    (parametrizované dotazy, placeholder ?)

Spustenie:
    python3 app.py                # štart v zraniteľnom režime (prepni v UI)
    python3 app.py --safe         # štart rovno v bezpečnom režime
    python3 app.py --port 8080

Zraniteľné miesta (v režime SECURE OFF):
    GET  /products?cat=1      numerický parameter bez úvodzoviek  -> UNION-based SQLi
    GET  /search?q=lamp       reťazec v LIKE '%...%'              -> UNION-based SQLi
    POST /login               meno a heslo v '...'                -> obídenie prihlásenia
"""

import argparse
import html
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

SAFE = False
db = None


def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.executescript("""
        CREATE TABLE categories (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL,
                               category_id INTEGER REFERENCES categories(id));
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT,
                            role TEXT, email TEXT);

        INSERT INTO categories VALUES (1, 'Notebooky'), (2, 'Príslušenstvo'), (3, 'Siete');
        INSERT INTO products VALUES
            (1, 'Notebook Lenovo ThinkPad T14', 1299.00, 1),
            (2, 'Notebook Dell Latitude 5440', 1149.00, 1),
            (3, 'Myš Logitech MX Master 3S', 109.90, 2),
            (4, 'Klávesnica Keychron K2', 89.00, 2),
            (5, 'Stolová lampa LED', 34.50, 2),
            (6, 'Router MikroTik hAP ax2', 79.00, 3),
            (7, 'Switch TP-Link TL-SG108', 25.90, 3);
        INSERT INTO users VALUES
            (1, 'admin',  'Sup3rTajneHeslo!', 'admin', 'admin@biaks-shop.local'),
            (2, 'jnovak', 'jano1990',         'user',  'jan.novak@example.com'),
            (3, 'mkovac', 'heslo123',         'user',  'maria.kovacova@example.com');
    """)
    return conn


# --- prístup k databáze -------------------------------------------------------
# Každá funkcia vráti (sql, riadky). Zraniteľná vetva skladá SQL z reťazcov,
# bezpečná vetva posiela vstup oddelene ako parameter (placeholder ?).

def query_products(cat):
    if SAFE:
        sql = "SELECT id, name, price FROM products WHERE category_id = ?"
        return sql, db.execute(sql, (cat,)).fetchall()
    sql = f"SELECT id, name, price FROM products WHERE category_id = {cat}"
    return sql, db.execute(sql).fetchall()


def query_search(q):
    if SAFE:
        sql = "SELECT id, name, price FROM products WHERE name LIKE ?"
        return sql, db.execute(sql, (f"%{q}%",)).fetchall()
    sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
    return sql, db.execute(sql).fetchall()


def query_login(username, password):
    if SAFE:
        sql = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
        return sql, db.execute(sql, (username, password)).fetchall()
    sql = (f"SELECT id, username, role FROM users "
           f"WHERE username = '{username}' AND password = '{password}'")
    return sql, db.execute(sql).fetchall()


# --- HTML ----------------------------------------------------------------------

STYLE = """
 :root { --bg:#f6f7f9; --card:#fff; --line:#e2e5ea; --ink:#1f2430; --muted:#6b7280; }
 * { box-sizing: border-box; }
 body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; color: var(--ink);
        background: var(--bg); margin: 0; }
 .wrap { max-width: 900px; margin: 0 auto; padding: 0 20px 48px; }
 header { background: var(--card); border-bottom: 1px solid var(--line); }
 .bar { max-width:900px; margin:0 auto; padding:14px 20px; display:flex;
        align-items:center; gap:16px; }
 .brand { font-weight: 700; font-size: 1.15rem; }
 .brand small { color: var(--muted); font-weight: 400; font-size: .8rem; }
 .spacer { flex: 1; }
 /* prepínač SECURE */
 .switch { display:flex; align-items:center; gap:10px; text-decoration:none; color:inherit;
           font-size:.85rem; font-weight:600; }
 .track { width:52px; height:28px; border-radius:999px; position:relative;
          transition:.15s; background:#d1495b; }
 .track.on { background:#2a9d8f; }
 .knob { position:absolute; top:3px; left:3px; width:22px; height:22px; border-radius:50%;
         background:#fff; transition:.15s; box-shadow:0 1px 3px rgba(0,0,0,.3); }
 .track.on .knob { left:27px; }
 .banner { padding:10px 20px; font-size:.9rem; font-weight:600; color:#fff; }
 .banner.vuln { background:#d1495b; } .banner.safe { background:#2a9d8f; }
 nav { margin:22px 0; display:flex; flex-wrap:wrap; gap:8px; }
 nav a { padding:7px 13px; background:var(--card); border:1px solid var(--line);
         border-radius:8px; text-decoration:none; color:var(--ink); font-size:.9rem; }
 nav a:hover { border-color:#c3c8d0; }
 h1 { margin:.2em 0; font-size:1.5rem; } h2 { font-size:1.15rem; }
 .card { background:var(--card); border:1px solid var(--line); border-radius:12px;
         padding:18px 20px; margin:16px 0; }
 table { border-collapse:collapse; width:100%; font-size:.92rem; }
 th,td { border-bottom:1px solid var(--line); padding:8px 10px; text-align:left; }
 th { color:var(--muted); font-weight:600; }
 pre.sql { background:#0f172a; color:#e2e8f0; padding:12px 14px; border-radius:8px;
           white-space:pre-wrap; font-size:.85rem; overflow-x:auto; }
 .err { color:#d1495b; font-weight:600; }
 label { display:block; margin:8px 0 4px; font-size:.9rem; }
 input { padding:8px 10px; border:1px solid var(--line); border-radius:8px; width:100%;
         max-width:320px; font-size:.95rem; }
 button { margin-top:12px; padding:9px 16px; border:0; border-radius:8px; background:#1f2430;
          color:#fff; font-size:.9rem; cursor:pointer; }
 .count { color:var(--muted); font-size:.85rem; margin-top:8px; }
"""


def page(title, body):
    on = SAFE
    track = "track on" if on else "track"
    switch_label = "SECURE: ON" if on else "SECURE: OFF"
    banner = ('<div class="banner safe">✓ BEZPEČNÝ režim — vstupy idú ako parametre (?), '
              'injection neprejde.</div>' if on else
              '<div class="banner vuln">⚠ ZRANITEĽNÝ režim — SQL sa skladá reťazcami. '
              'Vstup sa stáva súčasťou dotazu.</div>')
    return f"""<!DOCTYPE html>
<html lang="sk"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} – BIAKS Shop</title>
<style>{STYLE}</style></head><body>
<header>
 <div class="bar">
   <div class="brand">🛒 BIAKS Shop <small>SQL Injection demo</small></div>
   <div class="spacer"></div>
   <a class="switch" href="/toggle" title="Prepnúť zabezpečenie">
     <span>{switch_label}</span><span class="{track}"><span class="knob"></span></span>
   </a>
 </div>
 {banner}
</header>
<div class="wrap">
<h1>{html.escape(title)}</h1>
<nav><a href="/">Domov</a><a href="/products?cat=1">Notebooky</a>
<a href="/products?cat=2">Príslušenstvo</a><a href="/products?cat=3">Siete</a>
<a href="/search?q=">Hľadať</a><a href="/login">Prihlásenie</a></nav>
{body}
</div></body></html>"""


def sql_box(sql):
    # Vykonaný dotaz sa zobrazuje kvôli výučbe - v reálnej aplikácii by to bol únik informácií.
    return f'<p>Vykonaný dotaz:</p><pre class="sql">{html.escape(sql)}</pre>'


def rows_table(headers, rows):
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>"
                   for r in rows)
    return (f'<table><tr>{head}</tr>{body}</table>'
            f'<p class="count">Počet záznamov: {len(rows)}</p>')


LOGIN_FORM = """<form method="post" action="/login">
<label>Meno</label><input name="username" autocomplete="off">
<label>Heslo</label><input name="password" type="password" autocomplete="off">
<button>Prihlásiť</button></form>"""


class Handler(BaseHTTPRequestHandler):
    def send(self, status, content):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def run_query(self, title, fn, *args, headers=("ID", "Názov", "Cena €"), before=""):
        try:
            sql, rows = fn(*args)
        except sqlite3.Error as e:
            # Chybová hláška databázy sa vracia používateľovi (error-based detekcia SQLi).
            self.send(500, page(title, before + '<div class="card">'
                      + f'<p class="err">Chyba databázy: {html.escape(str(e))}</p></div>'))
            return None
        self.send(200, page(title, before + '<div class="card">' + sql_box(sql)
                            + rows_table(headers, rows) + '</div>'))
        return rows

    def do_GET(self):
        url = urlparse(self.path)
        params = parse_qs(url.query, keep_blank_values=True)
        if url.path == "/":
            self.send(200, page("Vitajte", '<div class="card"><p>Internetový obchod s '
                      'výpočtovou technikou. Vyberte kategóriu, vyhľadajte produkt alebo sa '
                      'prihláste.</p><p class="count">Prepínačom <b>SECURE</b> vpravo hore '
                      'prepneš medzi zraniteľným a bezpečným režimom bez reštartu.</p></div>'))
        elif url.path == "/toggle":
            global SAFE
            SAFE = not SAFE
            self.redirect("/")
        elif url.path == "/products":
            cat = params.get("cat", ["1"])[0]
            self.run_query("Produkty v kategórii", query_products, cat)
        elif url.path == "/search":
            q = params.get("q", [""])[0]
            form = (f'<div class="card"><form action="/search">'
                    f'<label>Hľadať produkt</label>'
                    f'<input name="q" value="{html.escape(q)}" autocomplete="off">'
                    f'<button>Hľadať</button></form></div>')
            self.run_query("Vyhľadávanie", query_search, q, before=form)
        elif url.path == "/login":
            self.send(200, page("Prihlásenie", '<div class="card">' + LOGIN_FORM + '</div>'))
        else:
            self.send(404, page("Nenájdené", '<div class="card"><p>Stránka neexistuje.</p></div>'))

    def do_POST(self):
        if urlparse(self.path).path != "/login":
            self.send(404, page("Nenájdené", '<div class="card"><p>Stránka neexistuje.</p></div>'))
            return
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        try:
            sql, rows = query_login(username, password)
        except sqlite3.Error as e:
            self.send(500, page("Prihlásenie", '<div class="card">'
                      + f'<p class="err">Chyba databázy: {html.escape(str(e))}</p></div>'))
            return
        if rows:
            uid, name, role = rows[0]
            msg = (f"<p><b>Prihlásený ako {html.escape(name)}</b> (rola: {html.escape(role)}).</p>"
                   + ("<p>Administrácia: prístup povolený.</p>" if role == "admin" else ""))
        else:
            msg = '<p class="err">Nesprávne meno alebo heslo.</p>' + LOGIN_FORM
        self.send(200, page("Prihlásenie", '<div class="card">' + sql_box(sql) + msg + '</div>'))

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")


def main():
    global SAFE, db
    ap = argparse.ArgumentParser(description="BIAKS Shop - zámerne zraniteľná aplikácia (SQLi)")
    ap.add_argument("--safe", action="store_true", help="štart rovno v bezpečnom režime")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    SAFE = args.safe
    db = init_db()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    print(f"BIAKS Shop na http://127.0.0.1:{args.port}/  "
          f"(štart: {'BEZPEČNÝ' if SAFE else 'ZRANITEĽNÝ'} režim, prepínač SECURE v UI)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
