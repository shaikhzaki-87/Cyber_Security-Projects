#!/usr/bin/env python3
"""
VulnLab-Insecure — Intentionally Vulnerable Practice Site
Run locally to test VulnHawk against. Contains: SQLi, XSS, Missing Headers, CSRF.
DO NOT deploy this publicly — it is deliberately broken for learning purposes.
"""

from flask import Flask, request, g
import sqlite3
import os

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnlab.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS products
                     (id INTEGER PRIMARY KEY, cat TEXT, name TEXT, price TEXT)""")
    conn.execute("DELETE FROM products")
    conn.executemany("INSERT INTO products (cat, name, price) VALUES (?, ?, ?)", [
        ("electronics", "Laptop", "$800"),
        ("electronics", "Phone", "$500"),
        ("books", "Python Guide", "$25"),
    ])
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return """
    <h1>VulnLab (Insecure)</h1>
    <ul>
      <li><a href="/listproducts.php?cat=electronics">Products (SQLi test point: cat)</a></li>
      <li><a href="/search?artist=test">Search (XSS test point: artist)</a></li>
      <li><a href="/change-password">Change Password Form (CSRF test point)</a></li>
    </ul>
    """


# --- Vulnerable to SQL Injection: raw string concatenation, no parameterization ---
@app.route("/listproducts.php")
def list_products():
    cat = request.args.get("cat", "electronics")
    db = get_db()
    query = f"SELECT id, name, price FROM products WHERE cat = '{cat}'"  # VULNERABLE ON PURPOSE
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.OperationalError as e:
        return f"sqlite3.OperationalError: {e}", 500
    html = "<h2>Products</h2><ul>"
    for r in rows:
        html += f"<li>{r[1]} - {r[2]}</li>"
    html += "</ul>"
    return html


# --- Vulnerable to Reflected XSS: user input echoed back unescaped ---
@app.route("/search")
def search():
    artist = request.args.get("artist", "")
    return f"<h2>Search Results</h2><p>You searched for: {artist}</p>"  # VULNERABLE ON PURPOSE


# --- Vulnerable to CSRF: POST form with no anti-CSRF token ---
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        return "<p>Password changed! (simulated, no token was required)</p>"
    return """
    <h2>Change Password</h2>
    <form method="POST" action="/change-password">
        <input type="password" name="new_password" placeholder="New password">
        <input type="submit" value="Change">
    </form>
    """  # No hidden CSRF token field — VULNERABLE ON PURPOSE


# --- No security headers added anywhere: Content-Security-Policy, X-Frame-Options, etc. all missing ---

if __name__ == "__main__":
    init_db()
    print("VulnLab-Insecure running at http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
