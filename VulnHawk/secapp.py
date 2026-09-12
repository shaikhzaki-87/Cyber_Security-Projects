#!/usr/bin/env python3
"""
VulnLab-Secure — Hardened Practice Site (for comparison)
Run locally to test VulnHawk against. Should report ZERO findings.
"""

from flask import Flask, request, g
from markupsafe import escape
import sqlite3
import os
import secrets

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnlab_secure.db")


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


# --- Security headers added to every response ---
@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.route("/")
def home():
    return """
    <h1>VulnLab (Secure)</h1>
    <ul>
      <li><a href="/listproducts.php?cat=electronics">Products (parameterized query)</a></li>
      <li><a href="/search?artist=test">Search (output escaped)</a></li>
      <li><a href="/change-password">Change Password Form (CSRF token present)</a></li>
    </ul>
    """


# --- Fixed: parameterized query, no injection possible ---
@app.route("/listproducts.php")
def list_products():
    cat = request.args.get("cat", "electronics")
    db = get_db()
    rows = db.execute("SELECT id, name, price FROM products WHERE cat = ?", (cat,)).fetchall()
    html = "<h2>Products</h2><ul>"
    for r in rows:
        html += f"<li>{r[1]} - {r[2]}</li>"
    html += "</ul>"
    return html


# --- Fixed: user input escaped before rendering ---
@app.route("/search")
def search():
    artist = request.args.get("artist", "")
    safe_artist = escape(artist)
    return f"<h2>Search Results</h2><p>You searched for: {safe_artist}</p>"


# --- Fixed: CSRF token present, cookie hardened ---
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        token = request.form.get("csrf_token")
        if not token:
            return "CSRF token missing — request rejected", 403
        return "<p>Password changed! (token validated)</p>"
    token = secrets.token_hex(16)
    return f"""
    <h2>Change Password</h2>
    <form method="POST" action="/change-password">
        <input type="hidden" name="csrf_token" value="{token}">
        <input type="password" name="new_password" placeholder="New password">
        <input type="submit" value="Change">
    </form>
    """


if __name__ == "__main__":
    init_db()
    print("VulnLab-Secure running at http://127.0.0.1:5002")
    app.run(host="127.0.0.1", port=5002, debug=False)
