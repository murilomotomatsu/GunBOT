from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import sqlite3
import hashlib
import time
import os

# ================= CONFIG =================

DB_FILE = "licenses.db"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

app = FastAPI()


# ================= DATABASE =================

def get_db():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    db = get_db()
    c = db.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_key TEXT UNIQUE,
            key_hash TEXT UNIQUE,
            hwid TEXT,
            active INTEGER DEFAULT 1,
            last_seen REAL
        )
    """)
    db.commit()

init_db()


# ================= SECURITY =================

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def check_admin(password: str) -> bool:
    return password == ADMIN_PASSWORD


# ================= CLIENT =================

@app.post("/validate")
def validate(data: dict):
    db = get_db()
    c = db.cursor()

    key_hash = hash_key(data["key"])

    c.execute(
        "SELECT id, hwid, active FROM licenses WHERE key_hash=?",
        (key_hash,)
    )
    row = c.fetchone()

    if not row:
        return {"status": "invalid"}

    lic_id, saved_hwid, active = row

    if not active:
        return {"status": "banned"}

    if not saved_hwid:
        c.execute(
            "UPDATE licenses SET hwid=?, last_seen=? WHERE id=?",
            (data["hwid"], time.time(), lic_id)
        )
        db.commit()
        return {"status": "ok"}

    if saved_hwid != data["hwid"]:
        return {"status": "hwid_mismatch"}

    c.execute(
        "UPDATE licenses SET last_seen=? WHERE id=?",
        (time.time(), lic_id)
    )
    db.commit()

    return {"status": "ok"}


# ================= ADMIN UI =================

@app.get("/", response_class=HTMLResponse)
def login():
    return """
    <h2>Admin Login</h2>
    <form method="post" action="/login">
      <input type="password" name="password" placeholder="Senha"/>
      <button>Entrar</button>
    </form>
    """

@app.post("/login")
def do_login(password: str = Form(...)):
    if not check_admin(password):
        return HTMLResponse("<h3>Senha incorreta</h3>", status_code=401)

    return RedirectResponse("/panel?auth=" + password, status_code=302)


@app.get("/panel", response_class=HTMLResponse)
def panel(auth: str):
    if not check_admin(auth):
        return HTMLResponse("Acesso negado", status_code=401)

    db = get_db()
    c = db.cursor()

    now = time.time()
    c.execute("SELECT raw_key, hwid, active, last_seen FROM licenses")
    rows = c.fetchall()

    html = f"""
    <style>
      body {{ font-family: Arial }}
      button {{ margin: 2px }}
      .copy {{ cursor:pointer; color:blue }}
    </style>

    <script>
    function copyKey(k) {{
        navigator.clipboard.writeText(k);
        alert("Key copiada");
    }}
    </script>

    <h2>Painel Admin</h2>

    <h3>Criar Key</h3>
    <form method="post" action="/create_key">
      <input name="key" placeholder="XXXX-XXXX-XXXX" required>
      <input type="hidden" name="auth" value="{auth}">
      <button>Criar</button>
    </form>

    <h3>Licenças</h3>
    <table border="1" cellpadding="6">
      <tr>
        <th>Key</th>
        <th>HWID</th>
        <th>Status</th>
        <th>Online</th>
        <th>Ações</th>
      </tr>
    """

    for raw_key, hwid, active, last_seen in rows:
        online = last_seen and (now - last_seen) < 120
        html += f"""
        <tr>
          <td onclick="copyKey('{raw_key}')" class="copy">{raw_key}</td>
          <td>{hwid or '-'}</td>
          <td>{"ATIVA" if active else "BANIDA"}</td>
          <td>{"🟢" if online else "⚫"}</td>
          <td>
            <form method="post" action="/ban" style="display:inline">
              <input type="hidden" name="key" value="{raw_key}">
              <input type="hidden" name="auth" value="{auth}">
              <button>Banir</button>
            </form>

            <form method="post" action="/unban" style="display:inline">
              <input type="hidden" name="key" value="{raw_key}">
              <input type="hidden" name="auth" value="{auth}">
              <button>Desbanir</button>
            </form>

            <form method="post" action="/delete" style="display:inline">
              <input type="hidden" name="key" value="{raw_key}">
              <input type="hidden" name="auth" value="{auth}">
              <button style="color:red">Excluir</button>
            </form>
          </td>
        </tr>
        """

    html += "</table>"
    return html


# ================= ADMIN ACTIONS =================

@app.post("/create_key")
def create_key(key: str = Form(...), auth: str = Form(...)):
    if not check_admin(auth):
        raise HTTPException(401)

    db = get_db()
    c = db.cursor()

    try:
        c.execute(
            "INSERT INTO licenses (raw_key, key_hash, active) VALUES (?, ?, 1)",
            (key, hash_key(key))
        )
        db.commit()
    except:
        pass

    return RedirectResponse("/panel?auth=" + auth, status_code=302)


@app.post("/ban")
def ban(key: str = Form(...), auth: str = Form(...)):
    if not check_admin(auth):
        raise HTTPException(401)

    db = get_db()
    c = db.cursor()

    c.execute("UPDATE licenses SET active=0 WHERE raw_key=?", (key,))
    db.commit()

    return RedirectResponse("/panel?auth=" + auth, status_code=302)


@app.post("/unban")
def unban(key: str = Form(...), auth: str = Form(...)):
    if not check_admin(auth):
        raise HTTPException(401)

    db = get_db()
    c = db.cursor()

    c.execute(
        "UPDATE licenses SET active=1, hwid=NULL WHERE raw_key=?",
        (key,)
    )
    db.commit()

    return RedirectResponse("/panel?auth=" + auth, status_code=302)


@app.post("/delete")
def delete_key(key: str = Form(...), auth: str = Form(...)):
    if not check_admin(auth):
        raise HTTPException(401)

    db = get_db()
    c = db.cursor()

    c.execute("DELETE FROM licenses WHERE raw_key=?", (key,))
    db.commit()

    return RedirectResponse("/panel?auth=" + auth, status_code=302)
