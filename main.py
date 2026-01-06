from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import psycopg2
import os
import time

from security import hash_key, check_admin

# ================= CONFIG =================

DB_HOST = os.environ["DB_HOST"]
DB_NAME = os.environ["DB_NAME"]
DB_USER = os.environ["DB_USER"]
DB_PASS = os.environ["DB_PASS"]
DB_PORT = os.environ.get("DB_PORT", "5432")

app = FastAPI()


# ================= DATABASE =================

def get_db():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        port=DB_PORT
    )


# ================= CLIENT =================

@app.post("/validate")
def validate(data: dict):
    db = get_db()
    c = db.cursor()

    key_hash = hash_key(data["key"])

    c.execute(
        "SELECT id, hwid, active FROM licenses WHERE key_hash=%s",
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
            "UPDATE licenses SET hwid=%s, last_seen=%s WHERE id=%s",
            (data["hwid"], time.time(), lic_id)
        )
        db.commit()
        return {"status": "ok"}

    if saved_hwid != data["hwid"]:
        return {"status": "hwid_mismatch"}

    c.execute(
        "UPDATE licenses SET last_seen=%s WHERE id=%s",
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
      <input type="password" name="password">
      <button>Entrar</button>
    </form>
    """

@app.post("/login")
def do_login(password: str = Form(...)):
    if not check_admin(password):
        return HTMLResponse("Senha incorreta", status_code=401)

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
    <h2>Painel Admin</h2>

    <form method="post" action="/create_key">
      <input name="key" placeholder="XXXX-XXXX-XXXX" required>
      <input type="hidden" name="auth" value="{auth}">
      <button>Criar Key</button>
    </form>

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
          <td>{raw_key}</td>
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
              <button>Excluir</button>
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

    c.execute(
        "INSERT INTO licenses (raw_key, key_hash) VALUES (%s, %s) ON CONFLICT DO NOTHING",
        (key, hash_key(key))
    )
    db.commit()

    return RedirectResponse("/panel?auth=" + auth, status_code=302)


@app.post("/ban")
def ban(key: str = Form(...), auth: str = Form(...)):
    if not check_admin(auth):
        raise HTTPException(401)

    db = get_db()
    c = db.cursor()

    c.execute("UPDATE licenses SET active=false WHERE raw_key=%s", (key,))
    db.commit()

    return RedirectResponse("/panel?auth=" + auth, status_code=302)


@app.post("/unban")
def unban(key: str = Form(...), auth: str = Form(...)):
    if not check_admin(auth):
        raise HTTPException(401)

    db = get_db()
    c = db.cursor()

    c.execute(
        "UPDATE licenses SET active=true, hwid=NULL WHERE raw_key=%s",
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

    c.execute("DELETE FROM licenses WHERE raw_key=%s", (key,))
    db.commit()

    return RedirectResponse("/panel?auth=" + auth, status_code=302)
