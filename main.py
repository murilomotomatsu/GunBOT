from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
import secrets, psycopg2, os, time

from security import hash_key, check_admin

# ================= CONFIG =================

SESSIONS = {}
SESSION_TTL = 60 * 60

DB_HOST = os.environ["DB_HOST"]
DB_NAME = os.environ["DB_NAME"]
DB_USER = os.environ["DB_USER"]
DB_PASS = os.environ["DB_PASS"]
DB_PORT = os.environ.get("DB_PORT", "5432")

app = FastAPI()

# ================= SESSION =================

def create_session():
    sid = secrets.token_urlsafe(32)
    SESSIONS[sid] = time.time()
    return sid

def valid_session(sid: str | None):
    ts = SESSIONS.get(sid)
    if not ts:
        return False
    if time.time() - ts > SESSION_TTL:
        del SESSIONS[sid]
        return False
    return True

def require_admin(request: Request):
    sid = request.cookies.get("admin_session")
    if not valid_session(sid):
        raise HTTPException(401)

# ================= DATABASE =================

def get_db():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        port=DB_PORT,
        sslmode="require"
    )

# ================= UPDATE API =================

@app.get("/latest")
def latest():
    db = get_db()
    c = db.cursor()
    c.execute(
        "SELECT version, url, sha256 FROM updates ORDER BY id DESC LIMIT 1"
    )
    row = c.fetchone()
    if not row:
        return JSONResponse({}, status_code=204)

    return {
        "version": row[0],
        "url": row[1],
        "sha256": row[2]
    }

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

    sid = create_session()
    resp = RedirectResponse("/panel", status_code=302)
    resp.set_cookie("admin_session", sid, httponly=True, samesite="lax")
    return resp

@app.get("/panel", response_class=HTMLResponse)
def panel(request: Request):
    require_admin(request)

    db = get_db()
    c = db.cursor()

    # Licenças
    c.execute("SELECT raw_key, hwid, active FROM licenses")
    licenses = c.fetchall()

    # Update atual
    c.execute(
        "SELECT id, version, url, sha256 FROM updates ORDER BY id DESC LIMIT 1"
    )
    update = c.fetchone()

    html = "<h2>Painel Admin</h2>"

    # ===== UPDATE =====
    html += """
    <h3>Atualização</h3>
    <form method="post" action="/update/create">
      <input name="version" placeholder="Versão (1.0.1)" required><br>
      <input name="url" placeholder="URL Dropbox ?dl=1" size="60" required><br>
      <input name="sha256" placeholder="SHA256" size="70" required><br>
      <button>Lançar Update</button>
    </form>
    """

    if update:
        html += f"""
        <p><b>Atual:</b> v{update[1]}</p>
        <form method="post" action="/update/delete">
          <input type="hidden" name="id" value="{update[0]}">
          <button>Excluir Update</button>
        </form>
        """

    # ===== LICENSES =====
    html += """
    <h3>Licenças</h3>
    <table border="1" cellpadding="6">
    <tr><th>Key</th><th>HWID</th><th>Status</th><th>Ações</th></tr>
    """

    for raw_key, hwid, active in licenses:
        html += f"""
        <tr>
          <td>{raw_key}</td>
          <td>{hwid or '-'}</td>
          <td>{"ATIVA" if active else "BANIDA"}</td>
          <td>
            <form method="post" action="/ban">
              <input type="hidden" name="key" value="{raw_key}">
              <button>Banir</button>
            </form>
            <form method="post" action="/unban">
              <input type="hidden" name="key" value="{raw_key}">
              <button>Desbanir</button>
            </form>
            <form method="post" action="/delete">
              <input type="hidden" name="key" value="{raw_key}">
              <button>Excluir</button>
            </form>
          </td>
        </tr>
        """

    html += "</table>"
    return html

# ================= UPDATE ACTIONS =================

@app.post("/update/create")
def create_update(
    request: Request,
    version: str = Form(...),
    url: str = Form(...),
    sha256: str = Form(...)
):
    require_admin(request)

    db = get_db()
    c = db.cursor()
    c.execute(
        "INSERT INTO updates (version, url, sha256) VALUES (%s, %s, %s)",
        (version, url, sha256)
    )
    db.commit()

    return RedirectResponse("/panel", status_code=302)

@app.post("/update/delete")
def delete_update(request: Request, id: int = Form(...)):
    require_admin(request)

    db = get_db()
    c = db.cursor()
    c.execute("DELETE FROM updates WHERE id=%s", (id,))
    db.commit()

    return RedirectResponse("/panel", status_code=302)

# ================= LICENSE ACTIONS =================

@app.post("/ban")
def ban(request: Request, key: str = Form(...)):
    require_admin(request)
    db = get_db()
    c = db.cursor()
    c.execute("UPDATE licenses SET active=false WHERE raw_key=%s", (key,))
    db.commit()
    return RedirectResponse("/panel", status_code=302)

@app.post("/unban")
def unban(request: Request, key: str = Form(...)):
    require_admin(request)
    db = get_db()
    c = db.cursor()
    c.execute(
        "UPDATE licenses SET active=true, hwid=NULL WHERE raw_key=%s",
        (key,)
    )
    db.commit()
    return RedirectResponse("/panel", status_code=302)

@app.post("/delete")
def delete_key(request: Request, key: str = Form(...)):
    require_admin(request)
    db = get_db()
    c = db.cursor()
    c.execute("DELETE FROM licenses WHERE raw_key=%s", (key,))
    db.commit()
    return RedirectResponse("/panel", status_code=302)
