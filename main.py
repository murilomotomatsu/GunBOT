from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
import time

from database import get_db, init_db
from security import hash_key, check_admin

app = FastAPI()
init_db()

# ================= CLIENT =================

@app.post("/validate")
def validate(data: dict):
    db = get_db()
    c = db.cursor()

    h = hash_key(data["key"])

    c.execute(
        "SELECT id, hwid, active FROM licenses WHERE key=?",
        (h,)
    )
    row = c.fetchone()

    if not row:
        return {"status": "invalid"}

    _id, saved_hwid, active = row

    if not active:
        return {"status": "banned"}

    if not saved_hwid:
        c.execute(
            "UPDATE licenses SET hwid=?, last_seen=? WHERE id=?",
            (data["hwid"], time.time(), _id)
        )
        db.commit()
        return {"status": "ok"}

    if saved_hwid != data["hwid"]:
        return {"status": "hwid_mismatch"}

    c.execute(
        "UPDATE licenses SET last_seen=? WHERE id=?",
        (time.time(), _id)
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
    c.execute("SELECT key, hwid, active, last_seen FROM licenses")
    rows = c.fetchall()

    online = [
        r for r in rows if r[3] and (now - r[3]) < 120
    ]

    html = """
    <h2>Painel Admin</h2>

    <h3>Criar Key</h3>
    <form method="post" action="/create_key">
      <input name="key" placeholder="KEY"/>
      <input type="hidden" name="auth" value="{auth}">
      <button>Criar</button>
    </form>

    <h3>Licenças</h3>
    <table border="1">
      <tr>
        <th>Key (hash)</th>
        <th>HWID</th>
        <th>Status</th>
        <th>Online</th>
        <th>Ação</th>
      </tr>
    """.format(auth=auth)

    for k, hwid, active, last_seen in rows:
        is_online = last_seen and (now - last_seen) < 120
        html += f"""
        <tr>
          <td>{k[:16]}...</td>
          <td>{hwid or '-'}</td>
          <td>{"ATIVA" if active else "BANIDA"}</td>
          <td>{"🟢" if is_online else "⚫"}</td>
          <td>
            <form method="post" action="/ban" style="display:inline">
              <input type="hidden" name="key" value="{k}">
              <input type="hidden" name="auth" value="{auth}">
              <button>Banir</button>
            </form>
          </td>
        </tr>
        """

    html += "</table>"
    html += f"<p>Online agora: {len(online)}</p>"

    return html

@app.post("/create_key")
def create_key(key: str = Form(...), auth: str = Form(...)):
    if not check_admin(auth):
        return HTMLResponse("Acesso negado", status_code=401)

    db = get_db()
    c = db.cursor()

    try:
        c.execute(
            "INSERT INTO licenses (key) VALUES (?)",
            (hash_key(key),)
        )
        db.commit()
    except:
        pass

    return RedirectResponse("/panel?auth=" + auth, status_code=302)

@app.post("/ban")
def ban(key: str = Form(...), auth: str = Form(...)):
    if not check_admin(auth):
        return HTMLResponse("Acesso negado", status_code=401)

    db = get_db()
    c = db.cursor()

    c.execute(
        "UPDATE licenses SET active=0 WHERE key=?",
        (key,)
    )
    db.commit()

    return RedirectResponse("/panel?auth=" + auth, status_code=302)
