from fastapi import FastAPI, HTTPException
import time

from database import get_db, init_db
from models import ValidateRequest
from security import hash_key

app = FastAPI()
init_db()

# ================= ADMIN =================

@app.post("/admin/create_key")
def create_key(raw_key: str):
    db = get_db()
    c = db.cursor()

    h = hash_key(raw_key)

    try:
        c.execute(
            "INSERT INTO licenses (key) VALUES (?)",
            (h,)
        )
        db.commit()
    except:
        raise HTTPException(400, "Key já existe")

    return {"status": "created"}

@app.post("/admin/ban")
def ban_key(raw_key: str):
    db = get_db()
    c = db.cursor()

    c.execute(
        "UPDATE licenses SET active=0 WHERE key=?",
        (hash_key(raw_key),)
    )
    db.commit()

    return {"status": "banned"}

# ================= CLIENT =================

@app.post("/validate")
def validate(data: ValidateRequest):
    db = get_db()
    c = db.cursor()

    h = hash_key(data.key)

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

    # Primeiro uso
    if not saved_hwid:
        c.execute(
            "UPDATE licenses SET hwid=?, last_seen=? WHERE id=?",
            (data.hwid, time.time(), _id)
        )
        db.commit()
        return {"status": "ok"}

    # HWID diferente
    if saved_hwid != data.hwid:
        return {"status": "hwid_mismatch"}

    # Atualiza heartbeat
    c.execute(
        "UPDATE licenses SET last_seen=? WHERE id=?",
        (time.time(), _id)
    )
    db.commit()

    return {"status": "ok"}
