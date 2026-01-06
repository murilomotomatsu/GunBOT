import sqlite3

DB = "data.db"

def get_db():
    return sqlite3.connect(DB, check_same_thread=False)

def init_db():
    db = get_db()
    c = db.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        raw_key TEXT UNIQUE,
        key_hash TEXT,
        hwid TEXT,
        active INTEGER DEFAULT 1,
        last_seen REAL
    )
    """)

    db.commit()
    db.close()
