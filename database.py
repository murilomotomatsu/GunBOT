import psycopg2
import threading

DB_CONFIG = {
    "host": "db.wmkjfqwjfrkczkdrrhex.supabase.co",
    "port": 5432,
    "database": "postgres",
    "user": "postgres",
    "password": "Atomosx123!"
}

_db = None
_lock = threading.Lock()

def get_db():
    global _db
    with _lock:
        if _db is None or _db.closed != 0:
            _db = psycopg2.connect(
                host=DB_CONFIG["host"],
                port=DB_CONFIG["port"],
                database=DB_CONFIG["database"],
                user=DB_CONFIG["user"],
                password=DB_CONFIG["password"],
                connect_timeout=5
            )
        return _db

def init_db():
    db = get_db()
    c = db.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id SERIAL PRIMARY KEY,
        raw_key TEXT UNIQUE NOT NULL,
        key_hash TEXT UNIQUE NOT NULL,
        hwid TEXT,
        active BOOLEAN DEFAULT TRUE,
        last_seen DOUBLE PRECISION
    )
    """)

    db.commit()
