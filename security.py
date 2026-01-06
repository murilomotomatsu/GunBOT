import hashlib

SECRET = "murilinxdnogunquestx13!"

def hash_key(key: str) -> str:
    return hashlib.sha256((key + SECRET).encode()).hexdigest()
