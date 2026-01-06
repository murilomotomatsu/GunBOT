import hashlib

SECRET = "murilinxdnogunquestx13!"
ADMIN_PASSWORD = "Atomosx123" 

def hash_key(key: str) -> str:
    return hashlib.sha256((key + SECRET).encode()).hexdigest()

def check_admin(password: str) -> bool:
    return password == ADMIN_PASSWORD