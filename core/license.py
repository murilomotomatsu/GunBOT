# ================= LICENSE =================
import hashlib
import platform
import subprocess
import uuid
import os
import json
import time
import requests
import tkinter as tk
from tkinter import simpledialog, messagebox

from config import LICENSE_FILE, API_URL, APP_VERSION


def get_hwid():
    """Generate hardware ID based on system characteristics."""
    parts = []

    parts.append(platform.node())
    parts.append(platform.processor())

    try:
        parts.append(str(uuid.getnode()))
    except:
        pass

    try:
        disk = subprocess.check_output(
            "wmic diskdrive get serialnumber",
            shell=True
        ).decode(errors="ignore")
        parts.append(disk)
    except:
        pass

    raw = "|".join(parts).encode()
    return hashlib.sha256(raw).hexdigest()


def load_license():
    """Load license from file."""
    if not os.path.exists(LICENSE_FILE):
        return None
    try:
        return json.load(open(LICENSE_FILE, "r", encoding="utf-8"))
    except:
        return None


def save_license(data):
    """Save license to file."""
    json.dump(data, open(LICENSE_FILE, "w", encoding="utf-8"), indent=2)


def ask_key():
    """Show dialog to ask for license key."""
    root = tk.Tk()
    root.withdraw()
    return simpledialog.askstring(
        "Licença",
        "Enter your activation key:"
    )


def validate_license():
    """Validate license with server."""
    lic = load_license()
    hwid = get_hwid()

    if not lic:
        key = ask_key()
        if not key:
            messagebox.showerror("Licença", "Activation key is required ")
            return False
        lic = {"key": key}

    max_attempts = 6          # ~30–45s total
    base_delay = 2.0          # segundos

    for attempt in range(1, max_attempts + 1):
        try:
            r = requests.post(
                API_URL,
                timeout=15,
                json={
                    "key": lic["key"],
                    "hwid": hwid,
                    "version": APP_VERSION
                }
            )
            resp = r.json()
            break

        except Exception:
            if attempt == max_attempts:
                messagebox.showerror(
                    "License",
                    "Server unavailable.\nPlease try again in a few seconds"
                )
                return False

            time.sleep(base_delay * attempt)  # backoff progressivo

    status = resp.get("status")

    if status == "ok":
        save_license(lic)
        return True

    if status == "banned":
        messagebox.showerror("License", "License banned")
        return False

    if status == "hwid_mismatch":
        messagebox.showerror(
            "License",
            "This key is already used on another computer"
        )
        return False

    messagebox.showerror("License", "Invalid license key")
    return False
