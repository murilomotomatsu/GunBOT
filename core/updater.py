# ================= UPDATER =================
import os
import sys
import subprocess
import requests

from config import UPDATE_API, APP_VERSION, UPDATER_EXE


def check_and_update():
    """Check for updates and launch updater if new version available."""
    try:
        r = requests.get(UPDATE_API, timeout=8)
        if r.status_code != 200:
            return
        data = r.json()
    except Exception:
        return

    server_version = data.get("version")
    if not server_version:
        return

    if server_version == APP_VERSION:
        return  # ✅ nada a fazer

    # 🚀 TEM UPDATE
    subprocess.Popen(
        ['cmd', '/c', 'start', '', UPDATER_EXE],
        cwd=os.path.dirname(sys.executable),
        shell=True,
    )

    os._exit(0)
