# updater.py
import os
import sys
import time
import tempfile
import subprocess
import threading
import requests
import tkinter as tk
from tkinter import ttk, messagebox

UPDATE_API = "https://gunbot-5drp.onrender.com/latest"
APP_EXE = "gunBOT_PRO.exe"
CHUNK = 8192


def kill_app():
    subprocess.call(
        ["taskkill", "/f", "/im", APP_EXE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)


class Updater(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Atualizando...")
        self.geometry("400x140")
        self.resizable(False, False)

        self.label = ttk.Label(self, text="Verificando...")
        self.label.pack(pady=10)

        self.bar = ttk.Progressbar(self, length=340)
        self.bar.pack(pady=10)

        threading.Thread(target=self.run, daemon=True).start()

    def fail(self, msg):
        messagebox.showerror("Erro", msg)
        self.destroy()

    def run(self):
        try:
            data = requests.get(UPDATE_API, timeout=10).json()
        except Exception:
            self.fail("Erro ao conectar")
            return

        url = data.get("url")
        if not url:
            self.destroy()
            return

        self.label.config(text="Baixando...")
        tmp = os.path.join(tempfile.gettempdir(), "gunbot_new.exe")

        try:
            r = requests.get(url, stream=True)
            total = int(r.headers.get("Content-Length", 0))
            done = 0

            with open(tmp, "wb") as f:
                for c in r.iter_content(CHUNK):
                    f.write(c)
                    done += len(c)
                    if total:
                        self.bar["value"] = (done / total) * 100
        except Exception:
            self.fail("Falha no download")
            return

        self.label.config(text="Instalando...")
        kill_app()

        base = os.path.dirname(sys.executable)
        app = os.path.join(base, APP_EXE)

        try:
            if os.path.exists(app):
                os.remove(app)
            os.rename(tmp, app)
        except Exception:
            self.fail("Não foi possível substituir o arquivo")
            return

        bat = os.path.join(tempfile.gettempdir(), "start.bat")
        with open(bat, "w") as f:
            f.write(f"""@echo off
timeout /t 2 > nul
start "" "{app}"
del "%~f0"
""")

        subprocess.Popen(["cmd", "/c", bat], shell=True)
        self.destroy()


if __name__ == "__main__":
    Updater().mainloop()
