# ================= CONFIG =================
import os
import sys

CONFIG_FILE = "macros.json"
MACRO_DIR = "macros"
os.makedirs(MACRO_DIR, exist_ok=True)

LICENSE_FILE = "license.json"
API_URL = "https://gunbot-5drp.onrender.com/validate"
UPDATE_API = "https://gunbot-5drp.onrender.com/latest"
APP_EXE_NAME = "gunBOT_PRO.exe"
UPDATER_EXE = "gunBOT_Updater.exe"
BASE_DIR = os.path.dirname(sys.executable)

APP_VERSION = "1.0.1"
