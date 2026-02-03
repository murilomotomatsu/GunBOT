# ================= GUNBOT PRO - ENTRY POINT =================
"""
GunBot PRO - Macro Automation Tool
Entry point for the application.
"""
import os
import sys

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.updater import check_and_update
from core.license import validate_license
from ui.app import MacroApp


if __name__ == "__main__":
    check_and_update()
    
    if not validate_license():
        os._exit(1)

    app = MacroApp()
    app.mainloop()
