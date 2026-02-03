# ================= WINDOW OPERATIONS =================
import time
import numpy as np
import cv2
import win32gui, win32ui, win32con
from ctypes import windll


def capture_window(hwnd):
    """Capture window content as image."""
    if not hwnd or not win32gui.IsWindow(hwnd):
        return None

    try:
        l, t, r, b = win32gui.GetWindowRect(hwnd)
        w, h = r - l, b - t

        if w <= 0 or h <= 0:
            return None

        hdc = win32gui.GetWindowDC(hwnd)
        if not hdc:
            return None

        src = win32ui.CreateDCFromHandle(hdc)
        mem = src.CreateCompatibleDC()

        bmp = win32ui.CreateBitmap()
        bmp.CreateCompatibleBitmap(src, w, h)

        mem.SelectObject(bmp)

        ok = windll.user32.PrintWindow(hwnd, mem.GetSafeHdc(), 2)
        if not ok:
            return None

        buf = bmp.GetBitmapBits(True)
        img = np.frombuffer(buf, dtype=np.uint8)
        img = img.reshape((h, w, 4))

        frame = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
        return frame, l, t

    except Exception:
        return None

    finally:
        try:
            if mem:
                mem.DeleteDC()
        except:
            pass
        try:
            if src:
                src.DeleteDC()
        except:
            pass
        try:
            if hdc:
                win32gui.ReleaseDC(hwnd, hdc)
        except:
            pass
        try:
            if bmp:
                win32gui.DeleteObject(bmp.GetHandle())
        except:
            pass


def list_windows():
    """List all visible windows with titles."""
    result = []

    def enum(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if title:
                result.append((hwnd, title))
    win32gui.EnumWindows(enum, None)
    return result


def ensure_window_visible(hwnd):
    """Ensure window is visible and not minimized."""
    if not win32gui.IsWindow(hwnd):
        return False

    # Se estiver minimizada
    if win32gui.IsIconic(hwnd):
        win32gui.ShowWindow(hwnd, win32con.SW_SHOWNOACTIVATE)
        time.sleep(0.1)

    # Garante que não esteja escondida, mas sem ativar
    win32gui.ShowWindow(hwnd, win32con.SW_SHOWNA)

    return True
