# ================= INPUT OPERATIONS =================
import time
import win32gui, win32con, win32api


def screen_to_client(hwnd, x, y):
    """Convert screen coordinates to client coordinates."""
    return win32gui.ScreenToClient(hwnd, (int(x), int(y)))


def send_key(hwnd, vk):
    """Send keyboard key to window."""
    win32gui.SendMessage(hwnd, win32con.WM_KEYDOWN, vk, 0)
    time.sleep(0.02)
    win32gui.SendMessage(hwnd, win32con.WM_KEYUP, vk, 0)


def send_key_combo(hwnd, vk, modifiers=None):
    """
    Send keyboard key combination using pure PostMessage (Background friendly).
    Sends KeyDown/KeyUp messages for both modifiers and keys directly to the window queue.
    
    Args:
        hwnd: Window handle
        vk: Virtual key code of the main key
        modifiers: List of modifier VK codes (e.g., [0x11 for CTRL, 0x10 for SHIFT])
    """
    if modifiers is None:
        modifiers = []
    
    # Helper for lparam
    def make_lparam(vk_code, is_keyup=False):
        scan_code = win32api.MapVirtualKey(vk_code, 0)
        lparam = 1  # repeat count = 1
        lparam |= (scan_code << 16)
        if is_keyup:
            lparam |= (1 << 30)
            lparam |= (1 << 31)
        return lparam

    # 1. Press modifiers (WM_KEYDOWN)
    for mod in modifiers:
        lparam = make_lparam(mod, is_keyup=False)
        win32gui.PostMessage(hwnd, win32con.WM_KEYDOWN, mod, lparam)
        time.sleep(0.02)
    
    # 2. Press Main Key (WM_KEYDOWN)
    lparam_down = make_lparam(vk, is_keyup=False)
    win32gui.PostMessage(hwnd, win32con.WM_KEYDOWN, vk, lparam_down)
    
    # 3. Main Key (WM_CHAR) - Optional but helps some apps
    # TranslateMessage would generate this, but we are bypassing the loop
    # Not strictly necessary for control keys, but good for completeness if needed later
    
    time.sleep(0.05)
    
    # 4. Release Main Key (WM_KEYUP)
    lparam_up = make_lparam(vk, is_keyup=True)
    win32gui.PostMessage(hwnd, win32con.WM_KEYUP, vk, lparam_up)
    
    # 5. Release Modifiers (WM_KEYUP)
    for mod in reversed(modifiers):
        time.sleep(0.01)
        lparam = make_lparam(mod, is_keyup=True)
        win32gui.PostMessage(hwnd, win32con.WM_KEYUP, mod, lparam)


def send_click(hwnd, x, y, button="left"):
    """Send mouse click to window."""
    cx, cy = screen_to_client(hwnd, x, y)
    lparam = win32api.MAKELONG(cx, cy)

    if button == "right":
        down = win32con.WM_RBUTTONDOWN
        up = win32con.WM_RBUTTONUP
        flag = win32con.MK_RBUTTON
    else:
        down = win32con.WM_LBUTTONDOWN
        up = win32con.WM_LBUTTONUP
        flag = win32con.MK_LBUTTON

    win32gui.SendMessage(hwnd, win32con.WM_MOUSEMOVE, 0, lparam)
    time.sleep(0.02)

    win32gui.SendMessage(hwnd, down, flag, lparam)
    time.sleep(0.02)

    win32gui.SendMessage(hwnd, up, 0, lparam)


def send_drag(hwnd, x, y, dx, dy, delay=0.02):
    """Send mouse drag to window."""
    cx, cy = screen_to_client(hwnd, x, y)

    start = win32api.MAKELONG(cx, cy)
    end = win32api.MAKELONG(cx + dx, cy + dy)

    win32gui.SendMessage(hwnd, win32con.WM_MOUSEMOVE, 0, start)
    time.sleep(delay)

    win32gui.SendMessage(
        hwnd,
        win32con.WM_LBUTTONDOWN,
        win32con.MK_LBUTTON,
        start
    )
    time.sleep(delay)

    win32gui.SendMessage(
        hwnd,
        win32con.WM_MOUSEMOVE,
        win32con.MK_LBUTTON,
        end
    )
    time.sleep(delay)

    win32gui.SendMessage(hwnd, win32con.WM_LBUTTONUP, 0, end)


def send_mouse_wheel(hwnd, x, y, delta=-120):
    """Send mouse wheel scroll to window."""
    cx, cy = screen_to_client(hwnd, x, y)
    lparam = win32api.MAKELONG(cx, cy)
    wparam = win32api.MAKELONG(0, delta)
    win32gui.SendMessage(hwnd, win32con.WM_MOUSEMOVE, 0, lparam)
    time.sleep(0.02)
    win32gui.SendMessage(hwnd, win32con.WM_MOUSEWHEEL, wparam, lparam)


# ================= GLOBAL INPUT OPERATIONS =================
# These functions work independently of window handles (require active focus)

def send_clipboard_global(action="paste"):
    """
    Send Ctrl+C (copy) or Ctrl+V (paste) globally using keybd_event.
    This simulates a real keyboard press that works with any focused window.
    
    Args:
        action: "copy" for Ctrl+C or "paste" for Ctrl+V
    """
    key = ord('C') if action == "copy" else ord('V')
    
    # Press CTRL down
    win32api.keybd_event(win32con.VK_CONTROL, 0, 0, 0)
    time.sleep(0.02)
    
    # Press key down
    win32api.keybd_event(key, 0, 0, 0)
    time.sleep(0.02)
    
    # Release key
    win32api.keybd_event(key, 0, win32con.KEYEVENTF_KEYUP, 0)
    time.sleep(0.02)
    
    # Release CTRL
    win32api.keybd_event(win32con.VK_CONTROL, 0, win32con.KEYEVENTF_KEYUP, 0)


def send_click_global(x, y, button="left"):
    """
    Send a mouse click at screen coordinates (global click).
    This clicks at the specified position regardless of which window is there.
    Useful for clicking on popups, download dialogs, etc.
    
    Args:
        x: Screen X coordinate
        y: Screen Y coordinate  
        button: "left" or "right" click
    """
    # Move cursor to position
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.05)
    
    if button == "right":
        down_flag = win32con.MOUSEEVENTF_RIGHTDOWN
        up_flag = win32con.MOUSEEVENTF_RIGHTUP
    else:
        down_flag = win32con.MOUSEEVENTF_LEFTDOWN
        up_flag = win32con.MOUSEEVENTF_LEFTUP
    
    # Perform click
    win32api.mouse_event(down_flag, 0, 0, 0, 0)
    time.sleep(0.02)
    win32api.mouse_event(up_flag, 0, 0, 0, 0)
