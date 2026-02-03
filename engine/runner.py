# ================= MACRO RUNNER =================
import time
import threading

from automation import (
    locate, ensure_window_visible, 
    send_click, send_drag, send_mouse_wheel, send_key, send_key_combo,
    send_clipboard_global, send_click_global
)


class MacroRunner:
    """Handles macro execution loop."""
    
    def __init__(self, app, macro):
        self.app = app
        self.macro = macro
        self.running = False

    def start(self):
        """Start macro execution thread."""
        if self.running: 
            return
        self.running = True
        threading.Thread(target=self.loop, daemon=True).start()
        self.app.log("Macro thread started", self.macro["name"])

    def stop(self):
        """Stop macro execution."""
        self.running = False
        self.app.log("Macro stopped", self.macro["name"])

    def loop(self):
        """Main macro execution loop."""
        while self.running:
            hwnd = self.app.get_hwnd()
            if not hwnd:
                time.sleep(1)
                continue
            if not ensure_window_visible(hwnd):
                time.sleep(1)
                continue
            
            trig = self.macro["trigger"]
            if trig:
                found = locate(hwnd, trig["image"], trig["confidence"]) is not None
                if trig["condition"] == "if_found" and not found:
                    time.sleep(0.4)
                    continue
                if trig["condition"] == "if_not_found" and found:
                    time.sleep(0.4)
                    continue

            for step in self.macro["steps"]:
                self.app.log(f"Step: {step['type']}", self.macro["name"])

                if not self.running: 
                    break

                cond = step["condition"]

                pos = None            
                if step["type"] in ("click", "drag", "wheel"):
                    pos = locate(hwnd, step["image"], step["confidence"])

                if cond == "if_found" and not pos: 
                    continue
                if cond == "if_not_found" and pos: 
                    continue

                if step["type"] == "click" and pos:
                    send_click(
                        hwnd,
                        pos[0],
                        pos[1],
                        step.get("button", "left")
                    )
                elif step["type"] == "drag" and pos:
                    cx, cy = pos
                    send_drag(
                        hwnd,
                        cx,
                        cy,
                        step.get("dx", 0),
                        step.get("dy", 0),
                        step.get("delay", 0.02)
                    )

                elif step["type"] == "wheel" and pos:
                    for _ in range(step["repeat"]):
                        send_mouse_wheel(hwnd, *pos, step["delta"])

                elif step["type"] == "delay":
                    t = step.get("seconds", 1)
                    end = time.time() + t
                    while time.time() < end:
                        if not self.running:
                            break
                        time.sleep(0.05)

                elif step["type"] == "key":
                    vk = step.get("vk")
                    modifiers = step.get("modifiers", [])
                    if vk:
                        if modifiers:
                            send_key_combo(hwnd, vk, modifiers)
                        else:
                            send_key(hwnd, vk)

                elif step["type"] == "click_pos":
                    click_x = step.get("click_x")
                    click_y = step.get("click_y")
                    if click_x is not None and click_y is not None:
                        send_click(
                            hwnd,
                            click_x,
                            click_y,
                            step.get("button", "left")
                        )

                elif step["type"] == "clipboard":
                    # Ctrl+C or Ctrl+V - CTRL must be global, key sent to window
                    import win32api, win32con
                    action = step.get("action", "paste")
                    key = ord('C') if action == "copy" else ord('V')
                    
                    # Press CTRL globally
                    win32api.keybd_event(win32con.VK_CONTROL, 0, 0, 0)
                    time.sleep(0.02)
                    
                    # Send key to window
                    send_key(hwnd, key)
                    
                    # Release CTRL globally
                    time.sleep(0.02)
                    win32api.keybd_event(win32con.VK_CONTROL, 0, win32con.KEYEVENTF_KEYUP, 0)

                elif step["type"] == "click_global":
                    # Global click at screen position (for popups/downloads)
                    click_x = step.get("click_x")
                    click_y = step.get("click_y")
                    if click_x is not None and click_y is not None:
                        send_click_global(
                            click_x,
                            click_y,
                            step.get("button", "left")
                        )
