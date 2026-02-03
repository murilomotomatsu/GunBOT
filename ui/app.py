# ================= MACRO APP =================
import os
import json
import time
import uuid
import threading
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from PIL import Image, ImageTk, ImageGrab
import win32gui
from pynput import mouse, keyboard

from config import CONFIG_FILE, MACRO_DIR, APP_VERSION
from core.utils import resource_path
from automation import locate, list_windows
from engine import MacroRunner


class MacroApp(tk.Tk):
    """Main application class for GunBot macro automation."""
    
    def __init__(self):
        super().__init__()
        self._image_cache = {} 
        self.main_controls = {}
        self.macro_tab_buttons = {}
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.title(f"GunQuest PRO BOT - {APP_VERSION}")
        self.geometry("730x570")
        self.iconbitmap(resource_path("ico.ico"))

        self.hwnd = None
        self.data = self.load()
        self.runners = {}

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True)

        self.build_main()
        self.restore_saved_window()
        for m in self.data["macros"]:
            self.build_macro_tab(m)

    # ---------- CONFIG ----------
    def on_close(self):
        """Handle window close event."""
        self.stop_all_macros()
        self.destroy()
        os._exit(0)

    def load(self):
        """Load configuration from file."""
        if not os.path.exists(CONFIG_FILE):
            return {"window_title":"", "macros":[]}
        return json.load(open(CONFIG_FILE, "r", encoding="utf-8"))

    def save(self):
        """Save configuration to file."""
        json.dump(self.data, open(CONFIG_FILE,"w",encoding="utf-8"), indent=2)

    # ---------- MAIN ----------
    def build_main(self):
        """Build the main tab UI."""
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="Main")

        ttk.Button(tab, text="Select Window", command=self.select_window).pack(pady=5)
        self.window_lbl = ttk.Label(tab, text="No window selected")
        self.window_lbl.pack()

        ttk.Button(tab, text="Lock Window", command=self.lock).pack(pady=4)
        ttk.Button(tab, text="+ New Macro", command=self.new_macro).pack(pady=10)

        ttk.Separator(tab, orient="horizontal").pack(fill="x", pady=10)

        ttk.Label(tab, text="Macro Controls").pack()

        ctrl_frame = tk.Frame(tab)
        ctrl_frame.pack(pady=5)

        self.main_ctrl_frame = ctrl_frame

        self.start_all_btn = tk.Button(
            tab,
            text="START ALL",
            bg="darkgreen",
            fg="white",
            command=self.toggle_all_macros,
            width=20
        )
        self.start_all_btn.pack(pady=10)

        ttk.Separator(tab, orient="horizontal").pack(fill="x", pady=8)

        ttk.Label(tab, text="Console").pack(anchor="w", padx=6)

        log_frame = ttk.Frame(tab)
        log_frame.pack(fill="both", expand=True, padx=6, pady=4)

        self.log_text = tk.Text(
            log_frame,
            height=10,
            bg="grey",
            fg="lime",
            insertbackground="white",
            wrap="word"
        )
        self.log_text.pack(side="left", fill="both", expand=True)

        scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scroll.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=scroll.set)

    def lock(self):
        """Lock current window selection."""
        if not self.hwnd:
            messagebox.showerror("Error", "No window selected")
            return

        title = win32gui.GetWindowText(self.hwnd)
        self.data["window"] = {
            "hwnd": self.hwnd,
            "title": title
        }
        self.save()

    def restore_saved_window(self):
        """Restore previously saved window selection."""
        saved = self.data.get("window")
        if not saved:
            return

        title = saved.get("title")
        if not title:
            return

        def enum(hwnd, _):
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd) == title:
                self.hwnd = hwnd

        win32gui.EnumWindows(enum, None)

        if self.hwnd:
            self.window_lbl.config(text=title)

    def log(self, msg, macro=None):
        """Log message to console."""
        ts = time.strftime("%H:%M:%S")
        prefix = f"[{ts}]"
        if macro:
            prefix += f"[{macro}]"
        line = f"{prefix} {msg}\n"

        def _write():
            self.log_text.insert("end", line)
            self.log_text.see("end")

        self.after(0, _write)

    # ---------- MACRO ----------
    def remove_macro(self, macro_id):
        """Remove a macro from the application."""
        macro = next((m for m in self.data["macros"] if m["id"] == macro_id), None)
        if not macro:
            return

        if not messagebox.askyesno(
            "Delete Macro",
            f"Are you sure you want to delete the macro '{macro['name']}'?\n\nThis action CANNOT be undone"
        ):
            return

        # Para execução se estiver rodando
        runner = self.runners.get(macro_id)
        if runner and runner.running:
            runner.stop()

        # Remove da lista
        self.data["macros"] = [m for m in self.data["macros"] if m["id"] != macro_id]
        self.save()

        # Remove runner
        self.runners.pop(macro_id, None)

        # Remove botão do MAIN
        ctrl = self.main_controls.pop(macro_id, None)
        if ctrl:
            ctrl["button"].destroy()

        # Remove botão da TAB
        self.macro_tab_buttons.pop(macro_id, None)

        # Remove aba
        for i in range(self.nb.index("end")):
            if self.nb.tab(i, "text") == macro["name"]:
                self.nb.forget(i)
                break

        # Remove arquivos do macro
        macro_path = os.path.join(MACRO_DIR, macro_id)
        try:
            import shutil
            shutil.rmtree(macro_path)
        except Exception as e:
            print("Erro ao remover pasta:", e)

        self.log("Macro deleted", macro["name"])

    def new_macro(self):
        """Create a new macro."""
        name = simpledialog.askstring("Macro", "Name:")
        if not name: 
            return
        mid = str(uuid.uuid4())
        macro = {
            "id": mid,
            "name": name,
            "trigger": {
                "image": None,
                "confidence": 0.80,
                "condition": "if_found"
            },
            "steps": []
        }
        os.makedirs(os.path.join(MACRO_DIR, mid), exist_ok=True)
        self.data["macros"].append(macro)
        self.save()
        self.build_macro_tab(macro)

    def build_macro_tab(self, macro):
        """Build a macro tab UI."""
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text=macro["name"])

        runner = MacroRunner(self, macro)
        self.runners[macro["id"]] = runner

        self.build_trigger(tab, macro)
        self.build_steps(tab, macro)
        self.add_main_macro_button(macro)

        btn = tk.Button(
            tab,
            text="START",
            bg="green",
            fg="white",
            width=10,
            command=lambda mid=macro["id"]: self.toggle_macro(mid)
        )
        btn.pack(pady=4)

        ttk.Button(
            tab,
            text="🗑 Delete Macro",
            command=lambda mid=macro["id"]: self.remove_macro(mid)
        ).pack(pady=4)

        self.macro_tab_buttons[macro["id"]] = btn

    def add_main_macro_button(self, macro):
        """Add a macro control button to main tab."""
        btn = tk.Button(
            self.main_ctrl_frame,
            bg="green",
            fg="white",
            width=24,
            command=lambda mid=macro["id"]: self.toggle_macro(mid)
        )
        btn.pack(pady=2)

        # guarda botão + nome
        self.main_controls[macro["id"]] = {
            "button": btn,
            "name": macro["name"]
        }

        # estado inicial
        btn.config(text=f"{macro['name']} - START")

    def set_macro_state(self, macro_id, running: bool):
        """Set macro running state."""
        runner = self.runners.get(macro_id)
        if not runner:
            return

        if running:
            self.log("START", self.main_controls.get(macro_id, {}).get("name"))
            runner.start()
        else:
            self.log("STOP", self.main_controls.get(macro_id, {}).get("name"))
            runner.stop()

        # ----- MAIN BUTTON -----
        main_data = self.main_controls.get(macro_id)
        if main_data:
            btn = main_data["button"]
            name = main_data["name"]
            btn.config(
                text=f"{name} - {'STOP' if running else 'START'}",
                bg="red" if running else "green"
            )

        # ----- TAB BUTTON -----
        tab_btn = self.macro_tab_buttons.get(macro_id)
        if tab_btn:
            tab_btn.config(
                text="STOP" if running else "START",
                bg="red" if running else "green"
            )
        self.update_start_all_button()

    # ---------- TRIGGER ----------
    def build_trigger(self, parent, macro):
        """Build trigger section UI."""
        lf = ttk.LabelFrame(parent, text="Trigger")
        lf.pack(fill="x", padx=5, pady=5)

        self.add_image_row(
            lf,
            macro["trigger"],
            is_trigger=True,
            macro=macro
        )

    # ---------- STEPS ----------
    def build_steps(self, parent, macro):
        """Build steps section UI."""
        outer = ttk.LabelFrame(parent, text="Steps")
        outer.pack(fill="both", expand=True, padx=5, pady=5)

        canvas = tk.Canvas(outer, highlightthickness=0)
        canvas.pack(side="left", fill="both", expand=True)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")

        canvas.configure(yscrollcommand=scrollbar.set)

        inner = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        inner.bind("<Configure>", on_configure)

        for step in macro["steps"]:
            self.add_image_row(inner, step, macro=macro)

        add_btn = ttk.Button(
            inner,
            text="+ Add Step",
            command=lambda: self.add_step(inner, macro)
        )
        add_btn.pack(pady=6)

    def move_step(self, macro, step, direction):
        """Move step up or down in the list."""
        steps = macro["steps"]
        i = steps.index(step)

        if direction == -1 and i == 0:
            return
        if direction == 1 and i == len(steps) - 1:
            return

        steps[i], steps[i + direction] = steps[i + direction], steps[i]
        self.save()
        self.refresh_steps(macro)

    def refresh_steps(self, macro):
        """Refresh steps display."""
        self._image_cache.clear()
        tab = self.nb.nametowidget(self.nb.select())

        for child in tab.winfo_children():
            if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Steps":
                child.destroy()

        self.build_steps(tab, macro)

    # ---------- ROW ----------
    def add_image_row(self, parent, obj, macro=None, is_trigger=False):
        """Add an image row for trigger or step."""
        frame = ttk.Frame(parent)
        frame.pack(fill="x", pady=2)

        # Define status_lbl early since some handlers need it
        status_lbl = ttk.Label(frame, text="", width=16)

        # Types that use image-based matching
        image_based_types = ("click", "drag", "wheel")
        uses_image = is_trigger or obj.get("type") in image_based_types

        if uses_image:
            thumb = ttk.Label(frame, text="—", width=6)
            thumb.pack(side="left")

            if obj.get("image"):
                self.update_thumb(thumb, obj["image"])
        else:
            thumb = None

        # Display names for step types
        type_display = {
            "click": "click_image",
            "click_pos": "click_pos",
            "click_global": "click_global",
            "drag": "drag",
            "wheel": "wheel",
            "delay": "delay",
            "key": "key",
            "clipboard": "clipboard"
        }
        display_name = "trigger" if is_trigger else type_display.get(obj["type"], obj["type"])
        ttk.Label(frame, text=display_name, width=10).pack(side="left")
       
        if not is_trigger and obj["type"] == "key":
            # Label to show current key
            key_display = self._format_key_display(obj)
            key_lbl = ttk.Label(frame, text=key_display, width=14, foreground="blue")
            key_lbl.pack(side="left")
            
            ttk.Button(
                frame,
                text="Set Key",
                command=lambda lbl=key_lbl: self.capture_key(obj, status_lbl, lbl)
            ).pack(side="left", padx=4)

        if uses_image:
            ttk.Label(frame, text="conf").pack(side="left")
            conf = tk.DoubleVar(value=obj.get("confidence", 0.75))
            ttk.Entry(frame, textvariable=conf, width=4).pack(side="left")
            conf.trace_add("write", lambda *_: self._set(obj, "confidence", conf.get()))

            size_var = tk.IntVar(value=obj.get("img_size", 13))
            ttk.Entry(frame, textvariable=size_var, width=3).pack(side="left")
            ttk.Label(frame, text="px").pack(side="left")

            def on_size_change(*_):
                try:
                    v = size_var.get()
                    if v < 5:
                        v = 5
                except (tk.TclError, ValueError):
                    return  

                obj["img_size"] = v
                self.save()

            size_var.trace_add("write", on_size_change)

        if not is_trigger and obj.get("type") == "click":
            btn_var = tk.StringVar(value=obj.get("button", "left"))

            ttk.Combobox(
                frame,
                values=["left", "right"],
                textvariable=btn_var,
                width=6,
                state="readonly"
            ).pack(side="left", padx=3)

            btn_var.trace_add(
                "write",
                lambda *_: self._set(obj, "button", btn_var.get())
            )

        if not is_trigger and obj.get("type") == "drag":
            dx = tk.IntVar(value=obj.get("dx", -40))
            dy = tk.IntVar(value=obj.get("dy", 0))

            ttk.Label(frame, text="dx").pack(side="left")
            ttk.Entry(frame, textvariable=dx, width=4).pack(side="left")

            ttk.Label(frame, text="dy").pack(side="left")
            ttk.Entry(frame, textvariable=dy, width=4).pack(side="left")

            dx.trace_add("write", lambda *_: self._safe_set(obj, "dx", dx))
            dy.trace_add("write", lambda *_: self._safe_set(obj, "dy", dy))

        if not is_trigger and obj.get("type") == "wheel":
            repeat = tk.IntVar(value=obj.get("repeat", 1))
            delta = tk.IntVar(value=obj.get("delta", -120))

            ttk.Label(frame, text="scrolls").pack(side="left")
            ttk.Entry(frame, textvariable=repeat, width=3).pack(side="left")

            ttk.Label(frame, text="dir").pack(side="left")
            dir_box = ttk.Combobox(
                frame,
                values=["up", "down"],
                width=5,
                state="readonly"
            )
            dir_box.pack(side="left")
            dir_box.set("down" if delta.get() < 0 else "up")

            def on_wheel_change(*_):
                try:
                    obj["repeat"] = max(1, repeat.get())
                    obj["delta"] = 120 if dir_box.get() == "up" else -120
                    self.save()
                except:
                    pass

            repeat.trace_add("write", on_wheel_change)
            dir_box.bind("<<ComboboxSelected>>", on_wheel_change)

        if not is_trigger and obj.get("type") == "delay":
            sec = tk.DoubleVar(value=obj.get("seconds", 1.0))
            ttk.Entry(frame, textvariable=sec, width=5).pack(side="left")
            ttk.Label(frame, text="s").pack(side="left")
            sec.trace_add("write", lambda *_: self._safe_set_float(obj, "seconds", sec))

        if not is_trigger and obj.get("type") == "click_pos":
            # Display current position
            pos_display = self._format_pos_display(obj)
            pos_lbl = ttk.Label(frame, text=pos_display, width=14, foreground="blue")
            pos_lbl.pack(side="left")
            
            ttk.Button(
                frame,
                text="Set Position",
                command=lambda lbl=pos_lbl: self.capture_position(obj, status_lbl, lbl)
            ).pack(side="left", padx=4)
            
            # Button type selection (left/right)
            btn_var = tk.StringVar(value=obj.get("button", "left"))
            ttk.Combobox(
                frame,
                values=["left", "right"],
                textvariable=btn_var,
                width=6,
                state="readonly"
            ).pack(side="left", padx=3)
            btn_var.trace_add(
                "write",
                lambda *_: self._set(obj, "button", btn_var.get())
            )

        if not is_trigger and obj.get("type") == "click_global":
            # Display current position (global click for popups/downloads)
            pos_display = self._format_pos_display(obj)
            pos_lbl = ttk.Label(frame, text=pos_display, width=14, foreground="purple")
            pos_lbl.pack(side="left")
            
            ttk.Button(
                frame,
                text="Set Position",
                command=lambda lbl=pos_lbl: self.capture_position(obj, status_lbl, lbl)
            ).pack(side="left", padx=4)
            
            # Button type selection (left/right)
            btn_var = tk.StringVar(value=obj.get("button", "left"))
            ttk.Combobox(
                frame,
                values=["left", "right"],
                textvariable=btn_var,
                width=6,
                state="readonly"
            ).pack(side="left", padx=3)
            btn_var.trace_add(
                "write",
                lambda *_: self._set(obj, "button", btn_var.get())
            )

        if not is_trigger and obj.get("type") == "clipboard":
            # Action selector for copy or paste
            action_var = tk.StringVar(value=obj.get("action", "paste"))
            ttk.Combobox(
                frame,
                values=["copy", "paste"],
                textvariable=action_var,
                width=6,
                state="readonly"
            ).pack(side="left", padx=3)
            action_var.trace_add(
                "write",
                lambda *_: self._set(obj, "action", action_var.get())
            )

        if is_trigger: 
            cond = tk.StringVar(value=obj.get("condition", "if_found"))
            ttk.Combobox(
                frame,
                values=["if_found", "if_not_found", "always"],
                textvariable=cond,
                width=12,
                state="readonly"
            ).pack(side="left")
            cond.trace_add("write", lambda *_: self._set(obj, "condition", cond.get()))

        if uses_image:
            ttk.Button(
                frame,
                text="Capture",
                command=lambda: self.capture(obj, macro, thumb, is_trigger)
            ).pack(side="left", padx=3)

        if not is_trigger:
            ttk.Button(
                frame,
                text="↑",
                width=1,
                command=lambda: self.move_step(macro, obj, -1)
            ).pack(side="left")

            ttk.Button(
                frame,
                text="↓",
                width=1,
                command=lambda: self.move_step(macro, obj, 1)
            ).pack(side="left")

        if not is_trigger:           
            ttk.Button(
                frame,
                text="✖",
                width=3,
                command=lambda: self.remove_step(macro, obj, frame)
            ).pack(side="left", padx=2)

        ttk.Button(
            frame,
            text="Test",
            command=lambda: self.test_obj(obj, status_lbl)
        ).pack(side="left", padx=3)

        status_lbl.pack(side="left", padx=4)

    # ---------- HELPERS ----------
    def _safe_set(self, obj, key, var):
        """Safely set integer value."""
        try:
            obj[key] = int(var.get())
            self.save()
        except:
            pass

    def _safe_set_float(self, obj, key, var):
        """Safely set float value."""
        try:
            obj[key] = float(var.get())
            self.save()
        except:
            pass

    def _set(self, obj, key, value):
        """Set value and save."""
        obj[key] = value
        self.save()

    def _format_key_display(self, obj):
        """Format key display text from VK code and modifiers."""
        vk = obj.get("vk")
        modifiers = obj.get("modifiers", [])
        
        if vk is None:
            return "[Not Set]"
        
        # VK code to name mapping
        VK_NAMES = {
            0x08: "Backspace", 0x09: "Tab", 0x0D: "Enter", 0x1B: "Esc",
            0x20: "Space", 0x21: "PgUp", 0x22: "PgDn", 0x23: "End",
            0x24: "Home", 0x25: "Left", 0x26: "Up", 0x27: "Right",
            0x28: "Down", 0x2D: "Insert", 0x2E: "Delete",
            0x70: "F1", 0x71: "F2", 0x72: "F3", 0x73: "F4",
            0x74: "F5", 0x75: "F6", 0x76: "F7", 0x77: "F8",
            0x78: "F9", 0x79: "F10", 0x7A: "F11", 0x7B: "F12",
        }
        
        # Get key name
        if vk in VK_NAMES:
            key_name = VK_NAMES[vk]
        elif 0x30 <= vk <= 0x39:  # 0-9
            key_name = chr(vk)
        elif 0x41 <= vk <= 0x5A:  # A-Z
            key_name = chr(vk)
        elif 0x60 <= vk <= 0x69:  # Numpad 0-9
            key_name = f"Num{vk - 0x60}"
        else:
            key_name = f"VK{vk}"
        
        # Build modifier prefix
        mod_names = []
        if 0x11 in modifiers:  # VK_CONTROL
            mod_names.append("Ctrl")
        if 0x10 in modifiers:  # VK_SHIFT
            mod_names.append("Shift")
        if 0x12 in modifiers:  # VK_ALT
            mod_names.append("Alt")
        
        if mod_names:
            return f"{'+'.join(mod_names)}+{key_name}"
        else:
            return key_name

    def _format_pos_display(self, obj):
        """Format position display text from click_x and click_y."""
        x = obj.get("click_x")
        y = obj.get("click_y")
        
        if x is None or y is None:
            return "[Not Set]"
        
        return f"({x}, {y})"

    def capture_position(self, step, status_lbl, pos_lbl=None):
        """Capture screen position by pressing Insert."""
        messagebox.showinfo(
            "Capture Position",
            "Position the mouse at the desired location and press INSERT"
        )

        def worker():
            with keyboard.Listener(on_press=lambda k: k == keyboard.Key.insert and False) as l:
                l.join()
            mx, my = mouse.Controller().position
            self.after(0, lambda: self.finish_position_capture(step, mx, my, status_lbl, pos_lbl))

        threading.Thread(target=worker, daemon=True).start()

    def finish_position_capture(self, step, x, y, status_lbl, pos_lbl=None):
        """Finish position capture process."""
        step["click_x"] = x
        step["click_y"] = y
        self.save()
        
        # Update the position label if provided
        if pos_lbl:
            pos_lbl.config(text=f"({x}, {y})")
        
        status_lbl.config(text="OK", foreground="green")

    def update_thumb(self, lbl, path):
        """Update thumbnail image."""
        try:
            img = Image.open(path).copy()  # FORÇA reload real
            img = img.resize((40, 40))

            tkimg = ImageTk.PhotoImage(img)

            lbl.configure(image=tkimg, text="")
            lbl.image = tkimg  # mantém referência viva

        except Exception as e:
            lbl.configure(text="ERR")

    def capture_key(self, step, status_lbl, key_lbl=None):
        """Capture keyboard key combination (supports Ctrl+, Shift+, Alt+)."""
        messagebox.showinfo(
            "Capture Key",
            "Press a key combination (e.g., Ctrl+1, Shift+A)\n\nHold modifiers and press the main key."
        )

        def worker():
            captured = {"vk": None, "modifiers": []}
            pressed_modifiers = set()
            
            # VK codes for modifiers
            VK_CONTROL = 0x11
            VK_SHIFT = 0x10
            VK_ALT = 0x12  # VK_MENU

            def on_press(key):
                vk = None
                
                # Get VK code
                if hasattr(key, "vk"):
                    vk = key.vk
                elif isinstance(key, keyboard.Key):
                    vk = key.value.vk
                else:
                    return  # Ignore unknown keys
                
                # Check if it's a modifier
                if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
                    pressed_modifiers.add(VK_CONTROL)
                    return  # Don't stop, wait for main key
                elif key == keyboard.Key.shift or key == keyboard.Key.shift_l or key == keyboard.Key.shift_r:
                    pressed_modifiers.add(VK_SHIFT)
                    return
                elif key == keyboard.Key.alt_l or key == keyboard.Key.alt_r or key == keyboard.Key.alt_gr:
                    pressed_modifiers.add(VK_ALT)
                    return
                
                # It's the main key - capture it with current modifiers
                captured["vk"] = vk
                captured["modifiers"] = list(pressed_modifiers)
                return False  # Stop listener

            with keyboard.Listener(on_press=on_press) as l:
                l.join()

            self.after(0, lambda: self.finish_key_capture(
                step, 
                captured.get("vk"), 
                captured.get("modifiers", []),
                status_lbl,
                key_lbl
            ))

        threading.Thread(target=worker, daemon=True).start()

    def finish_key_capture(self, step, vk, modifiers, status_lbl, key_lbl=None):
        """Finish key capture process with modifiers support."""
        if vk is None:
            status_lbl.config(text="FAILED", foreground="red")
            return

        step["vk"] = vk
        step["modifiers"] = modifiers
        self.save()
        
        # Get formatted display
        display = self._format_key_display(step)
        
        # Update the key label if provided
        if key_lbl:
            key_lbl.config(text=display)
        
        status_lbl.config(text="OK", foreground="green")

    def capture(self, obj, macro, lbl, is_trigger):
        """Capture image from screen."""
        messagebox.showinfo("Capture", "Position the mouse and press INSERT")

        def worker():
            with keyboard.Listener(on_press=lambda k: k==keyboard.Key.insert and False) as l:
                l.join()
            mx, my = mouse.Controller().position
            size = obj.get("img_size", 13)
            img = ImageGrab.grab((mx-size, my-size, mx+size, my+size))
            if is_trigger:
                filename = "trigger.png"
            else:
                filename = f"{obj['image_id']}.png"

            path = os.path.join(MACRO_DIR, macro["id"], filename)

            img.save(path)
            self.after(0, lambda: self.finish_capture(obj, path, lbl))

        threading.Thread(target=worker, daemon=True).start()

    def finish_capture(self, obj, path, lbl):
        """Finish capture process."""
        obj["image"] = path

        try:
            # força atualização visual
            if lbl.winfo_exists():
                lbl.configure(image="", text="...")
                lbl.image = None
                self.update_thumb(lbl, path)
        except (tk.TclError, AttributeError):
            # Widget pode ter sido destruído
            pass

        self.save()

    def test_obj(self, obj, status_lbl):
        """Test image location."""
        if not self.hwnd:
            status_lbl.config(text="NO WINDOW", foreground="orange")
            return

        if not obj.get("image"):
            status_lbl.config(text="NO IMAGE", foreground="orange")
            return

        pos = locate(self.hwnd, obj["image"], obj["confidence"])
        if pos:
            status_lbl.config(
                text=f"FOUND ({pos[0]}, {pos[1]})",
                foreground="green"
            )
        else:
            status_lbl.config(text="NOT FOUND", foreground="red")

    def add_step(self, parent, macro):
        """Add a new step to macro."""
        win = tk.Toplevel(self)
        win.title("Step Type")
        win.resizable(False, False)

        # tamanho fixo
        w, h = 180, 100
        x = (win.winfo_screenwidth() - w) // 2
        y = (win.winfo_screenheight() - h) // 2
        win.geometry(f"{w}x{h}+{x}+{y}")

        win.transient(self)
        win.grab_set()

        ttk.Label(win, text="Select step type:").pack(pady=5)

        step_type = tk.StringVar(value="click")
        cb = ttk.Combobox(
            win,
            textvariable=step_type,
            values=["click_image", "click_pos", "click_global", "drag", "wheel", "delay", "key", "clipboard"],
            state="readonly"
        )
        cb.pack(pady=5)

        result = {"type": None}

        def ok():
            result["type"] = step_type.get()
            win.destroy()

        ok_btn = ttk.Button(win, text="OK", command=ok)
        ok_btn.pack(pady=5)
        ok_btn.focus_set()
        win.bind("<Return>", lambda e: ok())
        win.bind("<Escape>", lambda e: win.destroy())

        self.wait_window(win)

        t = result["type"]
        if not t: 
            return
        
        # Map display names to internal types
        display_to_type = {"click_image": "click"}
        t = display_to_type.get(t, t)
        step = {
            "type": t,
            "image": None,
            "confidence": 0.80,
            "condition": "always",
            "img_size": 13,
            "image_id": str(uuid.uuid4())
        }

        if t == "click":
            step["button"] = "left"
        if t == "drag":
            step["dx"] = -40
            step["dy"] = 0
        if t == "wheel": 
            step["delta"], step["repeat"] = -120, 1
        if t == "delay": 
            step["seconds"] = 1.0
        if t == "key": 
            step["vk"] = None
            step["modifiers"] = []  # For key combos like Ctrl+1
        if t == "click_pos":
            step["click_x"] = None
            step["click_y"] = None
            step["button"] = "left"
        if t == "click_global":
            step["click_x"] = None
            step["click_y"] = None
            step["button"] = "left"
        if t == "clipboard":
            step["action"] = "paste"  # Default to paste, can be copy or paste

        macro["steps"].append(step)
        self.save()
        self.add_image_row(parent, step, macro)
        btn = macro.get("_add_btn")
        if btn:
            btn.pack_forget()
            btn.pack(pady=6)

        for w in parent.winfo_children():
            if isinstance(w, ttk.Button) and w["text"] == "+ Add Step":
                w.pack_forget()
                w.pack(pady=6)

    def toggle_all_macros(self):
        """Toggle all macros on/off."""
        any_running = any(r.running for r in self.runners.values())

        if any_running:
            self.log("STOP ALL")
            for macro_id in self.runners:
                self.set_macro_state(macro_id, False)
        else:
            self.log("START ALL")
            for macro_id in self.runners:
                self.set_macro_state(macro_id, True)

        self.update_start_all_button()

    def update_start_all_button(self):
        """Update start all button state."""
        any_running = any(r.running for r in self.runners.values())

        if any_running:
            self.start_all_btn.config(
                text="STOP ALL",
                bg="darkred"
            )
        else:
            self.start_all_btn.config(
                text="START ALL",
                bg="darkgreen"
            )

    def toggle_macro(self, macro_id):
        """Toggle single macro on/off."""
        runner = self.runners.get(macro_id)
        if not runner:
            return

        self.set_macro_state(macro_id, not runner.running)

    def stop_all_macros(self):
        """Stop all running macros."""
        for macro_id in self.runners:
            self.set_macro_state(macro_id, False)

    def start_all_macros(self):
        """Start all macros."""
        self.log("START ALL")
        for macro_id, runner in self.runners.items():
            if not runner.running:
                self.set_macro_state(macro_id, True)

    def remove_step(self, macro, step, frame):
        """Remove a step from macro."""
        if step in macro["steps"]:
            macro["steps"].remove(step)
            self.save()
            frame.destroy()

    def choose_window(self):
        """Show window selection dialog."""
        win = tk.Toplevel(self)
        win.title("Select Window")
        win.geometry("550x350")

        lst = tk.Listbox(win)
        lst.pack(fill="both", expand=True)

        windows = list_windows()
        for hwnd, title in windows:
            lst.insert("end", f"{title}  |  {hwnd}")

        selected = {}

        def ok():
            if not lst.curselection():
                return
            i = lst.curselection()[0]
            hwnd, title = windows[i]
            selected["hwnd"] = hwnd
            selected["title"] = title
            win.destroy()

        ttk.Button(win, text="OK", command=ok).pack(pady=5)
        self.wait_window(win)
        return selected if selected else None
    
    def select_window(self):
        """Select target window."""
        sel = self.choose_window()
        if not sel:
            return

        self.hwnd = sel["hwnd"]
        self.data["window"] = sel
        self.window_lbl.config(text=sel["title"])
        self.save()
    
    def get_hwnd(self):
        """Get current window handle."""
        if self.hwnd and win32gui.IsWindow(self.hwnd):
            return self.hwnd

        saved = self.data.get("window")
        if not saved:
            return None

        def enum(hwnd, _):
            if win32gui.GetWindowText(hwnd) == saved["title"]:
                self.hwnd = hwnd

        win32gui.EnumWindows(enum, None)
        return self.hwnd
