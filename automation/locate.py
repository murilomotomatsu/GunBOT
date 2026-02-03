# ================= IMAGE LOCATION =================
import os
import time
import cv2

from .window import capture_window


def locate(hwnd, path, conf, retries=3, delay=0.15):
    """Locate image template in window using OpenCV template matching."""
    if not path or not os.path.exists(path):
        return None

    for _ in range(retries):
        result = capture_window(hwnd)
        if not result:
            time.sleep(delay)
            continue

        frame, ox, oy = result
        tpl = cv2.imread(path)

        if tpl is None:
            return None

        fh, fw = frame.shape[:2]
        th, tw = tpl.shape[:2]

        if th > fh or tw > fw:
            return None  # template maior que a janela

        try:
            res = cv2.matchTemplate(frame, tpl, cv2.TM_CCOEFF_NORMED)
            _, v, _, loc = cv2.minMaxLoc(res)
        except cv2.error:
            time.sleep(delay)
            continue

        if v >= conf:
            x, y = loc
            return ox + x + tw // 2, oy + y + th // 2

        time.sleep(delay)

    return None
