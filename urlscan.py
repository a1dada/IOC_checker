# urlscan.py
import tkinter as tk
from tkinter import messagebox
import threading
import time
import requests
import webbrowser
from io import BytesIO
from PIL import Image, ImageTk

# ============================================================
#                     API KEYS
# ============================================================

URLSCAN_API_KEY = ""  
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyDsirSL28-N0w4FHdpTOw_2EAhxEaJavHc"

try:
    from settings import load_api_keys
    _keys = load_api_keys()
    if _keys.get("urlscan"):
        URLSCAN_API_KEY = _keys["urlscan"]
except Exception:
    pass


# ============================================================
#                     URLSCAN FRAME
# ============================================================

def create_urlscan_frame(
    root,
    parent_frame,
    BG_COLOR,
    BTN_COLOR,
    TEXT_COLOR,
    FRAME_BG,
    OUTPUT_BG
):
    frame = tk.Frame(parent_frame, bg=FRAME_BG)

    # ========================================================
    # TITLE
    # ========================================================

    tk.Label(
        frame,
        text="URLScan.io — анализ веб-страницы",
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        font=("Arial", 11, "bold")
    ).pack(anchor="w", padx=6, pady=(6, 2))

    # ========================================================
    # INPUT
    # ========================================================

    top = tk.Frame(frame, bg=FRAME_BG)
    top.pack(fill="x", padx=6)

    entry = tk.Entry(
        top,
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR
    )
    entry.pack(side="left", fill="x", expand=True)

    # ===== Универсальные Ctrl+C / Ctrl+V (как в VirusTotal) =====

    def _copy_entry(event=None):
        try:
            root.clipboard_clear()
            root.clipboard_append(entry.get())
        except tk.TclError:
            pass
        return "break"

    def _paste_entry(event=None):
        try:
            entry.delete(0, tk.END)
            entry.insert(0, root.clipboard_get())
        except tk.TclError:
            pass
        return "break"

    def _on_ctrl_key(event):
        # Ctrl+C
        if event.keycode == 67:
            return _copy_entry(event)
        # Ctrl+V
        if event.keycode == 86:
            return _paste_entry(event)

    entry.bind("<Control-KeyPress>", _on_ctrl_key)

    entry.bind("<<Paste>>", _paste_entry)
    root.bind_all("<Control-v>", _paste_entry)
    root.bind_all("<Control-V>", _paste_entry)
    root.bind_all("<Control-Insert>", _paste_entry)

    def on_enter(event=None):
        start_scan()
        return "break"

    entry.bind("<Return>", on_enter)
    entry.bind("<KP_Enter>", on_enter)

    tk.Button(
        top,
        text="📋 Вставить и проверить",
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        command=lambda: (_paste_entry(), start_scan())
    ).pack(side="right", padx=5)

    # ========================================================
    # STATUS
    # ========================================================

    status = tk.Label(
        frame,
        text="",
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        font=("Arial", 9, "italic")
    )
    status.pack(anchor="w", padx=6, pady=4)

    # ========================================================
    # CONTENT
    # ========================================================

    content = tk.Frame(frame, bg=FRAME_BG)
    content.pack(fill="both", expand=True, padx=6, pady=6)

    # ---------------- LEFT: REPORT ----------------

    text = tk.Text(
        content,
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        wrap="word",
        font=("Consolas", 9)
    )
    text.pack(side="left", fill="both", expand=True, padx=(0, 6))
    text.config(state="disabled")

    text.bind(
        "<Control-c>",
        lambda e: (
            root.clipboard_clear(),
            root.clipboard_append(text.get("1.0", tk.END)),
            "break"
        )
    )

    # ---------------- RIGHT: SCREENSHOT ----------------

    right = tk.Frame(content, bg=FRAME_BG, width=360, height=260)
    right.pack(side="right", anchor="n")
    right.pack_propagate(False)

    img_label = tk.Label(
        right,
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        text="Скриншот появится\nпосле анализа",
        justify="center"
    )
    img_label.pack(fill="both", expand=True, padx=4, pady=4)

    btns = tk.Frame(right, bg=FRAME_BG)
    btns.pack(fill="x", pady=4)

    btn_report = tk.Button(
        btns,
        text="Открыть отчёт",
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        width=18,
        state="disabled"
    )
    btn_report.pack(side="left", padx=2)

    btn_screen = tk.Button(
        btns,
        text="Открыть скрин",
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        width=18,
        state="disabled"
    )
    btn_screen.pack(side="right", padx=2)

    # ---------------- GOOGLE SAFE BROWSING RESULT ----------------

    gsb_frame = tk.Frame(right, bg=FRAME_BG)
    gsb_frame.pack(fill="x", padx=4, pady=(4, 0))

    gsb_label = tk.Label(
        gsb_frame,
        text="Google Safe Browsing: проверка не выполнена",
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        justify="left",
        anchor="w",
        font=("Arial", 9, "bold")
    )
    gsb_label.pack(fill="x")

    def _update_gsb_wrap(_=None):
        try:
            w = right.winfo_width()
            if w and w > 40:
                gsb_label.configure(wraplength=w - 16)
        except Exception:
            pass

    right.bind("<Configure>", _update_gsb_wrap)

    # ========================================================
    # HELPERS
    # ========================================================

    def set_status(msg):
        status.config(text=msg)
        status.update_idletasks()

    def reset_ui():
        text.config(state="normal")
        text.delete("1.0", tk.END)
        text.config(state="disabled")

        img_label.config(image="", text="Скриншот появится\nпосле анализа")
        img_label.image = None

        btn_report.config(state="disabled")
        btn_screen.config(state="disabled")

        gsb_label.config(
            text="Google Safe Browsing: проверка не выполнена",
            fg=TEXT_COLOR
        )

    def write_report(txt):
        text.config(state="normal")
        text.delete("1.0", tk.END)
        text.insert(tk.END, txt)
        text.config(state="disabled")

    # ========================================================
    # GOOGLE SAFE BROWSING
    # ========================================================

    def check_google_safe_browsing(url):

        try:
            payload = {
                "client": {"clientId": "soc-helper", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            r = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}",
                json=payload,
                timeout=10
            )

            # Если API вернул не-JSON, не падаем.
            try:
                data = r.json()
            except Exception:
                gsb_label.config(text=f"Google Safe Browsing: ошибка ответа (HTTP {r.status_code})", fg="#f39c12")
                return

            matches = data.get("matches") if isinstance(data, dict) else None

            if not matches:
                gsb_label.config(
                    text="Google Safe Browsing: угроз не обнаружено (CLEAN)",
                    fg="#2ecc71"
                )
                return

            threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})

            explanation = {
                "MALWARE": "вредоносное ПО",
                "SOCIAL_ENGINEERING": "фишинг / социальная инженерия",
                "UNWANTED_SOFTWARE": "нежелательное ПО",
                "POTENTIALLY_HARMFUL_APPLICATION": "потенциально опасное приложение"
            }

            readable = ", ".join(explanation.get(t, t) for t in threats)

            gsb_label.config(
                text=f"Google Safe Browsing: ОБНАРУЖЕНО — {readable}",
                fg="#e74c3c"
            )

        except Exception as e:
            gsb_label.config(
                text=f"Google Safe Browsing: ошибка проверки ({e})",
                fg="#f39c12"
            )

    # ========================================================
    # URLSCAN PARSER
    # ========================================================

    def extract_primary(result):
        for item in result.get("data", {}).get("requests", []):
            r = item.get("request", {})
            if r.get("primaryRequest") and r.get("type") == "Document":
                return item
        return None

    def build_report(data):
        doc = extract_primary(data)
        if not doc:
            return "Основной HTML-документ не найден."

        req = doc["request"]["request"]
        resp = doc["response"]["response"]
        asn = doc["response"].get("asn", {})
        geo = doc["response"].get("geoip", {})
        sec = resp.get("securityDetails", {})
        timing = resp.get("timing", {})

        out = []
        a = out.append

        a("=== 🌐 HTTP ===")
        a(f"URL: {resp.get('url')}")
        a(f"Метод: {req.get('method')}")
        a(f"HTTP статус: {resp.get('status')}")
        a(f"Протокол: {resp.get('protocol')}")
        a(f"MIME: {resp.get('mimeType')}")
        a(f"Кодировка: {resp.get('charset')}")
        a("")

        a("=== 📑 HTTP заголовки ===")
        for k, v in resp.get("headers", {}).items():
            a(f"{k}: {v}")
        a("")

        a("=== 📡 Сеть ===")
        a(f"IP: {resp.get('remoteIPAddress')}:{resp.get('remotePort')}")
        a(f"ASN: AS{asn.get('asn')} — {asn.get('description')}")
        a(f"Маршрут: {asn.get('route')}")
        a("")

        a("=== 🌍 Геолокация ===")
        a(f"Страна: {geo.get('country_name')} ({geo.get('country')})")
        a(f"Регион: {geo.get('region')}")
        a(f"Город: {geo.get('city')}")
        a(f"Часовой пояс: {geo.get('timezone')}")
        a("")

        a("=== 🔐 TLS / Сертификат ===")
        a(f"TLS: {sec.get('protocol')}")
        a(f"Cipher: {sec.get('cipher')}")
        a(f"CN: {sec.get('subjectName')}")
        a(f"Issuer: {sec.get('issuer')}")
        a(f"Valid from: {time.strftime('%Y-%m-%d', time.gmtime(sec.get('validFrom', 0)))}")
        a(f"Valid to:   {time.strftime('%Y-%m-%d', time.gmtime(sec.get('validTo', 0)))}")
        a(f"SANs: {', '.join(sec.get('sanList', []))}")
        a("")

        a("=== ⏱ Тайминги (мс) ===")
        for k, v in timing.items():
            a(f"{k}: {v}")
        a("")

        a("=== 📦 Контент ===")
        a(f"HTML size: {doc['response'].get('size')} bytes")
        a(f"Response time: {resp.get('responseTime')}")

        return "\n".join(out)

    # ========================================================
    # SCREENSHOT
    # ========================================================

    def _cover_resize_to_label(img: Image.Image):

        img_label.update_idletasks()
        cw = img_label.winfo_width()
        ch = img_label.winfo_height()

        # Если Tk еще не отрисовал размеры — пробуем чуть позже.
        if cw <= 2 or ch <= 2:
            return None

        iw, ih = img.size
        scale = max(cw / iw, ch / ih)

        nw = int(iw * scale)
        nh = int(ih * scale)

        img2 = img.resize((nw, nh), Image.LANCZOS)

        left = (nw - cw) // 2
        top = (nh - ch) // 2

        img2 = img2.crop((left, top, left + cw, top + ch))
        return img2

    def load_screenshot(url):
        try:
            r = requests.get(url, timeout=20)
            img = Image.open(BytesIO(r.content)).convert("RGB")

            resized = _cover_resize_to_label(img)
            if resized is None:
                # Повтор через 120мс — когда геометрия точно посчитана
                root.after(120, lambda: load_screenshot(url))
                return

            tk_img = ImageTk.PhotoImage(resized)
            img_label.config(image=tk_img, text="")
            img_label.image = tk_img

        except Exception as e:
            img_label.config(text=f"Ошибка загрузки\n{e}")

    def open_fullscreen(url):
        win = tk.Toplevel(root)
        win.configure(bg="black")
        win.attributes("-fullscreen", True)
        win.bind("<Escape>", lambda e: win.destroy())

        img = Image.open(BytesIO(requests.get(url).content))
        tk_img = ImageTk.PhotoImage(img)
        lbl = tk.Label(win, image=tk_img, bg="black")
        lbl.image = tk_img
        lbl.pack(expand=True)

    # ========================================================
    # MAIN
    # ========================================================

    def start_scan():
        url = entry.get().strip()
        if not url:
            return

        if not URLSCAN_API_KEY:
            messagebox.showerror("Ошибка", "URLScan API key не задан")
            return

        reset_ui()
        set_status("⏳ Анализ запущен…")

        def worker():
            try:
                r = requests.post(
                    "https://urlscan.io/api/v1/scan/",
                    headers={
                        "API-Key": URLSCAN_API_KEY,
                        "Content-Type": "application/json"
                    },
                    json={"url": url, "visibility": "public"},
                    timeout=15
                )

                j = r.json()
                if "uuid" not in j:
                    raise Exception(j.get("message", "Не удалось запустить анализ"))

                uuid = j["uuid"]

                while True:
                    time.sleep(10)
                    res = requests.get(
                        f"https://urlscan.io/api/v1/result/{uuid}/",
                        headers={"API-Key": URLSCAN_API_KEY}
                    )
                    if res.status_code == 404:
                        set_status("⌛ Ожидание рендера страницы…")
                        continue

                    data = res.json()
                    set_status("✔ Анализ завершён")

                    # 1) Пишем отчет
                    write_report(build_report(data))

                    # 2) И ТОЛЬКО ТЕПЕРЬ (вместе с выводом urlscan) — GSB
                    #    чтобы результат появлялся одновременно
                    check_google_safe_browsing(url)

                    scr = data.get("task", {}).get("screenshotURL")
                    rep = data.get("task", {}).get("reportURL")

                    if scr:
                        load_screenshot(scr)
                        btn_screen.config(
                            state="normal",
                            command=lambda: open_fullscreen(scr)
                        )

                    if rep:
                        btn_report.config(
                            state="normal",
                            command=lambda: webbrowser.open(rep)
                        )
                    break

            except Exception as e:
                set_status(f"Ошибка: {e}")

        threading.Thread(target=worker, daemon=True).start()

    return frame
