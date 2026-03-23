import os
import re
import requests
import webbrowser
import tkinter as tk
import ipaddress
from urllib.parse import quote

APIS_FILE = "apis.txt"
OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"
TRANSLATE_URL = "https://translate.googleapis.com/translate_a/single"

def translate_text_google(text: str, sl="auto", tl="ru", timeout=10) -> str:

    text = (text or "").strip()
    if not text:
        return ""

    params = {
        "client": "gtx",
        "sl": sl,     # source language (auto/en/ru)
        "tl": tl,     # target language
        "dt": "t",
        "q": text
    }

    try:
        r = requests.get(TRANSLATE_URL, params=params, timeout=timeout)
        if r.status_code != 200:
            return text

        data = r.json()
        # Формат обычно такой: data[0] = [[translated_part, original_part, ...], ...]
        parts = []
        for chunk in (data[0] or []):
            if chunk and isinstance(chunk, list) and chunk[0]:
                parts.append(chunk[0])
        return "".join(parts).strip() or text
    except Exception:
        return text

def looks_cyrillic(s: str) -> bool:
    return bool(re.search(r"[А-Яа-яЁё]", s or ""))



# ============================================================
#                     API KEYS
# ============================================================

def load_api_key():
    if not os.path.exists(APIS_FILE):
        return ""

    with open(APIS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("otx="):
                return line.strip().split("=", 1)[1]
    return ""


# ============================================================
#                    IOC TYPE
# ============================================================

def detect_ioc_type(val: str):
    val = (val or "").strip()

    if len(val) in (32, 40, 64):
        return "file", val

    if val.startswith("http://") or val.startswith("https://"):
        return "url", quote(val, safe="")

    try:
        ipaddress.ip_address(val)
        return "IPv4", val
    except ValueError:
        pass

    if "." in val:
        return "domain", val

    return None, val



# ============================================================
#                       UI
# ============================================================

class OTXCheckUI:
    def __init__(self, parent, FRAME_BG, OUTPUT_BG, TEXT_COLOR):
        self.api_key = load_api_key()
        self.headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}

        self.text = tk.Text(
            parent,
            wrap="word",
            bg=OUTPUT_BG,
            fg=TEXT_COLOR,
            font=("Consolas", 9),
            insertbackground=TEXT_COLOR
        )
        self.text.pack(fill="both", expand=True, padx=6, pady=6)

        self._link_map = {}
        self._init_tags()
        self.last_pulses = None

    # --------------------------------------------------------

    def _init_tags(self):
        t = self.text

        t.tag_config("h1", font=("Consolas", 10, "bold"))
        t.tag_config("h2", font=("Consolas", 9, "bold"))
        t.tag_config("label", font=("Consolas", 9, "bold"))
        t.tag_config("muted", foreground="#888888")
        t.tag_config("warn", foreground="#eab308")
        t.tag_config("bad", foreground="#ef4444")
        t.tag_config("sep")

        # badges (как в malware.py)
        t.tag_config("badge_base", font=("Consolas", 9, "bold"))
        t.tag_config("badge_soft", foreground="#1f1f1f", background="#e8eaed")

    # --------------------------------------------------------

    def _w(self, s, tag=None):
        self.text.insert("end", s, tag)

    def _hr(self):
        self._w("\n" + "_" * 90 + "\n\n", "sep")

    def _badge(self, text):
        self._w("  ")
        self._w(f" {text} ", ("badge_base", "badge_soft"))
        self._w(" ")

    def _link(self, title, url, indent=""):
        tag = f"link_{len(self._link_map) + 1}"
        self._link_map[tag] = url

        self.text.tag_config(tag, foreground="#1a73e8", underline=1)
        self.text.tag_bind(tag, "<Button-1>", lambda e, u=url: webbrowser.open(u))
        self.text.tag_bind(tag, "<Enter>", lambda e: self.text.config(cursor="hand2"))
        self.text.tag_bind(tag, "<Leave>", lambda e: self.text.config(cursor=""))

        self._w(f"{indent}🔗 ")
        self._w(title, tag)
        self._w("\n")

    # ========================================================
    #                      FETCH
    # ========================================================

    def fetch(self, ioc: str):
        self.last_pulses = None  # сигнал: запрос запущен
        self.text.delete("1.0", tk.END)

        if not self.api_key:
            self.last_pulses = []  # запрос завершён, данных нет
            self._w("OTX API key не задан. Укажите его в настройках.\n", "bad")
            return

        ioc_type, value = detect_ioc_type(ioc)
        if not ioc_type:
            self._w("Не удалось определить тип IOC\n", "bad")
            return

        self._w("🛰️ AlienVault OTX\n", "h1")
        self._w("IOC: ", "muted")
        self._w(f"{ioc}\n", "label")
        self._w(f"Тип: {ioc_type}\n", "muted")

        self._hr()

        def get(section):
            try:
                r = requests.get(
                    f"{OTX_BASE}/{ioc_type}/{value}/{section}",
                    headers=self.headers,
                    timeout=15
                )
                if r.status_code == 200:
                    return r.json()
            except Exception:
                pass
            return None

        # ================= GENERAL =================

        general = get("general")
        if not general:
            self.last_pulses = []  # запрос завершён, pulses пустые
            self._w("Нет данных OTX\n", "muted")
            return

        pulse_info = general.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        self.last_pulses = pulses

        self._w("🧠 Threat Context (Pulses)\n", "h2")
        self._w(f"• Pulses: {len(pulses)}\n\n", "muted")

        for p in pulses:
            self._w(f"▸ {p.get('name', '-')}\n", "warn")

            if p.get("TLP"):
                self._w(f"  TLP: {p['TLP']}\n", "muted")

            tags = p.get("tags", [])
            if tags:
                self._w("  Tags:\n", "muted")
                for t in tags[:20]:
                    self._badge(t)
                self._w("\n")

            if p.get("description"):
                original_desc = p["description"].strip()

                if original_desc and not looks_cyrillic(original_desc):
                    translated_desc = translate_text_google(original_desc, sl="en", tl="ru")
                    self._w("\n  Описание (RU перевод):\n", "muted")
                    for l in translated_desc.splitlines():
                        self._w(f"    {l}\n")
                else:
                    # Если описание уже русское — выводим как есть
                    self._w("\n  Описание:\n", "muted")
                    for l in original_desc.splitlines():
                        self._w(f"    {l}\n")


            if p.get("attack_ids"):
                self._w("\n  MITRE ATT&CK:\n", "muted")
                for a in p["attack_ids"]:
                    self._w(f"    • {a['id']} — {a['display_name']}\n")

            refs = p.get("references", [])
            if refs:
                self._w("\n  Sources / References:\n", "muted")
                for r in refs:
                    self._link(r, r, indent="    ")

            self._hr()

        # ================= FINAL LINK =================

        self._link(
            "Открыть карточку IOC в AlienVault OTX",
            f"https://otx.alienvault.com/indicator/{ioc_type}/{value}"
        )


# ============================================================
#                  FACTORY
# ============================================================

def create_otx_tab(parent, FRAME_BG, OUTPUT_BG, TEXT_COLOR):
    return OTXCheckUI(parent, FRAME_BG, OUTPUT_BG, TEXT_COLOR)
