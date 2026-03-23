import os
import threading
import requests
import tkinter as tk
from tkinter import ttk
import webbrowser
from collections import defaultdict
import json

APIS_FILE = "apis.txt"

OTX_SEARCH_URL = "https://otx.alienvault.com/api/v1/search/pulses"
OTX_PULSE_URL = "https://otx.alienvault.com/api/v1/pulses"

MITRE_JSON_FILE = "mitre_attack.json"

_MITRE_TECHNIQUES = {}
_MITRE_TACTICS = {}


# ============================================================
# API KEY
# ============================================================

def load_otx_key():
    if not os.path.exists(APIS_FILE):
        return ""
    with open(APIS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("otx="):
                return line.strip().split("=", 1)[1]
    return ""


# ============================================================
# HELPERS
# ============================================================

def extract_domain(email: str) -> str:
    return email.split("@", 1)[1].lower()


def otx_search(query: str, headers: dict):
    try:
        r = requests.get(
            OTX_SEARCH_URL,
            headers=headers,
            params={"q": query},
            timeout=90
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("results", []), data.get("count", 0)
    except Exception:
        pass
    return [], 0


def otx_get_pulse(pulse_id: str, headers: dict):
    try:
        r = requests.get(
            f"{OTX_PULSE_URL}/{pulse_id}",
            headers=headers,
            timeout=30
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def load_mitre_from_json():
    if not os.path.exists(MITRE_JSON_FILE):
        return

    try:
        with open(MITRE_JSON_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            ext_refs = obj.get("external_references", [])
            mitre_id = None

            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
                    break

            if not mitre_id:
                continue

            # имя техники
            _MITRE_TECHNIQUES[mitre_id] = obj.get("name", "Unknown technique")

            # тактика
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    _MITRE_TACTICS[mitre_id] = (
                        phase.get("phase_name", "")
                        .replace("-", " ")
                        .title()
                    )

    except Exception:
        pass



def mitre_tactic(tech_id: str) -> str:
    return (
        _MITRE_TACTICS.get(tech_id)
        or _MITRE_TACTICS.get(tech_id.split(".")[0])
        or "Other"
    )


def mitre_name(tech_id: str) -> str:
    return _MITRE_TECHNIQUES.get(tech_id, "Unknown technique")



def classify_tag(tag: str):
    t = tag.lower()
    if "phish" in t:
        return "tag_phish"
    if "malware" in t or "loader" in t:
        return "tag_mal"
    if "brand" in t:
        return "tag_brand"
    if "js" in t or "html" in t:
        return "tag_tech"
    return "tag_generic"


# ============================================================
# UI
# ============================================================

class EmailOTXUI:
    def __init__(self, root, parent, BG, BTN, TXT, FRAME_BG, OUTPUT_BG):
        load_mitre_from_json()
        
        self.root = root
        self.api_key = load_otx_key()
        self.headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}

        self.frame = tk.Frame(parent, bg=FRAME_BG)
        self.frame.pack(fill="both", expand=True)

        # ===== Header =====
        tk.Label(
            self.frame,
            text="Email Reputation",
            bg=FRAME_BG,
            fg=TXT,
            font=("Arial", 12, "bold")
        ).pack(anchor="w", padx=10, pady=(8, 4))

        # ===== Input =====
        top = tk.Frame(self.frame, bg=FRAME_BG)
        top.pack(fill="x", padx=10)

        self.entry = tk.Entry(top, bg=OUTPUT_BG, fg=TXT, insertbackground=TXT)
        self.entry.pack(side="left", fill="x", expand=True)

        self.entry.bind("<Control-KeyPress>", self._on_ctrl_key)
        self.entry.bind("<Return>", lambda e: self.start())
        self.entry.bind("<KP_Enter>", lambda e: self.start())

        tk.Button(
            top,
            text="▶ Проверить",
            bg=BTN,
            fg="white",
            command=self.start
        ).pack(side="right", padx=4)

        # ===== Progress =====
        style = ttk.Style()
        style.configure("SOC.Horizontal.TProgressbar", thickness=4)

        self.status = tk.Label(self.frame, text="", bg=FRAME_BG, fg=TXT)
        self.status.pack(anchor="w", padx=10, pady=(4, 2))

        self.progress = ttk.Progressbar(
            self.frame,
            mode="determinate",
            maximum=100,
            style="SOC.Horizontal.TProgressbar"
        )
        self.progress.pack(fill="x", padx=10)

        # ===== Output =====
        self.text = tk.Text(
            self.frame,
            wrap="word",
            bg=OUTPUT_BG,
            fg=TXT,
            font=("Consolas", 9)
        )
        self.text.pack(fill="both", expand=True, padx=10, pady=(6, 10))
        self.text.config(state="disabled")

        self._init_tags()

    # --------------------------------------------------------

    def _on_ctrl_key(self, event):
        if event.keycode == 67:  # Ctrl+C
            self.root.clipboard_clear()
            self.root.clipboard_append(self.entry.get())
            return "break"
        if event.keycode == 86:  # Ctrl+V
            try:
                self.entry.delete(0, tk.END)
                self.entry.insert(0, self.root.clipboard_get())
            except tk.TclError:
                pass
            return "break"

    def _set_stage(self, text: str, value: int):
        self.status.config(text=text)
        self.progress["value"] = value
        self.root.update_idletasks()

    def _init_tags(self):
        t = self.text
        t.tag_config("h1", font=("Consolas", 10, "bold"))
        t.tag_config("h2", font=("Consolas", 9, "bold"))
        t.tag_config("muted", foreground="#888888")
        t.tag_config("warn", foreground="#eab308")

        t.tag_config("tag_phish", background="#fde68a")
        t.tag_config("tag_mal", background="#fecaca")
        t.tag_config("tag_brand", background="#e9d5ff")
        t.tag_config("tag_tech", background="#bbf7d0")
        t.tag_config("tag_generic", background="#e5e7eb")

    def _w(self, s, tag=None):
        self.text.insert("end", s, tag)

    def _hr(self):
        self._w("\n" + "─" * 90 + "\n\n", "muted")

    def _badge(self, txt):
        self._w(" ")
        self._w(f" {txt} ", classify_tag(txt))
        self._w(" ")

    def _link(self, title, url):
        tag = f"link_{hash(url)}"
        self.text.tag_config(tag, foreground="#1a73e8", underline=1)
        self.text.tag_bind(tag, "<Button-1>", lambda e, u=url: webbrowser.open(u))
        self._w("  🔗 ")
        self._w(title, tag)
        self._w("\n")

    # ========================================================

    def start(self):
        email = self.entry.get().strip()
        if not self.api_key or "@" not in email:
            return

        # UX: очищаем поле сразу
        self.entry.delete(0, tk.END)

        self.text.config(state="normal")
        self.text.delete("1.0", tk.END)
        self.text.config(state="disabled")

        self.progress["value"] = 0
        self._set_stage("Проверка email…", 10)

        threading.Thread(
            target=self._worker,
            args=(email,),
            daemon=True
        ).start()

    def _worker(self, email):
        domain = extract_domain(email)

        self.root.after(0, lambda: self._set_stage("Поиск источников…", 40))
        pulses, total = otx_search(email, self.headers)
        if not pulses:
            pulses, total = otx_search(domain, self.headers)

        self.root.after(
            0,
            lambda: self._render(email, domain, pulses, total)
        )

    # ========================================================

    def _render(self, email, domain, pulses, total_count):
        self._set_stage("Подготовка вывода…", 80)

        self.text.config(state="normal")

        shown = len(pulses)

        self._w("🛰️ AlienVault OTX — Email Reputation\n", "h1")
        self._w(f"Email: {email}\n", "muted")
        self._w(f"Domain: {domain}\n", "muted")
        self._w(
            f"Найдено пульсов: {shown} из {total_count} "
            f"(в выводе может быть не полное количекство референсов, где встречалась данная почта)\n",
            "muted"
        )
        self._w(
            "Полный список и дополнительные связи доступны по ссылкам ниже.\n",
            "muted"
        )
        self._hr()

        all_tags = set()
        mitre = defaultdict(set)
        full_pulses = []

        for p in pulses:
            fp = otx_get_pulse(p["id"], self.headers)
            if not fp:
                continue
            full_pulses.append(fp)
            all_tags.update(fp.get("tags", []))
            for tid in fp.get("attack_ids", []):
                mitre[mitre_tactic(tid)].add(tid)

        if all_tags:
            self._w("🏷️ Tags:\n", "h2")
            for t in sorted(all_tags):
                self._badge(t)
            self._w("\n")
            self._hr()

        if mitre:
            self._w("🧭 MITRE ATT&CK:\n", "h2")
            for tactic, techs in mitre.items():
                self._w(f"{tactic}:\n", "warn")
                for t in sorted(techs):
                    self._w(f"  • {t} — {mitre_name(t)}\n")
            self._hr()

        self._w("📌 Pulses:\n", "h2")

        for p in full_pulses:
            self._w(f"▸ {p.get('name')}\n", "warn")
            self._w(f"  Author: {p.get('author_name')}\n", "muted")
            self._w(f"  TLP: {p.get('TLP')}\n", "muted")

            if p.get("references"):
                self._w("  References:\n", "muted")
                for r in p["references"]:
                    self._link(r, r)

            self._link(
                "Open pulse in OTX",
                f"https://otx.alienvault.com/pulse/{p['id']}"
            )
            self._hr()

        self._w("🔗 Дополнительные источники:\n", "h2")
        self._link(
            "Открыть email в AlienVault OTX",
            f"https://otx.alienvault.com/indicator/email/{email}"
        )
        self._link(
            "Открыть domain в AlienVault OTX",
            f"https://otx.alienvault.com/indicator/domain/{domain}"
        )

        self.text.config(state="disabled")
        self._set_stage("Готово", 100)


# ============================================================
# FACTORY
# ============================================================

def create_email_reputation_frame(
    root,
    parent,
    BG_COLOR,
    BTN_COLOR,
    TEXT_COLOR,
    FRAME_BG,
    OUTPUT_BG
):
    frame = tk.Frame(parent, bg=FRAME_BG)
    EmailOTXUI(
        root,
        frame,
        BG_COLOR,
        BTN_COLOR,
        TEXT_COLOR,
        FRAME_BG,
        OUTPUT_BG
    )
    return frame
