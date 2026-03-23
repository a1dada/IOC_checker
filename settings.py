# settings.py
import os
import json
import tkinter as tk
from tkinter import ttk, messagebox, colorchooser

from etalon_settings import ETALON_THEMES, get_etalon_colors

APIS_FILE = "apis.txt"
UI_SETTINGS_FILE = "ui_settings.json"


# ============================================================
#                    API KEYS
# ============================================================

def load_api_keys():
    keys = {
        "virustotal": "",
        "abuseipdb": "",
         "otx": "",
        "censys_token": "",
        "abusech": "",
        "urlscan": "",
        "vuln": ""
    }

    if os.path.exists(APIS_FILE):
        with open(APIS_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "=" not in line:
                    continue
                k, v = line.strip().split("=", 1)
                k = k.lower().strip()
                if k in keys:
                    keys[k] = v.strip()

    return keys


def save_api_keys(keys: dict):
    order = ["virustotal", "abuseipdb", "otx", "censys_token", "abusech","urlscan","vuln"]
    with open(APIS_FILE, "w", encoding="utf-8") as f:
        for name in order:
            f.write(f"{name}={keys.get(name, '').strip()}\n")


# ============================================================
#                    UI SETTINGS
# ============================================================

def load_ui_settings():
    if not os.path.exists(UI_SETTINGS_FILE):
        return {"theme": "dark", "overrides": {}}

    try:
        with open(UI_SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"theme": "dark", "overrides": {}}


def save_ui_settings(data: dict):
    with open(UI_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_ui_colors():
    ui = load_ui_settings()
    theme = ui.get("theme", "dark")

    base = get_etalon_colors(theme)
    overrides = ui.get("overrides", {})

    # пользователь может менять ТОЛЬКО цвет кнопок
    if "BTN_COLOR" in overrides:
        base["BTN_COLOR"] = overrides["BTN_COLOR"]
        base["TABLE_HEADER_BG"] = overrides["BTN_COLOR"]

    return base


# ============================================================
#                    THEME PREVIEW CARD
# ============================================================

def create_theme_preview(parent, theme_name, active_var, on_change):
    colors = get_etalon_colors(theme_name)

    is_active = active_var.get() == theme_name
    border_color = "#ff6a00" if is_active else colors["SEPARATOR_COLOR"]

    card = tk.Frame(
        parent,
        bg=colors["FRAME_BG"],
        highlightbackground=border_color,
        highlightthickness=2,
        width=180,
        height=120
    )
    card.pack(side="left", padx=12)
    card.pack_propagate(False)

    tk.Label(
        card,
        text=theme_name.upper(),
        bg=colors["FRAME_BG"],
        fg=colors["TEXT_COLOR"],
        font=("Arial", 10, "bold")
    ).pack(pady=(6, 4))

    preview = tk.Frame(card, bg=colors["OUTPUT_BG"])
    preview.pack(fill="both", expand=True, padx=8, pady=6)

    tk.Label(
        preview,
        text="Пример текста",
        bg=colors["OUTPUT_BG"],
        fg=colors["TEXT_COLOR"],
        anchor="w"
    ).pack(anchor="w", pady=2)

    tk.Button(
        preview,
        text="Кнопка",
        bg=colors["BTN_COLOR"],
        fg=colors["BTN_TEXT_COLOR"],
        relief="flat"
    ).pack(anchor="w", pady=4)

    if is_active:
        tk.Label(
            card,
            text="✓",
            bg=colors["FRAME_BG"],
            fg="#ff6a00",
            font=("Arial", 14, "bold")
        ).place(relx=1.0, rely=0.0, anchor="ne", x=-6, y=4)

    def select():
        active_var.set(theme_name)
        on_change()

    card.bind("<Button-1>", lambda e: select())
    for w in card.winfo_children():
        w.bind("<Button-1>", lambda e: select())

    return card


# ============================================================
#                    SETTINGS UI
# ============================================================

def create_settings_frame(
    root,
    parent_frame,
    BG_COLOR,
    BTN_COLOR,
    TEXT_COLOR,
    FRAME_BG,
    OUTPUT_BG
):
    frame = ttk.LabelFrame(
        parent_frame,
        text="Настройки",
        padding=10,
        style="Custom.TLabelframe"
    )

    # ========================================================
    # API BLOCK
    # ========================================================

    api_block = ttk.LabelFrame(
        frame, text="API-ключи", padding=10, style="Custom.TLabelframe"
    )
    api_block.pack(fill="x", pady=(0, 15))

    current_keys = load_api_keys()
    entries = {}

    for row, (label, key) in enumerate([
        ("VirusTotal API key:", "virustotal"),
        ("AbuseIPDB API key:", "abuseipdb"),
        ("AlienVault OTX API key:", "otx"),
        ("Censys Bearer Token:", "censys_token"),
        ("abuse.ch API key:", "abusech"),
        ("URLScan API key:", "urlscan"),
        ("Vulners API key:", "vuln"),
    ]):
        tk.Label(api_block, text=label, bg=FRAME_BG, fg=TEXT_COLOR)\
            .grid(row=row, column=0, sticky="w", pady=4)

        ent = tk.Entry(
            api_block,
            bg=OUTPUT_BG,
            fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR,
            width=60
        )
        ent.grid(row=row, column=1, sticky="we", pady=4)
        ent.insert(0, current_keys.get(key, ""))
        entries[key] = ent

    api_block.columnconfigure(1, weight=1)

    tk.Button(
        api_block,
        text="💾 Сохранить API",
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        command=lambda: (
            save_api_keys({k: e.get().strip() for k, e in entries.items()}),
            messagebox.showinfo("Готово", "API-ключи сохранены")
        )
    ).grid(row=len(entries), column=0, columnspan=2, pady=(10, 0))

    # ========================================================
    # THEME CHOOSER
    # ========================================================

    theme_block = ttk.LabelFrame(
        frame, text="Тема оформления", padding=10, style="Custom.TLabelframe"
    )
    theme_block.pack(fill="x", pady=(0, 15))

    ui_settings = load_ui_settings()
    theme_var = tk.StringVar(value=ui_settings.get("theme", "dark"))

    previews_row = tk.Frame(theme_block, bg=FRAME_BG)
    previews_row.pack(anchor="w")

    # ========================================================
    # ACCENT COLOR
    # ========================================================

    accent_block = ttk.LabelFrame(
        frame, text="Цвет кнопок", padding=10, style="Custom.TLabelframe"
    )
    accent_block.pack(fill="x")

    current_accent = get_etalon_colors(theme_var.get())["BTN_COLOR"]

    preview = tk.Label(accent_block, bg=current_accent, width=10)
    preview.pack(side="left", padx=5)

    def redraw_previews():
        for w in previews_row.winfo_children():
            w.destroy()
        for name in ETALON_THEMES.keys():
            create_theme_preview(previews_row, name, theme_var, on_theme_change)

    def on_theme_change():
        nonlocal current_accent
        current_accent = get_etalon_colors(theme_var.get())["BTN_COLOR"]
        preview.config(bg=current_accent)
        redraw_previews()

    redraw_previews()

    def choose_accent():
        nonlocal current_accent
        _, color = colorchooser.askcolor(color=current_accent)
        if color:
            current_accent = color
            preview.config(bg=color)

    def reset_accent():
        nonlocal current_accent
        current_accent = get_etalon_colors(theme_var.get())["BTN_COLOR"]
        preview.config(bg=current_accent)

    tk.Button(
        accent_block, text="Изменить", bg=BTN_COLOR,
        fg=TEXT_COLOR, command=choose_accent
    ).pack(side="left", padx=5)

    tk.Button(
        accent_block, text="Сбросить", bg=BTN_COLOR,
        fg=TEXT_COLOR, command=reset_accent
    ).pack(side="left", padx=5)

    # ========================================================
    # SAVE
    # ========================================================

    def save_all():
        theme = theme_var.get()
        etalon_btn = get_etalon_colors(theme)["BTN_COLOR"]

        data = {
            "theme": theme,
            "overrides": {}
        }

        if current_accent != etalon_btn:
            data["overrides"]["BTN_COLOR"] = current_accent

        save_ui_settings(data)

        messagebox.showinfo(
            "Сохранено",
            "Настройки сохранены.\nПерезапустите приложение."
        )

    tk.Button(
        frame, text="💾 Сохранить настройки",
        bg=BTN_COLOR, fg=TEXT_COLOR, command=save_all
    ).pack(pady=10)

    return frame
