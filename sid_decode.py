import tkinter as tk
import pyperclip
import re
from sid_data import SID_ENTRIES

# Пояснения FSMO ролей
FSMO_EXPLAIN = {
    "PDC Emulator": (
        "Эмулятор первичного контроллера домена (PDC). "
        "Обеспечивает обратную совместимость с NT4, синхронизацию времени и приоритет изменений паролей."
    ),
    "": ""
}


def explain_sid(sid: str) -> str:
    parts = sid.strip().split("-")
    if len(parts) < 3:
        return "❌ Ошибка: неверный формат SID."

    out = []
    out.append("🧾 АНАЛИЗ SID")
    out.append(f"Полный SID: {sid}\n")

    rev = parts[1]
    out.append(f"🔹 Revision: {rev}")
    out.append("    ➤ Версия структуры SID. Всегда «1» в современных Windows.\n")

    auth = parts[2]
    auth_name = "NT Authority" if auth == "5" else "Unknown Authority"
    out.append(f"🔹 Identifier Authority: {auth} ({auth_name})")
    out.append("    ➤ Источник выдачи SID.\n")

    subs = parts[3:]
    if subs:
        out.append(f"🔹 SubAuthorities ({len(subs)}): {', '.join(subs)}")
        out.append(
            "    ➤ Компоненты:\n"
            f"      • {subs[0]} — доменный / локальный SID.\n"
        )
        if len(subs) > 1:
            out.append(
                "      • " + ", ".join(subs[1:-1]) +
                " — идентификатор домена или машины.\n"
            )
            out.append(f"      • {subs[-1]} — RID объекта.\n")
    else:
        out.append("🔹 SubAuthorities: отсутствуют\n")

    for e in SID_ENTRIES:
        if e["sid"] == sid:
            out.append(f"✅ Известный SID: {e['name']}")
            out.append(f"📄 Описание: {e['description']}")
            if e["fsmo_role"]:
                expl = FSMO_EXPLAIN.get(e["fsmo_role"], "")
                out.append(f"🎯 FSMO Role: {e['fsmo_role']} — {expl}")
            break

    return "\n".join(out)


def create_sid_frame(
    root,
    parent,
    BG_COLOR,
    BTN_COLOR,
    TEXT_COLOR,
    FRAME_BG,
    OUTPUT_BG,
    TREEVIEW_BG
):
    frame = tk.Frame(parent, bg=BG_COLOR)

    # === Цвета таблицы (зависят от темы) ===
    ROW_BG = OUTPUT_BG
    ROW_FG = TEXT_COLOR
    HIGHLIGHT_BG = "#d6cfae" if OUTPUT_BG.lower().startswith("#f") else "#DAA520"

    # Ввод SID
    tk.Label(
        frame,
        text="SID:",
        bg=BG_COLOR,
        fg=TEXT_COLOR,
        font=("Arial", 11)
    ).pack(anchor="w", padx=10, pady=(10, 0))

    sid_entry = tk.Entry(
        frame,
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR
    )
    sid_entry.pack(fill="x", padx=10, pady=5)

    btn_frame = tk.Frame(frame, bg=BG_COLOR)
    btn_frame.pack(fill="x", padx=10)

    output = tk.Text(
        frame,
        height=12,
        wrap="word",
        bg=OUTPUT_BG,
        fg=TEXT_COLOR
    )
    output.pack(fill="both", expand=True, padx=10, pady=10)

    # === Таблица известных SID ===
    table_frame = tk.Frame(frame, bg=FRAME_BG)
    table_frame.pack(fill="both", expand=True, padx=10)

    headers = ["SID", "Имя", "Описание", "FSMO Role"]
    widths = [28, 30, 100, 25]

    # Шапка таблицы = цвет кнопок
    header = tk.Frame(table_frame, bg=BTN_COLOR)
    header.pack(fill="x")

    for i, (h, w) in enumerate(zip(headers, widths)):
        tk.Label(
            header,
            text=h,
            bg=BTN_COLOR,
            fg=TEXT_COLOR,
            font=("Arial", 10, "bold"),
            width=w,
            anchor="w"
        ).grid(row=0, column=i, sticky="w")

    canvas = tk.Canvas(table_frame, bg=FRAME_BG, highlightthickness=0)
    scrollbar = tk.Scrollbar(table_frame, orient="vertical", command=canvas.yview)
    scroll = tk.Frame(canvas, bg=FRAME_BG)

    scroll.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scroll, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    row_refs = {}
    for r, e in enumerate(SID_ENTRIES):
        labels = []
        for c, key in enumerate(["sid", "name", "description", "fsmo_role"]):
            lbl = tk.Label(
                scroll,
                text=e[key],
                bg=ROW_BG,
                fg=ROW_FG,
                wraplength=1000 if key == "description" else 0,
                justify="left",
                font=("Arial", 9),
                width=widths[c],
                anchor="w"
            )
            lbl.grid(row=r, column=c, sticky="w", padx=1, pady=1)
            labels.append(lbl)
        row_refs[e["sid"]] = labels

    def highlight(sid_val):
        for sid, widgets in row_refs.items():
            bg = HIGHLIGHT_BG if sid == sid_val else ROW_BG
            for w in widgets:
                w.config(bg=bg)

    def do_decode():
        s = sid_entry.get().strip()
        output.delete("1.0", tk.END)
        if not re.match(r"^S-\d+(-\d+)+$", s):
            output.insert("1.0", "❌ Неверный формат SID.")
            highlight(None)
            return
        output.insert("1.0", explain_sid(s))
        highlight(s)

    def do_paste():
        sid_entry.delete(0, tk.END)
        sid_entry.insert(0, pyperclip.paste())
        do_decode()

    tk.Button(btn_frame, text="Вставить и декодировать",
              command=do_paste, bg=BTN_COLOR, fg=TEXT_COLOR).pack(side="left")
    tk.Button(btn_frame, text="Декодировать",
              command=do_decode, bg=BTN_COLOR, fg=TEXT_COLOR).pack(side="left", padx=5)

    return frame
