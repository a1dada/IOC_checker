import tkinter as tk

ENCRYPTION_TYPES = {
    0: ("0x0", "по умолчанию используется значение RC4_HMAC_MD5"),
    1: ("0x1", "DES_CBC_CRC"),
    2: ("0x2", "DES_CBC_MD5"),
    3: ("0x3", "DES_CBC_CRC, DES_CBC_MD5"),
    4: ("0x4", "RC4"),
    5: ("0x5", "DES_CBC_CRC, RC4"),
    6: ("0x6", "DES_CBC_MD5, RC4"),
    7: ("0x7", "DES_CBC_CRC, DES_CBC_MD5, RC4"),
    8: ("0x8", "AES 128"),
    9: ("0x9", "DES_CBC_CRC, AES 128"),
    10: ("0xA", "DES_CBC_MD5, AES 128"),
    11: ("0xB", "DES_CBC_CRC, DES_CBC_MD5, AES 128"),
    12: ("0xC", "RC4, AES 128"),
    13: ("0xD", "DES_CBC_CRC, RC4, AES 128"),
    14: ("0xE", "DES_CBC_MD5, RC4, AES 128"),
    15: ("0xF", "DES_CBC_CRC, DES_CBC_MD5, RC4, AES 128"),
    16: ("0x10", "AES 256"),
    17: ("0x11", "DES_CBC_CRC, AES 256"),
    18: ("0x12", "DES_CBC_MD5, AES 256"),
    19: ("0x13", "DES_CBC_CRC, DES_CBC_MD5, AES 256"),
    20: ("0x14", "RC4, AES 256"),
    21: ("0x15", "DES_CBC_CRC, RC4, AES 256"),
    22: ("0x16", "DES_CBC_MD5, RC4, AES 256"),
    23: ("0x17", "DES_CBC_CRC, DES_CBC_MD5, RC4, AES 256"),
    24: ("0x18", "AES 128, AES 256"),
    25: ("0x19", "DES_CBC_CRC, AES 128, AES 256"),
    26: ("0x1A", "DES_CBC_MD5, AES 128, AES 256"),
    27: ("0x1B", "DES_CBC_CRC, DES_CBC_MD5, AES 128, AES 256"),
    28: ("0x1C", "RC4, AES 128, AES 256"),
    29: ("0x1D", "DES_CBC_CRC, RC4, AES 128, AES 256"),
    30: ("0x1E", "DES_CBC_MD5, RC4, AES 128, AES 256"),
    31: ("0x1F", "DES_CBC_CRC, DES_CBC_MD5, RC4-HMAC, AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96"),
}


def create_encryption_frame(
    root,
    parent_frame,
    BG_COLOR,
    BTN_COLOR,
    TEXT_COLOR,
    FRAME_BG,
    OUTPUT_BG,
    TREEVIEW_BG
):
    HEADER_BG = BTN_COLOR
    HEADER_FG = TEXT_COLOR
    DEFAULT_ROW_COLOR = FRAME_BG
    HIGHLIGHT_COLOR = "#DAA520"

    frame = tk.Frame(parent_frame, bg=FRAME_BG)

    label = tk.Label(
        frame,
        text="Введите значение msDS-SupportedEncryptionTypes:",
        bg=FRAME_BG,
        fg=TEXT_COLOR
    )
    label.pack(anchor="w", padx=5, pady=(5, 0))

    input_frame = tk.Frame(frame, bg=FRAME_BG)
    input_frame.pack(fill="x", padx=5)

    entry = tk.Entry(
        input_frame,
        width=20,
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR
    )
    entry.pack(side="left", fill="x", expand=True)

    # ===== Поле результата =====
    result_frame = tk.Frame(frame, bg=FRAME_BG)
    result_frame.pack(fill="x", padx=5, pady=5)

    output_var = tk.StringVar()
    output_entry = tk.Entry(
        result_frame,
        textvariable=output_var,
        state="readonly",
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        readonlybackground=OUTPUT_BG
    )
    output_entry.pack(side="left", fill="x", expand=True)

    def copy_result():
        root.clipboard_clear()
        root.clipboard_append(output_var.get())
        root.update()

    tk.Button(
        result_frame,
        text="📋",
        command=copy_result,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="right", padx=5)

    incident_label = tk.Label(
        frame,
        text="",
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        font=("Arial", 12, "bold")
    )
    incident_label.pack(anchor="w", padx=5, pady=2)

    # ===== ЛОГИКА РАСЧЁТА =====

    def calculate(val=None):
        try:
            if val is None:
                val = entry.get().strip()

            val = int(val)
            if val not in ENCRYPTION_TYPES:
                output_var.set("Неверное значение")
                incident_label.config(text="")
                highlight_row(None)
                return

            _, desc = ENCRYPTION_TYPES[val]
            output_var.set(desc)

            is_incident = "RC4" in desc or "DES" in desc
            incident_label.config(
                text="Инцидент" if is_incident else "Безопасно",
                fg="red" if is_incident else "green"
            )

            highlight_row(val)

        except Exception:
            output_var.set("Ошибка ввода")
            incident_label.config(text="")
            highlight_row(None)

    # ===== Универсальные Ctrl+C / Ctrl+V =====

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
        if event.keycode == 67:   # C
            return _copy_entry(event)
        if event.keycode == 86:   # V
            return _paste_entry(event)

    entry.bind("<Control-KeyPress>", _on_ctrl_key)

    # ===== Enter / Ctrl+Enter =====

    def on_enter(event=None):
        val = entry.get().strip()
        if not val:
            return "break"

        entry.delete(0, tk.END)   # UX: расчёт пошёл
        calculate(val)
        return "break"

    entry.bind("<Return>", on_enter)
    entry.bind("<KP_Enter>", on_enter)

    entry.bind("<Control-Return>", lambda e: calculate())
    entry.bind("<Control-KP_Enter>", lambda e: calculate())

    tk.Button(
        input_frame,
        text="Рассчитать",
        command=lambda: calculate(),
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="right", padx=5)

    # ===== ТАБЛИЦА =====

    header_frame = tk.Frame(frame, bg=HEADER_BG)
    header_frame.pack(fill="x", padx=5)

    headers = ["Десятичное", "Шестнадцатеричное", "Типы шифрования", "Инцидент"]
    for h in headers:
        tk.Label(
            header_frame,
            text=h,
            width=30,
            bg=HEADER_BG,
            fg=HEADER_FG,
            font=("Arial", 10, "bold")
        ).pack(side="left")

    table_container = tk.Frame(frame, bg=FRAME_BG)
    table_container.pack(fill="both", expand=True, padx=5, pady=5)

    canvas = tk.Canvas(table_container, bg=FRAME_BG, highlightthickness=0)
    scrollbar = tk.Scrollbar(table_container, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg=FRAME_BG)

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    row_refs = {}

    def highlight_row(selected_value):
        for val, widgets in row_refs.items():
            color = HIGHLIGHT_COLOR if val == selected_value else DEFAULT_ROW_COLOR
            for w in widgets:
                w.config(bg=color)

    for i, (dec, (hexv, desc)) in enumerate(ENCRYPTION_TYPES.items()):
        is_incident = "RC4" in desc or "DES" in desc

        w1 = tk.Label(scrollable_frame, text=str(dec), width=20,
                      bg=DEFAULT_ROW_COLOR, fg=TEXT_COLOR)
        w2 = tk.Label(scrollable_frame, text=hexv, width=20,
                      bg=DEFAULT_ROW_COLOR, fg=TEXT_COLOR)
        w3 = tk.Label(scrollable_frame, text=desc, width=60,
                      anchor="w", justify="left", wraplength=500,
                      bg=DEFAULT_ROW_COLOR, fg=TEXT_COLOR)
        w4 = tk.Label(scrollable_frame, text="Да" if is_incident else "Нет",
                      width=10, bg=DEFAULT_ROW_COLOR, fg=TEXT_COLOR)

        w1.grid(row=i, column=0, sticky="w", padx=1)
        w2.grid(row=i, column=1, sticky="w", padx=1)
        w3.grid(row=i, column=2, sticky="w", padx=1)
        w4.grid(row=i, column=3, sticky="w", padx=1)

        row_refs[dec] = (w1, w2, w3, w4)

    return frame
