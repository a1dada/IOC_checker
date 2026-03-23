import tkinter as tk

NETLOGON_ERRORS = {
    "0x0": ("STATUS_SUCCESS", "Коды ошибок входа 0x0 указывают на то, что аутентификация прошла успешно и учётная запись корректно прошла все этапы проверки, включая пароль, политики безопасности и доступность контроллера домена."),
    "0xC000005E": ("STATUS_NO_LOGON_SERVERS", "Коды ошибок входа 0xC000005E указывают на то, что система не смогла связаться ни с одним доступным контроллером домена, что обычно связано с сетевыми проблемами, недоступностью DC, ошибками DNS или нарушением доверительного канала."),
    "0xC0000064": ("STATUS_NO_SUCH_USER", "Коды ошибок входа 0xC0000064 указывают на то, что указанная учётная запись не существует в домене или локальной системе, что может быть вызвано опечаткой в имени пользователя либо попыткой входа под удалённой или никогда не существовавшей учётной записью."),
    "0xC000006A": ("STATUS_WRONG_PASSWORD", "Коды ошибок входа 0xC000006A указывают на то, что имя пользователя найдено, но введённый пароль не совпадает с сохранённым"),
    "0xC000006D": ("STATUS_LOGON_FAILURE", "Коды ошибок входа 0xC000006D указывают на то, что аутентификация не была успешной без уточнения причины, так как система намеренно не раскрывает детали, и такая ситуация часто используется для маскировки различий между неверным паролем и несуществующей учётной записью."),
    "0xC000006E": ("STATUS_ACCOUNT_RESTRICTION", "Коды ошибок входа 0xC000006E указывают на то, что вход был запрещён из-за ограничений учётной записи, таких как требования политик безопасности, тип входа или дополнительные условия, не связанные напрямую с паролем."),
    "0xC000006F": ("STATUS_INVALID_LOGON_HOURS", "Коды ошибок входа 0xC000006F указывают на то, что попытка входа выполнена вне разрешённого временного интервала, заданного в свойствах учётной записи, и система корректно заблокировала аутентификацию."),
    "0xC0000070": ("STATUS_INVALID_WORKSTATION", "Коды ошибок входа 0xC0000070 указывают на то, что вход выполняется с рабочей станции, не разрешённой для данной учётной записи, что связано с ограничениями по списку допустимых компьютеров."),
    "0xC0000071": ("STATUS_PASSWORD_EXPIRED", "Коды ошибок входа 0xC0000071 указывают на то, что пароль учётной записи истёк и пользователь обязан выполнить процедуру смены пароля перед получением доступа."),
    "0xC0000072": ("STATUS_ACCOUNT_DISABLED", "Коды ошибок входа 0xC0000072 указывают на то, что учётная запись находится в отключённом состоянии и не может быть использована для входа до её повторного включения администратором."),
    "0xC00000DC": ("STATUS_INVALID_SERVER_STATE", "Коды ошибок входа 0xC00000DC указывают на то, что текущее состояние учётной записи требует обязательной смены пароля, при этом обычный вход в систему до выполнения этого условия невозможен."),
    "0xC0000133": ("STATUS_TIME_DIFFERENCE_AT_DC", "Коды ошибок входа 0xC0000133 указывают на то, что между системой и контроллером домена зафиксирована недопустимая разница во времени, что нарушает работу механизмов Kerberos и блокирует аутентификацию."),
    "0xC000015B": ("STATUS_LOGON_TYPE_NOT_GRANTED", "Коды ошибок входа 0xC000015B указывают на то, что для учётной записи отсутствует право на вход данным способом, например через RDP, службу или сетевой доступ, согласно действующим политикам."),
    "0xC000018C": ("STATUS_TRUSTED_DOMAIN_FAILURE", "Коды ошибок входа 0xC000018C указывают на то, что нарушены доверительные отношения между доменами или между компьютером и доменом, что делает невозможной проверку учётных данных."),
    "0xC0000192": ("STATUS_NETLOGON_NOT_STARTED", "Коды ошибок входа 0xC0000192 указывают на то, что служба Netlogon не функционирует корректно или учётная запись была заблокирована в результате политики безопасности."),
    "0xC0000193": ("STATUS_ACCOUNT_EXPIRED", "Коды ошибок входа 0xC0000193 указывают на то, что срок действия учётной записи истёк и она более не может использоваться для аутентификации."),
    "0xC0000224": ("STATUS_PASSWORD_MUST_CHANGE", "Коды ошибок входа 0xC0000224 указывают на то, что система требует обязательной смены пароля при следующей попытке входа и не разрешает стандартную аутентификацию до выполнения этого условия."),
    "0xC0000234": ("STATUS_ACCOUNT_LOCKED_OUT", "Коды ошибок входа 0xC0000234 указывают на то, что учётная запись была заблокирована из-за превышения допустимого количества неудачных попыток входа."),
    "0xC00002EE": ("STATUS_UNFINISHED_CONTEXT_DELETED", "Коды ошибок входа 0xC00002EE указывают на то, что не удалось установить или сохранить защищённый контекст аутентификации, что часто связано с сетевыми сбоями или нарушением безопасного канала."),
    "0xC0000413": ("STATUS_AUTHENTICATION_FIREWALL_FAILED", "Коды ошибок входа 0xC0000413 указывают на то, что аутентификация была отклонена механизмами защитных политик, такими как Authentication Firewall или дополнительные проверки безопасности."),
}


def create_netlogon_frame(
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
        text="Введите код ошибки Netlogon (например: 0xC00002EE):",
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

    # ===== ЛОГИКА РАСЧЁТА =====

    def calculate(val=None):
        if val is None:
            val = entry.get().strip()

        raw_code = val.upper().replace("0X", "0x")
        if raw_code not in NETLOGON_ERRORS:
            output_var.set("Неизвестный код")
            explanation_text.delete("1.0", tk.END)
            explanation_text.insert(tk.END, "Нет описания для данного кода.")
            highlight_row(None)
            return

        status, explanation = NETLOGON_ERRORS[raw_code]
        output_var.set(status)
        explanation_text.delete("1.0", tk.END)
        explanation_text.insert(tk.END, explanation)
        highlight_row(raw_code)

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

        entry.delete(0, tk.END)   # UX: расчёт запущен
        calculate(val)
        return "break"

    entry.bind("<Return>", on_enter)
    entry.bind("<KP_Enter>", on_enter)

    entry.bind("<Control-Return>", lambda e: calculate())
    entry.bind("<Control-KP_Enter>", lambda e: calculate())

    def paste_and_calculate():
        try:
            entry.delete(0, tk.END)
            entry.insert(0, root.clipboard_get())
            calculate()
        except tk.TclError:
            pass

    tk.Button(
        input_frame,
        text="Вставить и рассчитать",
        command=paste_and_calculate,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="right", padx=5)

    # ===== РЕЗУЛЬТАТ =====

    output_var = tk.StringVar()
    output_entry = tk.Entry(
        frame,
        textvariable=output_var,
        state="readonly",
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        readonlybackground=OUTPUT_BG
    )
    output_entry.pack(fill="x", padx=5, pady=5)

    explanation_frame = tk.Frame(frame, bg=FRAME_BG)
    explanation_frame.pack(fill="x", padx=5, pady=(0, 5))

    explanation_text = tk.Text(
        explanation_frame,
        height=5,
        wrap="word",
        bg=OUTPUT_BG,
        fg=TEXT_COLOR
    )
    explanation_text.pack(side="left", fill="both", expand=True)

    def copy_explanation():
        text = explanation_text.get("1.0", tk.END).strip()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()

    tk.Button(
        explanation_frame,
        text="📋",
        command=copy_explanation,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="right", padx=5, pady=5)

    # ===== ТАБЛИЦА =====

    header_frame = tk.Frame(frame, bg=HEADER_BG)
    header_frame.pack(fill="x", padx=5)

    for h in ["Код", "Статус"]:
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

    def highlight_row(selected_code):
        for code, widgets in row_refs.items():
            color = HIGHLIGHT_COLOR if code == selected_code else DEFAULT_ROW_COLOR
            for w in widgets:
                w.config(bg=color)

    for i, (code, (status, _)) in enumerate(NETLOGON_ERRORS.items()):
        w1 = tk.Label(
            scrollable_frame,
            text=code,
            width=30,
            bg=DEFAULT_ROW_COLOR,
            fg=TEXT_COLOR
        )
        w2 = tk.Label(
            scrollable_frame,
            text=status,
            width=60,
            anchor="w",
            bg=DEFAULT_ROW_COLOR,
            fg=TEXT_COLOR
        )

        w1.grid(row=i, column=0, sticky="w", padx=1)
        w2.grid(row=i, column=1, sticky="w", padx=1)

        row_refs[code] = (w1, w2)

    return frame
