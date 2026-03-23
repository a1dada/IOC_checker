import tkinter as tk

UAC_FLAGS = {
    0x00000001: "SCRIPT (скрипт входа в систему)",
    0x00000002: "ACCOUNTDISABLE (учетная запись отключена)",
    0x00000008: "HOMEDIR_REQUIRED (требуется домашний каталог)",
    0x00000010: "LOCKOUT (учетная запись заблокирована)",
    0x00000020: "PASSWD_NOTREQD (пароль не требуется)",
    0x00000040: "PASSWD_CANT_CHANGE (нельзя сменить пароль)",
    0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED (разрешён зашифрованный пароль)",
    0x00000100: "TEMP_DUPLICATE_ACCOUNT (временная учетная запись)",
    0x00000200: "NORMAL_ACCOUNT (обычная учетная запись)",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT (междоменная учетная запись)",
    0x00001000: "WORKSTATION_TRUST_ACCOUNT (учетная запись рабочей станции)",
    0x00002000: "SERVER_TRUST_ACCOUNT (учетная запись сервера)",
    0x00010000: "DONT_EXPIRE_PASSWORD (пароль не истекает)",
    0x00020000: "MNS_LOGON_ACCOUNT (специальная учетная запись MNS)",
    0x00040000: "SMARTCARD_REQUIRED (требуется смарт-карта)",
    0x00080000: "TRUSTED_FOR_DELEGATION (доверена для делегирования)",
    0x00100000: "NOT_DELEGATED (не подлежит делегированию)",
    0x00200000: "USE_DES_KEY_ONLY (только DES-ключи)",
    0x00400000: "DONT_REQUIRE_PREAUTH (не требует преаутентификации)",
    0x00800000: "PASSWORD_EXPIRED (пароль просрочен)",
    0x01000000: "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (Kerberos доверие)",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT (учетная запись с частичными секретами)"
}

EXPLANATIONS = {
    0x00000001: "SCRIPT — этот флаг означает, что для учётной записи пользователя в Active Directory задан скрипт входа, который выполняется автоматически при интерактивном входе пользователя в систему (обычно через logon.bat, logon.cmd, PowerShell-скрипт и т. п.).",
    0x00000002: "ACCOUNTDISABLE — этот флаг означает, что учётная запись отключена — пользователь или компьютер не могут пройти аутентификацию в домене и войти в систему до тех пор, пока флаг ACCOUNTDISABLE (0x00000002) не будет снят администратором.",
    0x00000008: "HOMEDIR_REQUIRED — этот флаг означает, что для учётной записи требуется наличие домашнего каталога — параметр HOMEDIR_REQUIRED (0x00000008) указывает, что вход пользователя в систему возможен только при корректно настроенном и доступном home-каталоге.",
    0x00000010: "LOCKOUT — этот флаг означает, что учётная запись заблокирована — параметр LOCKOUT (0x00000010) устанавливается автоматически системой при превышении допустимого числа неудачных попыток входа и временно запрещает аутентификацию до истечения политики блокировки либо ручной разблокировки администратором.",
    0x00000020: "PASSWD_NOTREQD — этот флаг означает, что для учётной записи не требуется пароль — параметр PASSWD_NOTREQD (0x00000020) допускает аутентификацию без установленного пароля, что является устаревшей и небезопасной настройкой, применявшейся в ранних версиях Windows; в современных доменных средах наличие этого флага рассматривается как высокий риск безопасности, поскольку он может указывать на некорректную конфигурацию или попытку ослабления контроля доступа.",
    0x00000040: "PASSWD_CANT_CHANGE — этот флаг означает, что пользователь не может самостоятельно изменить пароль — параметр PASSWD_CANT_CHANGE (0x00000040) ограничивает возможность смены пароля со стороны учётной записи и обычно применяется к сервисным или техническим пользователям.",
    0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED — этот флаг означает, что для учётной записи разрешено хранение зашифрованного пароля в обратимом виде — параметр ENCRYPTED_TEXT_PWD_ALLOWED (0x00000080) допускает сохранение пароля таким образом, что он может быть восстановлен в исходном виде, что эквивалентно хранению пароля в открытом тексте.",
    0x00000100: "TEMP_DUPLICATE_ACCOUNT — этот флаг означает, что учётная запись является временной дублирующей — параметр TEMP_DUPLICATE_ACCOUNT (0x00000100) используется для устаревших сценариев доверительных отношений и миграций между доменами, при которых создавалась временная копия учётной записи.",
    0x00000200: "NORMAL_ACCOUNT — этот флаг означает, что учётная запись является обычной пользовательской — параметр NORMAL_ACCOUNT (0x00000200) указывает на стандартный тип учётной записи для пользователей домена, предназначенной для интерактивного и сетевого входа.",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT — этот флаг означает, что учётная запись используется для междоменного доверия — параметр INTERDOMAIN_TRUST_ACCOUNT (0x00000800) применяется к техническим объектам, обслуживающим доверительные отношения между доменами Active Directory, и не предназначен для интерактивного входа.",
    0x00001000: "WORKSTATION_TRUST_ACCOUNT — этот флаг означает, что учётная запись является учётной записью рабочей станции — параметр WORKSTATION_TRUST_ACCOUNT 0x00001000 применяется к компьютерным объектам Active Directory и используется для аутентификации машин в домене, его наличие является нормальным для объектов типа Computer, а появление у пользовательской учётной записи считается аномалией и указывает на ошибку конфигурации или некорректно созданный объект.",
    0x00002000: "SERVER_TRUST_ACCOUNT — этот флаг означает, что учётная запись является учётной записью сервера доверия — параметр SERVER_TRUST_ACCOUNT 0x00002000 используется для объектов доменных контроллеров и обеспечивает аутентификацию сервера в рамках домена, его наличие является нормальным только для контроллеров домена, а появление у пользовательских или обычных компьютерных учётных записей указывает на некорректную конфигурацию.",
    0x00010000: "DONT_EXPIRE_PASSWORD — этот флаг означает, что пароль для учётной записи никогда не истекает — параметр DONT_EXPIRE_PASSWORD 0x00010000 отключает применение политики срока действия пароля, что обычно используется для сервисных или технических учётных записей.",
    0x00020000: "MNS_LOGON_ACCOUNT — этот флаг означает, что учётная запись не может использоваться для делегирования — параметр NOT_DELEGATED 0x00020000 запрещает передачу учётных данных данной учётной записи другим сервисам при аутентификации, что применяется для защиты чувствительных пользователей и сервисов, и указывает на усиленные ограничения безопасности для данной учётной записи.",
    0x00040000: "SMARTCARD_REQUIRED — этот флаг означает, что учётная запись использует только DES-шифрование для Kerberos — параметр USE_DES_KEY_ONLY 0x00040000 ограничивает применение алгоритмов шифрования Kerberos устаревшим DES, что связано с поддержкой старых систем и приложений, и в современных доменах считается небезопасной и нежелательной настройкой.",
    0x00080000: "TRUSTED_FOR_DELEGATION — этот флаг означает, что для учётной записи не требуется предварительная аутентификация Kerberos — параметр DONT_REQUIRE_PREAUTH 0x00080000 позволяет запрашивать билеты Kerberos без этапа предварительной проверки, что используется крайне редко и обычно только для специальных сервисов, при этом такая настройка значительно снижает уровень защиты учётной записи.",
    0x00100000: "NOT_DELEGATED — этот флаг означает, что пароль учётной записи считается истёкшим — параметр PASSWORD_EXPIRED 0x00100000 указывает, что при следующей попытке входа пользователю потребуется сменить пароль, при этом аутентификация возможна только в рамках процедуры смены пароля и до её завершения доступ к ресурсам будет ограничен.",
    0x00200000: "USE_DES_KEY_ONLY — этот флаг означает, что учётная запись поддерживает аутентификацию только с использованием Kerberos AES — параметр USE_AES_KEYS 0x00200000 указывает, что для данной учётной записи разрешены современные алгоритмы шифрования AES вместо устаревших механизмов, что является корректной и рекомендуемой настройкой для доменных сред и повышает криптографическую стойкость аутентификации.",
    0x00400000: "DONT_REQUIRE_PREAUTH — этот флаг означает, что учётная запись требует смарт-карту для входа — параметр SMARTCARD_REQUIRED 0x00400000 указывает, что аутентификация возможна только при использовании смарт-карты или аналогичного сертификатного механизма, что применяется в средах с повышенными требованиями к безопасности и исключает вход по одному лишь паролю.",
    0x00800000: "PASSWORD_EXPIRED — этот флаг означает, что учётная запись помечена как доверенная для делегирования — параметр TRUSTED_FOR_DELEGATION 0x00800000 позволяет сервисам, работающим от имени данной учётной записи, передавать учётные данные пользователя другим сервисам, что используется для сложных сценариев аутентификации и требует строгого контроля из-за расширения области доверия.",
    0x01000000: "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION — этот флаг означает, что учётная запись доверена для аутентификации с ограниченным делегированием — параметр TRUSTED_TO_AUTH_FOR_DELEGATION 0x01000000 позволяет службе, работающей от имени этой учётной записи, аутентифицировать пользователей и передавать их учётные данные только к строго определённым сервисам, что используется в сценариях constrained delegation и требует точной настройки списков разрешённых сервисов.",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT — этот флаг означает, что учётная запись использует только ключи RC4 для Kerberos — параметр USE_RC4_KEY 0x04000000 указывает, что при аутентификации Kerberos применяется алгоритм RC4 вместо более современных механизмов, что связано с совместимостью со старыми системами и в современных доменах считается нежелательной настройкой."
}


def classify_flags(bits):
    type_parts = []
    status = []
    notes = []

    if 0x00002000 in bits:
        type_parts.append("серверная")
    elif 0x00001000 in bits:
        type_parts.append("рабочей станции")
    elif 0x00000800 in bits:
        type_parts.append("междоменная")
    elif 0x00000200 in bits:
        type_parts.append("обычная")
    elif 0x00000100 in bits:
        type_parts.append("временная")

    if 0x00000002 in bits:
        status.append("отключена")
    if 0x00000010 in bits:
        status.append("заблокирована")
    if 0x00010000 in bits:
        status.append("пароль не истекает")
    if 0x00000020 in bits:
        status.append("пароль не требуется")
    if 0x00040000 in bits:
        status.append("требуется смарт-карта")
    if 0x00400000 in bits:
        status.append("без pre-auth")
    if 0x00800000 in bits:
        status.append("пароль истёк")

    for bit in bits:
        if bit in EXPLANATIONS:
            notes.append(f"- {EXPLANATIONS[bit]}")

    return (
        f"Учётная запись: {', '.join(type_parts) if type_parts else 'не определена'}\n"
        f"Статус: {', '.join(status) if status else 'без особенностей'}\n\n"
        f"Пояснения:\n" + ("\n\n".join(notes) if notes else "—")
    )


def create_uac_frame(
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

    DEFAULT_ROW_BG = OUTPUT_BG
    ROW_TEXT_COLOR = TEXT_COLOR
    HIGHLIGHT_BG = "#d6cfae" if OUTPUT_BG.lower().startswith("#f") else "#666633"

    frame = tk.Frame(parent_frame, bg=FRAME_BG)

    tk.Label(
        frame,
        text="Введите значение UserAccountControl:",
        bg=FRAME_BG,
        fg=TEXT_COLOR
    ).pack(anchor="w", padx=5, pady=(5, 0))

    input_frame = tk.Frame(frame, bg=FRAME_BG)
    input_frame.pack(fill="x", padx=5)

    entry = tk.Entry(
        input_frame,
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR
    )
    entry.pack(side="left", fill="x", expand=True)

    output_box = tk.Text(
        frame,
        height=18,
        wrap="word",
        bg=OUTPUT_BG,
        fg=TEXT_COLOR
    )
    output_box.pack(fill="x", padx=5, pady=5)

    # ===== ЛОГИКА ДЕКОДИРОВАНИЯ =====

    def decode(val=None):
        try:
            if val is None:
                val = entry.get().strip()

            value = int(val)
            bits = [b for b in UAC_FLAGS if value & b]

            output_box.delete("1.0", tk.END)

            if bits:
                output_box.insert(tk.END, classify_flags(bits) + "\n\n")
                output_box.insert(tk.END, "Активные флаги:\n")
                for b in bits:
                    output_box.insert(
                        tk.END,
                        f"{b} ({hex(b)}) — {UAC_FLAGS[b]}\n"
                    )
            else:
                output_box.insert(tk.END, "Нет активных флагов")

            highlight(bits)

        except Exception:
            output_box.delete("1.0", tk.END)
            output_box.insert(tk.END, "Ошибка ввода")
            highlight([])

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

        entry.delete(0, tk.END)   # UX-сигнал: декодирование запущено
        decode(val)
        return "break"

    entry.bind("<Return>", on_enter)
    entry.bind("<KP_Enter>", on_enter)

    entry.bind("<Control-Return>", lambda e: decode())
    entry.bind("<Control-KP_Enter>", lambda e: decode())

    def paste_and_decode():
        try:
            entry.delete(0, tk.END)
            entry.insert(0, root.clipboard_get())
            decode()
        except tk.TclError:
            pass

    tk.Button(
        input_frame,
        text="Вставить и декодировать",
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        command=paste_and_decode
    ).pack(side="right", padx=5)

    tk.Button(
        input_frame,
        text="Декодировать",
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        command=lambda: decode()
    ).pack(side="right", padx=5)

    # ===== ТАБЛИЦА ФЛАГОВ =====

    header = tk.Frame(frame, bg=HEADER_BG)
    header.pack(fill="x", padx=5)

    for text, width in zip(("DEC", "HEX", "Описание"), (12, 16, 60)):
        tk.Label(
            header,
            text=text,
            width=width,
            bg=HEADER_BG,
            fg=HEADER_FG,
            font=("Arial", 10, "bold"),
            anchor="w"
        ).pack(side="left")

    table = tk.Frame(frame, bg=FRAME_BG)
    table.pack(fill="both", expand=True, padx=5, pady=5)

    row_refs = {}

    def highlight(active):
        for bit, widgets in row_refs.items():
            bg = HIGHLIGHT_BG if bit in active else DEFAULT_ROW_BG
            for w in widgets:
                w.config(bg=bg)

    for i, (bit, desc) in enumerate(sorted(UAC_FLAGS.items())):
        w0 = tk.Label(
            table,
            text=str(bit),
            width=12,
            bg=DEFAULT_ROW_BG,
            fg=ROW_TEXT_COLOR,
            anchor="w"
        )
        w1 = tk.Label(
            table,
            text=hex(bit),
            width=16,
            bg=DEFAULT_ROW_BG,
            fg=ROW_TEXT_COLOR,
            anchor="w"
        )
        w2 = tk.Label(
            table,
            text=desc,
            width=60,
            bg=DEFAULT_ROW_BG,
            fg=ROW_TEXT_COLOR,
            anchor="w",
            justify="left",
            wraplength=600
        )

        w0.grid(row=i, column=0, sticky="w", padx=1, pady=1)
        w1.grid(row=i, column=1, sticky="w", padx=1, pady=1)
        w2.grid(row=i, column=2, sticky="w", padx=1, pady=1)

        row_refs[bit] = (w0, w1, w2)

    return frame
