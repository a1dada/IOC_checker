import tkinter as tk
from tkinter import ttk
from datetime import datetime


# === Функция конвертации времени (из Entry) ===
def convert_time(entry_ldap, output_var):
    try:
        ldap_value = entry_ldap.get().replace(" ", "")
        ldap_value = int(ldap_value)
        timestamp = (ldap_value - 116444736000000000) // 10000000
        result = datetime.utcfromtimestamp(timestamp).strftime('%d.%m.%Y')
        output_var.set(result)
    except Exception:
        output_var.set("Ошибка ввода!")


# === Функция конвертации времени (из значения) ===
def convert_time_value(val, output_var):
    try:
        ldap_value = int(val.replace(" ", ""))
        timestamp = (ldap_value - 116444736000000000) // 10000000
        result = datetime.utcfromtimestamp(timestamp).strftime('%d.%m.%Y')
        output_var.set(result)
    except Exception:
        output_var.set("Ошибка ввода!")


# === Копировать результат в буфер ===
def copy_to_clipboard(root, text):
    root.clipboard_clear()
    root.clipboard_append(text.replace("\u200b", ""))
    root.update()


# === Вставить из буфера и рассчитать (для кнопки) ===
def paste_and_convert(root, entry_ldap, output_var):
    try:
        entry_ldap.delete(0, tk.END)
        entry_ldap.insert(0, root.clipboard_get())
        convert_time(entry_ldap, output_var)
    except tk.TclError:
        pass


# === Создание фрейма ===
def create_expiry_frame(root, parent_frame, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG):
    frame_expiry = ttk.LabelFrame(
        parent_frame,
        text="Истечение срока действия пароля",
        padding=10,
        style="Custom.TLabelframe"
    )

    # === Поле ввода значения ===
    label_ldap = tk.Label(
        frame_expiry,
        text="Введите значение ms-Mcs-AdmPwdExpirationTime:",
        bg=FRAME_BG,
        fg=TEXT_COLOR
    )
    label_ldap.pack(anchor="w")

    entry_frame = tk.Frame(frame_expiry, bg=FRAME_BG)
    entry_frame.pack(anchor="w", pady=5)

    entry_ldap = tk.Entry(
        entry_frame,
        width=40,
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR
    )
    entry_ldap.pack(side="left", padx=5)

    output_var = tk.StringVar()

    # ===== Универсальные Ctrl+C / Ctrl+V=====

    def _copy_entry(event=None):
        try:
            root.clipboard_clear()
            root.clipboard_append(entry_ldap.get())
        except tk.TclError:
            pass
        return "break"

    def _paste_entry(event=None):
        try:
            entry_ldap.delete(0, tk.END)
            entry_ldap.insert(0, root.clipboard_get())
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

    entry_ldap.bind("<Control-KeyPress>", _on_ctrl_key)

    # ===== Enter / Ctrl+Enter =====

    def on_enter(event=None):
        val = entry_ldap.get().strip()
        if not val:
            return "break"

        entry_ldap.delete(0, tk.END)  
        convert_time_value(val, output_var)
        return "break"

    entry_ldap.bind("<Return>", on_enter)
    entry_ldap.bind("<KP_Enter>", on_enter)

    entry_ldap.bind("<Control-Return>", lambda e: convert_time(entry_ldap, output_var))
    entry_ldap.bind("<Control-KP_Enter>", lambda e: convert_time(entry_ldap, output_var))

    # === Кнопка вставки ===
    btn_paste = tk.Button(
        entry_frame,
        text="Вставить и рассчитать",
        command=lambda: paste_and_convert(root, entry_ldap, output_var),
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    )
    btn_paste.pack(side="left")

    # === Результат ===
    result_frame = tk.Frame(frame_expiry, bg=FRAME_BG)
    result_frame.pack(anchor="w", pady=5)

    label_result = tk.Label(
        result_frame,
        text="Дата истечения срока действия пароля:",
        bg=FRAME_BG,
        fg=TEXT_COLOR
    )
    label_result.pack(side="left")

    result_entry = tk.Entry(
        result_frame,
        textvariable=output_var,
        width=20,
        state="readonly",
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR,
        readonlybackground=OUTPUT_BG
    )
    result_entry.pack(side="left", padx=5)

    btn_copy = tk.Button(
        result_frame,
        text="📋",
        command=lambda: copy_to_clipboard(root, output_var.get()),
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    )
    btn_copy.pack(side="left", padx=5)

    # === Блок описания ===
    frame_desc = tk.Frame(frame_expiry, bg=FRAME_BG, padx=5, pady=5)
    frame_desc.pack(fill="x", padx=5, pady=5)

    label_desc = tk.Label(
        frame_desc,
        text=(
            "Атрибут **ms-Mcs-AdmPwdExpirationTime** используется в Windows для управления паролями локального администратора,\n"
            "особенно в связке с LAPS (Local Administrator Password Solution).\n\n"
            "Этот атрибут хранит время в формате **FILETIME**, который представляет собой количество 100-наносекундных интервалов,\n"
            "прошедших с 1 января 1601 года.\n\n"
            "**Пример значения:**\n"
            "132543276000000000  → 15.03.2025\n\n"
            "**Значение:**\n"
            "Когда срок действия пароля истекает, LAPS может автоматически заменить пароль,\n"
            "если он настроен. Иначе потребуется ручное вмешательство."
        ),
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        justify="left",
        wraplength=700
    )
    label_desc.pack()

    return frame_expiry
