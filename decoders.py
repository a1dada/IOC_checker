import base64
import tkinter as tk
from tkinter import ttk, messagebox
import xml.dom.minidom as minidom


# === Утилита очистки текста ===
def _cleanup(text: str) -> str:
    if not text:
        return ""
    cleaned = text.replace("\ufeff", "").replace("\x00", "").replace("\r", "")
    first_lt = cleaned.find("<")
    return cleaned[first_lt:] if first_lt != -1 else cleaned


# === XML -> таблица ===
def _xml_to_rows(node, path="", result=None):
    if result is None:
        result = []

    if node.nodeType == node.TEXT_NODE:
        text = node.data.strip()
        if text:
            result.append((path, text))
        return result

    if node.nodeType == node.ELEMENT_NODE:
        new_path = f"{path}/{node.tagName}" if path else node.tagName

        for k, v in node.attributes.items():
            result.append((f"{new_path}[@{k}]", v))

        for child in node.childNodes:
            _xml_to_rows(child, new_path, result)

    return result


# === XML форматирование ===
def _pretty_xml(text: str) -> str:
    cleaned = _cleanup(text)
    if not cleaned.strip():
        raise ValueError("Нет данных для парсинга")

    dom = minidom.parseString(cleaned.encode("utf-8"))
    return dom.toprettyxml(indent="  ").strip()


# === Base64 decode ===
def decode_base64_text(text: str) -> str:
    encoded_text = text.replace("\n", "").replace("\r", "").replace(" ", "")
    raw = base64.b64decode(encoded_text)
    return raw.decode("utf-8", errors="ignore")


# === UI ===
def create_decoders_frame(
    root,
    parent_frame,
    BG_COLOR,
    BTN_COLOR,
    TEXT_COLOR,
    FRAME_BG,
    OUTPUT_BG
):
    frame_decoders = ttk.LabelFrame(
        parent_frame,
        text="Декодеры",
        padding=10,
        style="Custom.TLabelframe"
    )

    # === стиль таблицы ===
    style = ttk.Style()
    style.configure(
        "Decoders.Treeview.Heading",
        background=BTN_COLOR,
        foreground=TEXT_COLOR,
        font=("Arial", 10, "bold")
    )

    # === Base64 ввод ===
    tk.Label(
        frame_decoders,
        text="Введите Base64:",
        bg=FRAME_BG,
        fg=TEXT_COLOR
    ).pack(anchor="w")

    entry_base64 = tk.Text(
        frame_decoders,
        height=12,
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR
    )
    entry_base64.pack(anchor="w", padx=5, pady=5)

    # === Результат ===
    output_base64 = tk.Text(
        frame_decoders,
        height=40,
        bg=OUTPUT_BG,
        fg=TEXT_COLOR
    )

    # === Таблица XML ===
    table_container = tk.Frame(frame_decoders, bg=FRAME_BG)

    tree_view = ttk.Treeview(
        table_container,
        columns=("path", "value"),
        show="headings",
        height=12,
        style="Decoders.Treeview"
    )

    tree_view.heading("path", text="Элемент")
    tree_view.heading("value", text="Значение")
    tree_view.column("path", width=200, stretch=False, anchor="w")
    tree_view.column("value", width=600, stretch=False, anchor="w")

    tree_view.pack(side="left", fill="both", expand=True)

    ttk.Scrollbar(
        table_container,
        orient="vertical",
        command=tree_view.yview
    ).pack(side="right", fill="y")

    tree_view.configure(yscrollcommand=lambda *a: None)

    # === ЛОГИКА ===

    def decode_and_show(text: str):
        try:
            decoded = decode_base64_text(text)
            output_base64.delete("1.0", tk.END)
            output_base64.insert("1.0", decoded)
        except Exception as e:
            output_base64.delete("1.0", tk.END)
            output_base64.insert("1.0", f"Ошибка декодирования: {e}")

    def parse_xml():
        text = output_base64.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Ошибка", "Нет данных для парсинга!")
            return

        try:
            pretty = _pretty_xml(text)
            output_base64.delete("1.0", tk.END)
            output_base64.insert("1.0", pretty)

            cleaned = _cleanup(text)
            dom = minidom.parseString(cleaned.encode("utf-8"))
            rows = _xml_to_rows(dom.documentElement)

            tree_view.delete(*tree_view.get_children())
            for path, value in rows:
                tree_view.insert("", "end", values=(path, value))

        except Exception as e:
            messagebox.showerror("Ошибка парсинга", str(e))

    # === Универсальные Ctrl+C / Ctrl+V ===

    def _copy_text(event=None):
        try:
            selected = entry_base64.get("sel.first", "sel.last")
        except tk.TclError:
            selected = entry_base64.get("1.0", tk.END).strip()

        if selected:
            root.clipboard_clear()
            root.clipboard_append(selected)
            root.update()
        return "break"

    def _paste_text(event=None):
        try:
            entry_base64.delete("1.0", tk.END)
            entry_base64.insert("1.0", root.clipboard_get())
        except tk.TclError:
            pass
        return "break"

    def _on_ctrl_key(event):
        if event.keycode == 67:  # C
            return _copy_text(event)
        if event.keycode == 86:  # V
            return _paste_text(event)

    entry_base64.bind("<Control-KeyPress>", _on_ctrl_key)

    # === Enter / Ctrl+Enter ===

    def on_enter(event=None):
        text = entry_base64.get("1.0", tk.END).strip()
        if not text:
            return "break"

        entry_base64.delete("1.0", tk.END)   # UX: видно, что декодирование пошло
        decode_and_show(text)
        return "break"

    entry_base64.bind("<Return>", on_enter)
    entry_base64.bind("<Control-Return>", lambda e: decode_and_show(
        entry_base64.get("1.0", tk.END))
    )

    # === КНОПКИ ===

    btn_frame = tk.Frame(frame_decoders, bg=FRAME_BG)
    btn_frame.pack(anchor="w", padx=5, pady=5)

    tk.Button(
        btn_frame,
        text="🔄 Декодировать",
        command=lambda: decode_and_show(entry_base64.get("1.0", tk.END)),
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="left", padx=(0, 5))

    tk.Button(
        btn_frame,
        text="🧩 Распарсить XML",
        command=parse_xml,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="left", padx=(0, 5))

    tk.Button(
        btn_frame,
        text="📋 Копировать",
        command=lambda: (
            root.clipboard_clear(),
            root.clipboard_append(output_base64.get("1.0", tk.END)),
            root.update()
        ),
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="left", padx=(5, 0))

    tk.Label(
        frame_decoders,
        text="Результат декодирования:",
        bg=FRAME_BG,
        fg=TEXT_COLOR
    ).pack(anchor="w")

    output_base64.pack(anchor="w", padx=5, pady=5)

    def toggle_table():
        if table_container.winfo_ismapped():
            table_container.pack_forget()
        else:
            table_container.pack(fill="both", expand=True, padx=5, pady=5)

    tk.Button(
        frame_decoders,
        text="📑 Показать / скрыть таблицу",
        command=toggle_table,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(anchor="w", padx=5, pady=5)

    return frame_decoders

