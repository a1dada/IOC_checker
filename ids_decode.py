import base64
import json
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import xml.dom.minidom as minidom


# -------------------- ДЕКОДИРОВАНИЕ PAYLOAD --------------------
def decode_payload_base64(b64_value: str) -> str:
    if not b64_value:
        return ""

    try:
        cleaned = b64_value.replace("\n", "").replace("\r", "").replace(" ", "")
        raw = base64.b64decode(cleaned)
        return raw.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[Ошибка декодирования payload: {e}]"


# -------------------- ЗАГРУЗКА IDS-ФАЙЛА --------------------
def load_ids_file(path: str):
    if not path or not os.path.isfile(path):
        raise FileNotFoundError("Файл не найден")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read().strip()

    if not content:
        raise ValueError("Файл пустой")

    first_non_empty = None
    for line in content.splitlines():
        line = line.strip()
        if line:
            first_non_empty = line
            break

    if first_non_empty is None:
        raise ValueError("Не удалось найти JSON-строку в файле")

    data = json.loads(first_non_empty)

    decoded_payload = decode_payload_base64(data.get("payload", ""))
    packet_value = data.get("packet", "")
    packet_str = packet_value if isinstance(packet_value, str) else str(packet_value)

    return decoded_payload, packet_str


# -------------------- ОЧИСТКА МУСОРА --------------------
def _cleanup_for_clipboard(text: str) -> str:
    if not text:
        return ""

    i = 0
    while i < len(text):
        ch = text[i]
        if ord(ch) >= 32 or ch in "\n\r\t":
            break
        i += 1

    cleaned = text[i:].replace("\x00", "")
    return cleaned.strip()


# -------------------- XML --------------------
def _extract_clean_xml(text: str) -> str:
    cleaned = _cleanup_for_clipboard(text)
    lt = cleaned.find("<")
    if lt == -1:
        raise ValueError("XML не найден")
    return cleaned[lt:]


def _pretty_xml(text: str) -> str:
    xml_clean = _extract_clean_xml(text)
    dom = minidom.parseString(xml_clean)
    return dom.toprettyxml(indent="  ").strip()


def _xml_to_rows(node, path=""):
    rows = []
    current_path = f"{path}/{node.tagName}" if path else node.tagName

    text_value = (
        node.firstChild.nodeValue.strip()
        if node.firstChild and node.firstChild.nodeType == node.TEXT_NODE
        else ""
    )

    if text_value:
        rows.append((current_path, text_value))

    for child in node.childNodes:
        if child.nodeType == child.ELEMENT_NODE:
            rows.extend(_xml_to_rows(child, current_path))

    return rows


# -------------------- UI --------------------
def create_ids_decode_frame(root, parent_frame, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG):

    frame = ttk.LabelFrame(
        parent_frame,
        text="Расшифровка IDS-артефактов",
        padding=10,
        style="Custom.TLabelframe"
    )

    # -------------------- Верх --------------------
    top_frame = tk.Frame(frame, bg=FRAME_BG)
    top_frame.pack(fill="x", pady=(0, 10))

    lbl_file = tk.Label(top_frame, text="Файл: не выбран", bg=FRAME_BG, fg=TEXT_COLOR)
    lbl_file.pack(side="left", expand=True)

    # -------------------- Таблица --------------------
    table_container = tk.Frame(frame, bg=FRAME_BG)

    columns = ("path", "value")
    tree_view = ttk.Treeview(
        table_container,
        columns=columns,
        show="headings",
        height=12
    )

    tree_view.heading("path", text="Элемент")
    tree_view.heading("value", text="Значение")

    tree_view.column("path", width=220, anchor="w", stretch=False)
    tree_view.column("value", width=600, anchor="w", stretch=True)

    tree_view.pack(side="left", fill="both", expand=True)

    y_scroll = ttk.Scrollbar(table_container, orient="vertical", command=tree_view.yview)
    y_scroll.pack(side="right", fill="y")
    tree_view.configure(yscrollcommand=y_scroll.set)

    # -------------------- Контекст --------------------
    popup_menu = tk.Menu(tree_view, tearoff=0, bg=FRAME_BG, fg=TEXT_COLOR)

    def copy_cell(idx):
        item = tree_view.focus()
        if not item:
            return
        values = tree_view.item(item, "values")
        if len(values) > idx:
            root.clipboard_clear()
            root.clipboard_append(values[idx])

    popup_menu.add_command(label="Копировать элемент", command=lambda: copy_cell(0))
    popup_menu.add_command(label="Копировать значение", command=lambda: copy_cell(1))

    def on_tree_right_click(event):
        iid = tree_view.identify_row(event.y)
        if iid:
            tree_view.selection_set(iid)
            tree_view.focus(iid)
            popup_menu.tk_popup(event.x_root, event.y_root)

    tree_view.bind("<Button-3>", on_tree_right_click)

    btn_toggle_table = None

    # -------------------- Файл --------------------
    def on_open_file():
        nonlocal btn_toggle_table
        path = filedialog.askopenfilename(
            title="Выберите файл IDS-артефакта",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return

        lbl_file.config(text=f"Файл: {os.path.basename(path)}")

        payload, packet = load_ids_file(path)

        txt_payload.delete("1.0", tk.END)
        txt_payload.insert("1.0", payload)

        txt_packet.delete("1.0", tk.END)
        txt_packet.insert("1.0", packet)

        table_container.pack_forget()
        tree_view.delete(*tree_view.get_children())

        if btn_toggle_table:
            btn_toggle_table.destroy()
            btn_toggle_table = None

    tk.Button(
        top_frame,
        text="📁 Выбрать файл",
        command=on_open_file,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="right")

    # -------------------- Payload --------------------
    tk.Label(frame, text="Декодированный Payload", bg=FRAME_BG, fg=TEXT_COLOR).pack(anchor="w")

    txt_payload = tk.Text(
        frame,
        height=30,
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR,
        wrap="word"
    )
    txt_payload.pack(fill="x", padx=5, pady=5)

    # -------------------- Packet --------------------
    tk.Label(frame, text="Декодированный Packet", bg=FRAME_BG, fg=TEXT_COLOR).pack(anchor="w")

    txt_packet = tk.Text(
        frame,
        height=10,
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR,
        wrap="word"
    )
    txt_packet.pack(fill="x", padx=5, pady=5)

    # -------------------- Кнопки --------------------
    btns_frame = tk.Frame(frame, bg=FRAME_BG)
    btns_frame.pack(anchor="w", pady=5)

    def toggle_table():
        if table_container.winfo_ismapped():
            table_container.pack_forget()
        else:
            table_container.pack(fill="both", padx=5, pady=5)

    def parse_payload():
        nonlocal btn_toggle_table

        pretty = _pretty_xml(txt_payload.get("1.0", tk.END))
        txt_payload.delete("1.0", tk.END)
        txt_payload.insert("1.0", pretty)

        dom = minidom.parseString(_extract_clean_xml(pretty))
        rows = _xml_to_rows(dom.documentElement)

        tree_view.delete(*tree_view.get_children())
        for p, v in rows:
            tree_view.insert("", "end", values=(p, v))

        if not btn_toggle_table:
            btn_toggle_table = tk.Button(
                btns_frame,
                text="📑 Показать / скрыть таблицу",
                bg=BTN_COLOR,
                fg=TEXT_COLOR,
                command=toggle_table
            )
            btn_toggle_table.pack(side="left", padx=10)

    tk.Button(btns_frame, text="🧩 Парсить payload", command=parse_payload,
              bg=BTN_COLOR, fg=TEXT_COLOR).pack(side="left")

    tk.Button(btns_frame, text="🧹 Очистить",
              command=lambda: (txt_payload.delete("1.0", tk.END),
                               txt_packet.delete("1.0", tk.END)),
              bg=BTN_COLOR, fg=TEXT_COLOR).pack(side="left", padx=10)

    return frame
