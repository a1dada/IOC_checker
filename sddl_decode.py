import tkinter as tk
from tkinter import scrolledtext
import re
import pyperclip

from sddl_parser import parse_sddl, parse_event_block, explain_sid, explain_operation_type, explain_field_name

def create_sddl_decoder_frame(root, parent, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG):
    frame = tk.Frame(parent, bg=FRAME_BG)

    label_input = tk.Label(frame, text="Вставьте блок события или SDDL:", bg=FRAME_BG, fg=TEXT_COLOR)
    label_input.pack(anchor="w", padx=10, pady=(10, 0))

    input_text = scrolledtext.ScrolledText(frame, height=10, bg=OUTPUT_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, wrap="word")
    input_text.pack(fill="both", padx=10, pady=(0, 5), expand=True)

    btn_frame = tk.Frame(frame, bg=FRAME_BG)
    btn_frame.pack(fill="x", padx=10)

    def decode():
        raw = input_text.get("1.0", tk.END).strip()
        event_data = parse_event_block(raw)
        sddl = event_data.get("AttributeValue", raw)
        sddl_result = parse_sddl(sddl)

        explanation = ""

        if event_data:
            explanation += f"🔷 ObjectDN: {event_data.get('ObjectDN', '-')}"
            explanation += f"🔷 ObjectClass: {event_data.get('ObjectClass', '-')}"
            explanation += f"🔷 ObjectGUID: {event_data.get('ObjectGUID', '-')}"
            explanation += f"🔷 DSName: {event_data.get('DSName', '-')}"
            explanation += f"🔷 OperationType: {event_data.get('OperationType', '-')} ({explain_operation_type(event_data.get('OperationType'))})\n"
            explanation += f"🔷 SubjectUserName: {event_data.get('SubjectUserName', '-')}\n"
            explanation += f"🔷 SubjectUserSid: {event_data.get('SubjectUserSid', '-')} ({explain_sid(event_data.get('SubjectUserSid'))})\n"
            explanation += f"🔷 SubjectLogonId: {event_data.get('SubjectLogonId', '-')} (Идентификатор сессии входа пользователя)\n"
            explanation += f"\n"

        explanation += sddl_result
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, explanation)

    def paste_and_decode():
        input_text.delete("1.0", tk.END)
        input_text.insert(tk.END, pyperclip.paste())
        decode()

    tk.Button(btn_frame, text="Вставить и декодировать", bg=BTN_COLOR, fg=TEXT_COLOR, command=paste_and_decode).pack(side="left")
    tk.Button(btn_frame, text="Очистить", bg=BTN_COLOR, fg=TEXT_COLOR, command=lambda: input_text.delete("1.0", tk.END)).pack(side="left", padx=(10, 0))

    label_output = tk.Label(frame, text="Результат:", bg=FRAME_BG, fg=TEXT_COLOR)
    label_output.pack(anchor="w", padx=10, pady=(10, 0))

    output_text = scrolledtext.ScrolledText(frame, height=30, bg=OUTPUT_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, wrap="word")
    output_text.pack(fill="both", padx=10, pady=(0, 10), expand=True)

    return frame
