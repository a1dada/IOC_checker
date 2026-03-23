import os
import tkinter as tk
from tkinter import ttk

# ============================================================
#            ПРОВЕРКА И СОЗДАНИЕ apis.txt
# ============================================================

if not os.path.exists("apis.txt"):
    import tkinter.simpledialog as simpledialog
    import tkinter.messagebox as messagebox

    root_temp = tk.Tk()
    root_temp.withdraw()

    vt_key = simpledialog.askstring("API ключ", "Введите API ключ для VirusTotal:")
    abuse_key = simpledialog.askstring("API ключ", "Введите API ключ для AbuseIPDB:")

    if not vt_key or not abuse_key:
        messagebox.showerror("Ошибка", "Оба ключа обязательны для продолжения.")
        root_temp.destroy()
        exit()

    with open("apis.txt", "w", encoding="utf-8") as f:
        f.write(f"virustotal={vt_key.strip()}\n")
        f.write(f"abuseipdb={abuse_key.strip()}\n")
        f.write("otx=\n")
        f.write("censys_token=\n")
        f.write("abusech=\n")
        f.write("urlscan=\n")

    messagebox.showinfo("Успешно", "Файл apis.txt успешно создан.")
    root_temp.destroy()

# ============================================================
#                       IMPORTS
# ============================================================

import expiration
import decoders
import msDS_SupportedEncryptionTypes
import netlogon_errors
import virustotal
import link_analyzer
import urlscan
import email_reputation
import cve_check
import taskmanager
import UserAccountControl
import com_object
import sid_decode
import sddl_decode
import ip_ids_paste
import ids_decode
import settings

# ============================================================
#                    LOAD UI COLORS
# ============================================================

colors = settings.load_ui_colors()

BG_COLOR        = colors["BG_COLOR"]
FRAME_BG        = colors["FRAME_BG"]
TEXT_COLOR      = colors["TEXT_COLOR"]
BTN_COLOR       = colors["BTN_COLOR"]
BTN_TEXT_COLOR  = colors["BTN_TEXT_COLOR"]
OUTPUT_BG       = colors["OUTPUT_BG"]

TABLE_HEADER_BG = colors["TABLE_HEADER_BG"]
TABLE_HEADER_FG = colors["TABLE_HEADER_FG"]

TREEVIEW_BG     = colors["TREEVIEW_BG"]
TREEVIEW_FG     = colors["TREEVIEW_FG"]

# ============================================================
#                           ROOT
# ============================================================

root = tk.Tk()
root.title("SOC Анализ")
root.geometry("1287x700")
root.configure(bg=BG_COLOR)

try:
    root.iconbitmap("logo.ico")
except Exception:
    pass

# ============================================================
#                          STYLES
# ============================================================

style = ttk.Style()
style.theme_use("default")

# --- Treeview (SIDEBAR) ---
style.configure(
    "Treeview",
    background=TREEVIEW_BG,
    fieldbackground=TREEVIEW_BG,
    foreground=TREEVIEW_FG,
    borderwidth=0,
    relief="flat",
    rowheight=26
)

style.map(
    "Treeview",
    background=[("selected", BTN_COLOR)],
    foreground=[("selected", "#ffffff")]
)

style.configure(
    "Treeview.Heading",
    background=TABLE_HEADER_BG,
    foreground=TABLE_HEADER_FG,
    font=("Arial", 10, "bold")
)

# --- Labelframe ---
style.configure(
    "Custom.TLabelframe",
    background=FRAME_BG,
    foreground=TEXT_COLOR,
    borderwidth=1,
    relief="solid"
)

style.configure(
    "Custom.TLabelframe.Label",
    background=FRAME_BG,
    foreground=TEXT_COLOR,
    font=("Arial", 10, "bold")
)

# ============================================================
#                          LAYOUT
# ============================================================

frame_main = tk.Frame(root, bg=BG_COLOR)
frame_main.pack(fill="both", expand=True)

# --- SIDEBAR ---
frame_left = tk.Frame(frame_main, bg=TREEVIEW_BG, width=260)
frame_left.pack_propagate(False)
frame_left.pack(side="left", fill="y")

tree = ttk.Treeview(frame_left, show="tree")
tree.pack(fill="both", expand=True, padx=6, pady=6)

# --- CONTENT ---
frame_right = tk.Frame(frame_main, bg=BG_COLOR)
frame_right.pack(side="right", fill="both", expand=True, padx=10, pady=10)

# ============================================================
#                         FRAMES
# ============================================================

frame_expiry = expiration.create_expiry_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_decoders = decoders.create_decoders_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)


frame_encryption = msDS_SupportedEncryptionTypes.create_encryption_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG, FRAME_BG
)

frame_netlogon = netlogon_errors.create_netlogon_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG, FRAME_BG
)

frame_virustotal = virustotal.create_virustotal_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_link_analyzer = link_analyzer.create_link_analyzer_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_urlscan = urlscan.create_urlscan_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_email_reputation = email_reputation.create_email_reputation_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_cve_info = cve_check.create_cve_check_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_taskmanager = taskmanager.create_task_manager_frame(
    frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_uac = UserAccountControl.create_uac_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG, FRAME_BG
)

frame_com = com_object.create_com_object_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_sid = sid_decode.create_sid_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG, FRAME_BG
)

frame_sddl = sddl_decode.create_sddl_decoder_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_ip_ids_paste = ip_ids_paste.create_ip_ids_paste_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_ids_decode = ids_decode.create_ids_decode_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

frame_settings = settings.create_settings_frame(
    root, frame_right, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG
)

ALL_FRAMES = [
    frame_virustotal,
    frame_link_analyzer,
    frame_urlscan,
    frame_email_reputation,
    frame_cve_info,
    frame_expiry,
    frame_encryption,
    frame_netlogon,
    frame_uac,
    frame_com,
    frame_sid,
    frame_sddl,
    frame_decoders,
    frame_ids_decode,
    frame_ip_ids_paste,
    frame_taskmanager,
    frame_settings,
]

# ============================================================
#                    FRAME SWITCHING
# ============================================================

def show_frame(event):
    sel = tree.selection()
    if not sel:
        return

    key = tree.item(sel, "text")

    for f in ALL_FRAMES:
        f.pack_forget()

    mapping = {
        "VirusTotal": frame_virustotal,
        "Link analyzer": frame_link_analyzer,
        "URLScan": frame_urlscan,
        "Email reputation": frame_email_reputation,
        "CVE info": frame_cve_info,
        "ms-Mcs-AdmPwdExpirationTime": frame_expiry,
        "msDS-SupportedEncryptionTypes": frame_encryption,
        "Netlogon Error Codes": frame_netlogon,
        "UAC Decode": frame_uac,
        "COM Objects": frame_com,
        "SID Decoder": frame_sid,
        "SDDL Decoder": frame_sddl,
        "Декодеры": frame_decoders,
        "Расшифровка IDS-артефактов": frame_ids_decode,
        "IP для IDS": frame_ip_ids_paste,
        "Task Manager": frame_taskmanager,
        "Настройки": frame_settings,
    }

    frame = mapping.get(key)
    if frame:
        frame.pack(fill="both", expand=True)

tree.bind("<<TreeviewSelect>>", show_frame)

# ============================================================
#                      NAV TREE
# ============================================================

ioc = tree.insert("", "end", text="Обогащение IOC", open=True)
tree.insert(ioc, "end", text="VirusTotal")
tree.insert(ioc, "end", text="Link analyzer")
tree.insert(ioc, "end", text="URLScan")
tree.insert(ioc, "end", text="Email reputation")
tree.insert(ioc, "end", text="CVE info")

attr = tree.insert("", "end", text="Атрибуты", open=True)
tree.insert(attr, "end", text="ms-Mcs-AdmPwdExpirationTime")
tree.insert(attr, "end", text="msDS-SupportedEncryptionTypes")
tree.insert(attr, "end", text="Netlogon Error Codes")
tree.insert(attr, "end", text="UAC Decode")
tree.insert(attr, "end", text="COM Objects")
tree.insert(attr, "end", text="SID Decoder")
tree.insert(attr, "end", text="SDDL Decoder")

dec = tree.insert("", "end", text="Декодеры", open=True)
tree.insert(dec, "end", text="Декодеры")
tree.insert(dec, "end", text="Расшифровка IDS-артефактов")

tasks = tree.insert("", "end", text="Tasks and calendar", open=True)
tree.insert(tasks, "end", text="Task Manager")

cfg = tree.insert("", "end", text="Настройки", open=True)
tree.insert(cfg, "end", text="Настройки")

# ============================================================
#                     INITIAL FRAME
# ============================================================

frame_virustotal.pack(fill="both", expand=True)

root.mainloop()
