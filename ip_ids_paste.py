import tkinter as tk
import requests
import webbrowser
import win32clipboard

VT_API_KEY = "e8bb04ba24b2f8e486f9c449a352b40663efacf63d556b97277ad750fe36ef82"
ABUSE_API_KEY = "56abcb9a3fd0bcaf58bbf4ec1c32f8274ab50aa9d08f20e0c411308fb15a50e5916adb8a0367de5c"

HEADERS_VT = {"x-apikey": VT_API_KEY}
HEADERS_ABUSE = {"Key": ABUSE_API_KEY, "Accept": "application/json"}


def create_ip_ids_paste_frame(
    root,
    parent_frame,
    BG_COLOR,
    BTN_COLOR,
    TEXT_COLOR,
    FRAME_BG,
    OUTPUT_BG
):
    frame = tk.Frame(parent_frame, bg=FRAME_BG)

    entry_frame = tk.Frame(frame, bg=FRAME_BG)
    entry_frame.pack(fill="x", padx=10, pady=5)

    entry = tk.Entry(
        entry_frame,
        width=50,
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR
    )
    entry.pack(side="left", padx=(0, 10))

    output_text = tk.Text(
        frame,
        height=10,
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        wrap="word"
    )
    output_text.pack(fill="both", expand=True, padx=10, pady=10)

    html_report = ""
    current_ip = ""

    # ===== ОСНОВНАЯ ЛОГИКА =====

    def check_ip(val=None):
        nonlocal html_report, current_ip

        if val is None:
            val = entry.get().strip()

        if not val:
            return

        output_text.delete("1.0", tk.END)
        html_report = ""

        try:
            ip = val.replace("https://", "").replace("http://", "").split("/")[0]
            current_ip = ip

            # --- VirusTotal ---
            vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            vt_res = requests.get(vt_url, headers=HEADERS_VT, timeout=20)
            vt_data = vt_res.json()

            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            # --- AbuseIPDB ---
            abuse_url = (
                f"https://api.abuseipdb.com/api/v2/check?"
                f"ipAddress={ip}&maxAgeInDays=90"
            )
            abuse_res = requests.get(abuse_url, headers=HEADERS_ABUSE, timeout=20)
            abuse_json = abuse_res.json()

            abuse_data = abuse_json.get("data", {})
            domain = abuse_data.get("domain", "-")

            country = abuse_data.get("countryName") or abuse_data.get("countryCode") or "-"
            abuse_score = abuse_data.get("abuseConfidenceScore", 0)

            ip_obfuscated = ip.replace(".", "[.]", 1)
            domain_obfuscated = domain.replace(".", "[.]") if domain and domain != "-" else "-"

            vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
            abuse_link = f"https://www.abuseipdb.com/check/{ip}"

            abuse_text = (
                "не находится в базах компрометации"
                if abuse_score == 0
                else "находится в базах компрометации"
            )

            html_report = (
                f"IP-адрес <b>{ip_obfuscated}</b> "
                f"(<a href='{vt_link}'>ссылка</a> на VirusTotal ({malicious}/{total})) "
                f"принадлежит домену <b>{domain_obfuscated}</b> "
                f"(<b>{country}</b>) и {abuse_text}. "
                f"<a href='{abuse_link}'>Ссылка</a> на AbuseIPDB."
            )

            output_text.insert("1.0", html_report)

        except Exception as e:
            current_ip = ""
            html_report = ""
            output_text.insert("1.0", f"Ошибка: {e}")

    # ===== Clipboard / Browser =====

    def paste_and_check():
        try:
            entry.delete(0, tk.END)
            entry.insert(0, root.clipboard_get())
            check_ip()
        except tk.TclError:
            pass

    def copy_html_real():
        if not html_report:
            return

        try:
            content = html_report
            prefix = "<html><body><!--StartFragment-->"
            suffix = "<!--EndFragment--></body></html>"

            full_html = prefix + content + suffix

            start_html = len(
                "Version:0.9\r\n"
                "StartHTML:00000000\r\n"
                "EndHTML:00000000\r\n"
                "StartFragment:00000000\r\n"
                "EndFragment:00000000\r\n"
            )

            start_fragment = start_html + len(prefix)
            end_fragment = start_fragment + len(content)
            end_html = end_fragment + len(suffix)

            header = (
                "Version:0.9\r\n"
                f"StartHTML:{start_html:08d}\r\n"
                f"EndHTML:{end_html:08d}\r\n"
                f"StartFragment:{start_fragment:08d}\r\n"
                f"EndFragment:{end_fragment:08d}\r\n"
            )

            full_data = header + full_html

            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            cf_html = win32clipboard.RegisterClipboardFormat("HTML Format")
            win32clipboard.SetClipboardData(cf_html, full_data.encode("utf-8"))
            win32clipboard.CloseClipboard()

        except Exception as e:
            print(f"Ошибка копирования HTML: {e}")

    def open_virustotal():
        if current_ip:
            webbrowser.open(f"https://www.virustotal.com/gui/ip-address/{current_ip}")

    def open_abuseipdb():
        if current_ip:
            webbrowser.open(f"https://www.abuseipdb.com/check/{current_ip}")

    # ===== Универсальные Ctrl+C / Ctrl+V =====

    def _copy_entry(event=None):
        try:
            root.clipboard_clear()
            root.clipboard_append(entry.get())
            root.update()
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

        entry.delete(0, tk.END)   # UX-сигнал: проверка началась
        check_ip(val)
        return "break"

    entry.bind("<Return>", on_enter)
    entry.bind("<KP_Enter>", on_enter)

    entry.bind("<Control-Return>", lambda e: check_ip())
    entry.bind("<Control-KP_Enter>", lambda e: check_ip())

    # ===== КНОПКИ =====

    tk.Button(
        entry_frame,
        text="📋 Вставить и проверить",
        command=paste_and_check,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="left")

    tk.Button(
        entry_frame,
        text="📋 Копировать в HTML",
        command=copy_html_real,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="left", padx=(5, 0))

    tk.Button(
        entry_frame,
        text="🌐 VirusTotal",
        command=open_virustotal,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="left", padx=(15, 0))

    tk.Button(
        entry_frame,
        text="🌐 AbuseIPDB",
        command=open_abuseipdb,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="left", padx=(5, 0))

    return frame
