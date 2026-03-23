
import tkinter as tk
import requests
import webbrowser
from tkinter import ttk
import re
from urllib.parse import urlparse

ABUSE_API_KEY = "56abcb9a3fd0bcaf58bbf4ec1c32f8274ab50aa9d08f20e0c411308fb15a50e5916adb8a0367de5c"
OTX_API_KEY = "830adbecbade7a5a4c8ab616dcf787ef867eb6f869abb2a7340c2e7fd3b3ee9c"

HEADERS_OTX = {"X-OTX-API-KEY": OTX_API_KEY}

def extract_domain(ioc):
    if ioc.startswith("http"):
        return urlparse(ioc).hostname or ioc
    return ioc

def detect_type(ioc):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "IPv4"
    elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        return "file"
    elif "." in ioc:
        return "domain"
    return "unknown"

def create_ioc_checker_frame(root, parent_frame, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG):
    frame = tk.Frame(parent_frame, bg=FRAME_BG)

    entry_frame = tk.Frame(frame, bg=FRAME_BG)
    entry_frame.pack(fill="x", padx=10, pady=5)

    entry = tk.Entry(entry_frame, width=50, bg=FRAME_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
    entry.pack(side="left", padx=(0, 10))

    tk.Button(entry_frame, text="📋 Вставить и проверить", command=lambda: paste_and_check(), bg=BTN_COLOR, fg=TEXT_COLOR).pack(side="left")

    ioc_label = tk.Label(frame, text="", font=("Arial", 14, "bold"), fg="orange", bg=FRAME_BG)
    ioc_label.pack(anchor="w", padx=10)

    container = tk.Frame(frame, bg=FRAME_BG)
    container.pack(fill="both", expand=True, padx=10, pady=10)

    blocks = []

    def add_block(title, open_url_func):
        block = tk.LabelFrame(container, text=title, bg=FRAME_BG, fg=TEXT_COLOR, font=("Arial", 10, "bold"))
        block.pack(fill="x", pady=5)
        btn_open = tk.Button(block, text=f"🌐 Открыть в {title}", command=open_url_func, bg=BTN_COLOR, fg=TEXT_COLOR)
        btn_open.pack(anchor="ne", padx=5, pady=5)
        content = tk.Text(block, height=10, wrap="word", bg=OUTPUT_BG, fg=TEXT_COLOR, bd=0)
        content.pack(fill="x", padx=5, pady=(0, 5))
        blocks.append((title, content))
        return block

    abuse_block = add_block("AbuseDB", lambda: webbrowser.open(f"https://abuseipdb.com/check/{entry.get().strip()}"))
    abuse_progress = ttk.Progressbar(abuse_block, orient="horizontal", length=200, mode="determinate")
    abuse_progress.pack(pady=5)

    otx_block = add_block("OTX", lambda: webbrowser.open(f"https://otx.alienvault.com/indicator/{detect_type(extract_domain(entry.get().strip()))}/{extract_domain(entry.get().strip())}"))
    urlhaus_block = add_block("URLhaus", lambda: webbrowser.open("https://urlhaus.abuse.ch/"))

    style = ttk.Style()
    style.theme_use("default")
    style.configure("green.Horizontal.TProgressbar", troughcolor=FRAME_BG, background="#00cc44")
    style.configure("yellow.Horizontal.TProgressbar", troughcolor=FRAME_BG, background="#cccc00")
    style.configure("red.Horizontal.TProgressbar", troughcolor=FRAME_BG, background="#cc3333")

    def fetch_abuse(ioc):
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}&maxAgeInDays=90"
        headers = { "Key": ABUSE_API_KEY, "Accept": "application/json" }
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()["data"]
                score = data.get("abuseConfidenceScore", 0)
                text = (
                    f"{ioc} — reported {data.get('totalReports')} times\n"
                    f"Abuse Confidence Score: {score}%\n\n"
                    f"ISP: {data.get('isp')}\nASN: {data.get('asn')}\n"
                    f"Domain: {data.get('domain')}\nCountry: {data.get('countryCode')}\n"
                )
                blocks[0][1].delete("1.0", tk.END)
                blocks[0][1].insert("1.0", text)
                abuse_progress["value"] = score
                if score < 21:
                    abuse_progress.configure(style="green.Horizontal.TProgressbar")
                elif score < 71:
                    abuse_progress.configure(style="yellow.Horizontal.TProgressbar")
                else:
                    abuse_progress.configure(style="red.Horizontal.TProgressbar")
            else:
                blocks[0][1].insert("1.0", f"Ошибка {response.status_code}")
        except Exception as e:
            blocks[0][1].insert("1.0", f"Ошибка: {e}")

    def fetch_otx(ioc):
        blocks[1][1].delete("1.0", tk.END)
        ioc_clean = extract_domain(ioc)
        ioc_type = detect_type(ioc_clean)
        url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc_clean}/general"
        try:
            response = requests.get(url, headers=HEADERS_OTX)
            if response.status_code == 200:
                data = response.json()
                verdict = data.get("validation", {}).get("status", "—")
                base = data.get("base_indicator", {})
                geo = data.get("geo", {})
                summary = data.get("pulse_info", {})
                tags = summary.get("tags", [])
                cert = data.get("certificate", {})
                text = (
                    f"Analysis Overview\n\n"
                    f"Verdict: {verdict}\n"
                    f"Type: {base.get('type', '-')}\n"
                    f"IP: {data.get('ip', '-')}\n"
                    f"Location: {geo.get('country_name', '-')}\n"
                    f"ASN: {data.get('asn', '-')}\n"
                    f"Tags: {', '.join(tags)}\n"
                    f"Certificate: {cert.get('subject', '-') if isinstance(cert, dict) else '-'}\n"
                )
                blocks[1][1].insert("1.0", text)
            else:
                blocks[1][1].insert("1.0", f"Ошибка {response.status_code}")
        except Exception as e:
            blocks[1][1].insert("1.0", f"Ошибка: {e}")

    def fetch_urlhaus(ioc):
        blocks[2][1].delete("1.0", tk.END)
        blocks[2][1].insert("1.0", "Пока не реализовано.")

    def check_ioc():
        ioc = entry.get().strip()
        if not ioc: return
        ioc_label.config(text=ioc)
        for _, widget in blocks:
            widget.delete("1.0", tk.END)
        if detect_type(ioc) == "IPv4":
            fetch_abuse(ioc)
        else:
            blocks[0][1].insert("1.0", "AbuseIPDB: только для IP.")
        fetch_otx(ioc)
        fetch_urlhaus(ioc)

    def paste_and_check():
        try:
            entry.delete(0, tk.END)
            entry.insert(0, root.clipboard_get())
        except tk.TclError:
            return
        check_ioc()

    return frame
