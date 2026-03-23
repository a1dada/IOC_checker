import os
import time
import base64
import ipaddress
import webbrowser
import malware
import ip_info
import otx_check
import re
from urllib.parse import urlparse, quote
import threading
import queue

import requests
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk, ImageDraw, ImageFont

APIS_FILE = "apis.txt"


def load_api_keys():
    """
    Читает ключи из apis.txt:
      virustotal=...
      abuseipdb=...
      otx=...
      censys_token=...
    """
    keys = {
        "virustotal": "",
        "abuseipdb": "",
        "otx": "",
        "censys_token": "",
    }

    if not os.path.exists(APIS_FILE):
        return keys

    with open(APIS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            lk = k.strip().lower()
            if lk in keys:
                keys[lk] = v.strip()

    return keys


def create_virustotal_frame(root, parent_frame, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG):
    frame = tk.Frame(parent_frame, bg=FRAME_BG)  

    # === API ключи ===
    api_keys = load_api_keys()
    vt_api_key = api_keys["virustotal"]
    abuse_api_key = api_keys["abuseipdb"]
    censys_token = api_keys["censys_token"]

    HEADERS_VT = {"x-apikey": vt_api_key} if vt_api_key else {}
    HEADERS_CENSYS = {"Authorization": f"Bearer {censys_token}"} if censys_token else {}

    # ================= ВВОД IOC =================
    top_input = tk.Frame(frame, bg=FRAME_BG)
    top_input.pack(anchor="nw", fill="x", padx=5, pady=(5, 2))

    entry = tk.Entry(top_input, width=60, bg=FRAME_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
    entry.pack(side="left", fill="x", expand=True)


    # ===== Универсальные Ctrl+C / Ctrl+V (работают при любой раскладке) =====

    def _copy_entry(event=None):
        try:
            root.clipboard_clear()
            root.clipboard_append(entry.get())
        except tk.TclError:
            pass
        return "break"

    def _paste_entry(event=None):
        entry.delete(0, tk.END)
        entry.insert(0, root.clipboard_get())
        return "break"

    def _on_ctrl_key(event):
        # Ctrl+C
        if event.keycode == 67:
            return _copy_entry(event)
        # Ctrl+V
        if event.keycode == 86:
            return _paste_entry(event)

    entry.bind("<Control-KeyPress>", _on_ctrl_key)


    entry.bind("<Control-Return>", lambda e: check_ioc())
    entry.bind("<Control-KP_Enter>", lambda e: check_ioc())


    def paste_and_check():
        try:
            entry.delete(0, tk.END)
            entry.insert(0, root.clipboard_get())
        except tk.TclError:
            pass
        check_ioc()

    def on_enter(event=None):
        val = entry.get().strip()
        if not val:
            return "break"

        entry.delete(0, tk.END)   # сразу очищаем — UX-сигнал
        check_ioc(val)            # передаём значение явно
        return "break"



    # Enter (обычный)
    entry.bind("<Return>", on_enter)

    # Enter на NumPad
    entry.bind("<KP_Enter>", on_enter)  

    tk.Button(
        top_input,
        text="📋 Вставить и проверить",
        command=paste_and_check,
        bg=BTN_COLOR,
        fg=TEXT_COLOR
    ).pack(side="right", padx=5)

    # =============== SUMMARY-БАННЕР ===============
    summary_frame = tk.Frame(frame, bg=FRAME_BG)
    summary_frame.pack(fill="x", padx=5, pady=(2, 5))

    summary_label = tk.Label(
        summary_frame,
        text="",  # пусто при старте
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        anchor="w",
        justify="left",
        font=("Arial", 10, "bold")
    )
    summary_label.pack(fill="x", padx=8, pady=4)

    summary_text_holder = {"text": ""}
    current_ioc_holder = {"val": ""}
    result_queue = queue.Queue()
    last_vt_attrs = {}
    last_vt_stats = {}
    summary_state = {
        "malware_done": False,
        "otx_done": False,
        "rendered": False,
        "malware_rendered": False
    }

    # ===== STATUS / PROGRESS =====
    status_frame = tk.Frame(frame, bg=FRAME_BG)
    status_frame.pack(fill="x", padx=5, pady=(0, 5))

    status_label = tk.Label(
        status_frame,
        text="",
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        anchor="w",
        font=("Arial", 9, "italic")
    )
    status_label.pack(side="left", padx=(8, 10))

    progress = ttk.Progressbar(
        status_frame,
        mode="indeterminate",
        length=60
    )
    progress.pack(side="left")
    progress.pack_forget()  # по умолчанию скрыта


    # =============== ОСНОВНОЙ КОНТЕНТ ===============
    content_frame = tk.Frame(frame, bg=FRAME_BG)
    content_frame.pack(fill="both", expand=True, padx=5, pady=5)

    # ---- Слева: вкладки ----
    notebook = ttk.Notebook(content_frame)
    notebook.pack(side="left", fill="both", expand=True, padx=(0, 5))

    tab_info = tk.Frame(notebook, bg=OUTPUT_BG)
    tab_av = tk.Frame(notebook, bg=OUTPUT_BG)
    tab_ipinfo = tk.Frame(notebook, bg=OUTPUT_BG)
    tab_malware = tk.Frame(notebook, bg=OUTPUT_BG)
    tab_otx = tk.Frame(notebook, bg=OUTPUT_BG)


    notebook.add(tab_info, text="Информация")
    notebook.add(tab_av, text="Антивирусные движки")
    notebook.add(tab_ipinfo, text="IP-Info")
    notebook.add(tab_malware, text="Malware Feeds")
    notebook.add(tab_otx, text="OTX Check")


    malware_ui = malware.create_malware_tab(
        parent=tab_malware,
        BG_COLOR=BG_COLOR,
        FRAME_BG=FRAME_BG,
        TEXT_COLOR=TEXT_COLOR,
        OUTPUT_BG=OUTPUT_BG
    )

    otx_ui = otx_check.create_otx_tab(
        parent=tab_otx,
        FRAME_BG=FRAME_BG,
        OUTPUT_BG=OUTPUT_BG,
        TEXT_COLOR=TEXT_COLOR
    )


    ip_info_ui = ip_info.create_ip_info_tab(
        parent=tab_ipinfo,
        FRAME_BG=FRAME_BG,
        OUTPUT_BG=OUTPUT_BG,
        TEXT_COLOR=TEXT_COLOR,
        abuse_api_key=abuse_api_key,
        censys_token=censys_token,
        HEADERS_CENSYS=HEADERS_CENSYS,
    )
    ip_info_ui.on_abuse_ready = lambda: root.after(
        0, lambda: render_abuseipdb_summary(hash_summary_text, ip_info_ui)
    )


    # --- Информация ---
    info_text = tk.Text(tab_info, wrap="word", bg=OUTPUT_BG, fg=TEXT_COLOR)
    info_text.configure(font=("Consolas", 9))
    info_text.pack(fill="both", expand=True, padx=5, pady=5)

    # --- Антивирусные движки ---
    av_text = tk.Text(tab_av, wrap="none", bg=OUTPUT_BG, fg=TEXT_COLOR)
    av_text.configure(font=("Consolas", 9))
    av_text.pack(fill="both", expand=True, padx=5, pady=5)



    # ---- Справа: гейдж + кнопки ----
    right_panel = tk.Frame(content_frame, bg=FRAME_BG)
    right_panel.pack(side="right", fill="y", anchor="n")


    # ======= VT ANIMATED GAUGE (СВЕРХУ) =======
    gauge_label = tk.Label(right_panel, bg=FRAME_BG)
    gauge_label.pack(anchor="n", pady=(6, 10))


    # ======= КНОПКИ (ПОД ГЕЙДЖЕМ) =======
    buttons_frame = tk.Frame(right_panel, bg=FRAME_BG)
    buttons_frame.pack(anchor="n", pady=(0, 10))




    # ======= HASH QUICK SUMMARY CONTAINER =======
    hash_summary_frame = tk.Frame(right_panel, bg=FRAME_BG)
    hash_summary_frame.pack(anchor="n", fill="x", padx=6, pady=(4, 0))


    # ========= Вспомогательные функции =========

    def is_ip(val: str) -> bool:
        try:
            ipaddress.ip_address(val)
            return True
        except ValueError:
            return False

    def encode_url_for_vt(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def build_vt_url(val: str):
        if len(val) in (32, 40, 64):
            return f"https://www.virustotal.com/api/v3/files/{val}", "file"
        elif is_ip(val):
            return f"https://www.virustotal.com/api/v3/ip_addresses/{val}", "ip"
        elif "." in val and not val.lower().startswith("http"):
            return f"https://www.virustotal.com/api/v3/domains/{val}", "domain"
        else:
            encoded = encode_url_for_vt(val)
            return f"https://www.virustotal.com/api/v3/urls/{encoded}", "url"

    def determine_gui_url(val: str) -> str:
        if len(val) in (32, 40, 64):
            return f"https://www.virustotal.com/gui/file/{val}"
        elif is_ip(val):
            return f"https://www.virustotal.com/gui/ip-address/{val}"
        elif "." in val and not val.lower().startswith("http"):
            return f"https://www.virustotal.com/gui/domain/{val}"
        else:
            encoded = encode_url_for_vt(val)
            return f"https://www.virustotal.com/gui/url/{encoded}"


    def determine_otx_gui_url(val: str) -> str:
        if not val:
            return ""

        # file hash
        if len(val) in (32, 40, 64):
            return f"https://otx.alienvault.com/indicator/file/{val}"

        # IP
        try:
            ipaddress.ip_address(val)
            return f"https://otx.alienvault.com/indicator/ip/{val}"
        except ValueError:
            pass

        # domain
        if "." in val and not val.lower().startswith("http"):
            return f"https://otx.alienvault.com/indicator/domain/{val}"

        # URL
        encoded = quote(val, safe="")
        return f"https://otx.alienvault.com/indicator/url/{encoded}"
   



    # ======= Копирование / браузер =======

    def copy_full_report():
        text_parts = []
        text_parts.append("[Информация]\n" + info_text.get("1.0", tk.END).strip())
        text_parts.append("\n\n[Антивирусные движки]\n" + av_text.get("1.0", tk.END).strip())
        text_parts.append("\n\n[IP-Info]\n(см. вкладку IP-Info)")
        full = "\n".join(text_parts).strip()
        if not full:
            full = "Отчёт пуст. Сначала выполните запрос к сервисам."
        root.clipboard_clear()
        root.clipboard_append(full)
        root.update()

    def copy_summary():
        summary = summary_text_holder["text"].strip()
        if not summary:
            summary = "Краткое резюме отсутствует. Сначала выполните запрос."
        root.clipboard_clear()
        root.clipboard_append(summary)
        root.update()

    def open_in_browser():
        val = current_ioc_holder.get("val", "")
        if not val:
            return
        webbrowser.open(determine_gui_url(val))

    def open_in_otx():
        val = current_ioc_holder.get("val", "")
        if not val:
            return

        url = determine_otx_gui_url(val)
        if url:
            webbrowser.open(url)


    # ======= Кнопки справа (только Open) =======

    tk.Button(
        buttons_frame,
        text="🌐 Открыть в VT",
        command=open_in_browser,
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        width=18
    ).grid(row=0, column=0, padx=2, pady=2, sticky="w")

    tk.Button(
        buttons_frame,
        text="🌐 Открыть в OTX",
        command=open_in_otx,
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        width=18
    ).grid(row=0, column=1, padx=2, pady=2, sticky="e")

    # ======= HASH QUICK SUMMARY (под кнопками) =======

    hash_summary_text = tk.Text(
        hash_summary_frame,
        wrap="word",
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        font=("Consolas", 9),
        relief="flat",
        bd=0,
        highlightthickness=0,
        padx=4,
        pady=2,
    )
    hash_summary_text.pack(fill="both", expand=True)


    # ======= HASH SUMMARY TAGS =======
    hash_summary_text.tag_config("h", font=("Consolas", 9, "bold"))
    hash_summary_text.tag_config("ok", foreground="#22c55e")
    hash_summary_text.tag_config("bad", foreground="#ef4444")
    hash_summary_text.tag_config("muted", foreground="#9ca3af")
    hash_summary_text.tag_config("warn", foreground="#eab308")

    hash_summary_text.tag_config(
        "tag",
        background="#e8eaed",
        foreground="#1f2937",
        font=("Consolas", 8, "bold")
    )


    # ========= AbuseDB / OTX / Censys вспомогательные =========
    def is_hash(val: str) -> bool:
        return len(val) in (32, 40, 64)


    def extract_otx_tags(pulses: list, limit: int = 10):
        seen = set()
        tags = []
        has_more = False

        for p in pulses:
            for t in (p.get("tags") or []):
                if t not in seen:
                    seen.add(t)
                    if len(tags) < limit:
                        tags.append(t)
                    else:
                        has_more = True
                        return tags, has_more

        return tags, has_more


    def render_abuseipdb_summary(text_widget, ip_info_ui):
        score = getattr(ip_info_ui, "last_abuse_score", None)
        found = getattr(ip_info_ui, "last_abuse_found", None)

        if score is None or found is None:
            return

        status_tag = "bad" if score >= 70 else "muted" if score >= 30 else "ok"
        status_text = "Was found in our database" if found else "Not found in our database"

        # заголовок — как VT / OTX
        text_widget.insert("end", "\n🧨 AbuseIPDB\n", "h")

        # статус — цветной
        text_widget.insert(
            "end",
            f"  {status_text}\n",
            status_tag
        )

        # score — нейтральный
        text_widget.insert(
            "end",
            f"  Confidence score: {score}%\n",
            "muted"
        )
 
    
    def draw_fill_gauge(value: int, total: int, size: int = 130):
        total = max(total, 1)
        angle = 360 * (value / total)

        img = Image.new("RGBA", (size, size), FRAME_BG)
        draw = ImageDraw.Draw(img)

        fill_color = "#cc3333" if value > 0 else "#00cc44"
        draw.pieslice([0, 0, size, size], start=90, end=90 + angle, fill=fill_color)
        draw.ellipse([10, 10, size - 10, size - 10], fill=FRAME_BG)

        percent_text = f"{value}/{total}"
        try:
            font = ImageFont.truetype("arial.ttf", 18)
        except Exception:
            font = ImageFont.load_default()

        bbox = draw.textbbox((0, 0), percent_text, font=font)
        w = bbox[2] - bbox[0]
        h = bbox[3] - bbox[1]

        draw.text(
            ((size - w) / 2, (size - h) / 2),
            percent_text,
            fill=fill_color,
            font=font
        )

        return ImageTk.PhotoImage(img)


    def animate_gauge(label, target_value, total, steps=25, delay=15):
        total = max(total, 1)
        target_value = max(0, min(target_value, total))
        current_step = 0

        def _step():
            nonlocal current_step
            current_step += 1

            value = int(target_value * current_step / steps)
            img = draw_fill_gauge(value, total)

            label.image = img
            label.configure(image=img)

            if current_step < steps:
                label._anim_after = label.after(delay, _step)

        _step()


    # ========= Основной чек: VT + AbuseDB + OTX + Censys =========


    def reset_ui_for_new_check():

        # --- гейдж ---
        if hasattr(gauge_label, "_anim_after"):
            gauge_label.after_cancel(gauge_label._anim_after)
            del gauge_label._anim_after

        gauge_label.config(image="")
        gauge_label.image = None



        
        # --- основной вывод ---
        info_text.delete("1.0", tk.END)
        av_text.delete("1.0", tk.END)
        hash_summary_text.delete("1.0", tk.END)

        # --- вкладки источников ---
        try:
            malware_ui.text.delete("1.0", tk.END)
        except Exception:
            pass

        try:
            otx_ui.text.delete("1.0", tk.END)
        except Exception:
            pass

        try:
            ip_info_ui.text.delete("1.0", tk.END)
        except Exception:
            pass



        # --- summary ---
        summary_label.config(
            text="⏳ Выполняется проверка…",
            bg=FRAME_BG,
            fg=TEXT_COLOR
        )

        # --- статус ---
        progress.pack(side="left")
        progress.start(10)
        status_label.config(text="Запрос к VirusTotal…")
        summary_state["malware_done"] = False
        summary_state["otx_done"] = False
        summary_state["rendered"] = False
        summary_state["malware_rendered"] = False



    def check_ioc(val=None):
        if not val:
            val = entry.get().strip()
        if not val:
            return

        current_ioc_holder["val"] = val
        reset_ui_for_new_check()

        threading.Thread(
            target=check_ioc_worker,
            args=(val,),
            daemon=True
        ).start()

        root.after(100, poll_result_queue)


    def check_ioc_worker(val):
        result = {
            "val": val,
            "vt_attrs": None,
            "obj_type": None,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": 0,
            "error": None
        }

        try:
            if not vt_api_key:
                raise RuntimeError("API-ключ VirusTotal не задан")

            url, obj_type = build_vt_url(val)
            res = requests.get(url, headers=HEADERS_VT, timeout=25)

            if res.status_code != 200:
                raise RuntimeError(f"VT HTTP {res.status_code}")

            data = res.json()
            attrs = data.get("data", {}).get("attributes", {}) or {}

            stats = attrs.get("last_analysis_stats", {}) or {}

            result.update({
                "vt_attrs": attrs,
                "obj_type": obj_type,

                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()) if stats else 0,

                # === ДОБАВЛЕНО ===
                "last_analysis_ts": attrs.get("last_analysis_date"),
                "meaningful_name": attrs.get("meaningful_name"),
            })

        except Exception as e:
            result["error"] = str(e)

        # === передаём результат в UI-поток ===
        result_queue.put(result)

        # === параллельные источники ===
        threading.Thread(
            target=malware_ui.fetch_all,
            args=(val,),
            daemon=True
        ).start()

        threading.Thread(
            target=ip_info_ui.fetch_all,
            args=(val,),
            daemon=True
        ).start()

        threading.Thread(
            target=otx_ui.fetch,
            args=(val,),
            daemon=True
        ).start()


    def poll_external_sources_and_refresh():
        val = current_ioc_holder.get("val", "")

        # ===== Malware =====
        if is_ip(val):
            summary_state["malware_done"] = True
        else:
            if getattr(malware_ui, "last_found", None) is not None:
                summary_state["malware_done"] = True

        # ===== OTX =====
        if getattr(otx_ui, "last_pulses", None) is not None:
            summary_state["otx_done"] = True

        # ===== ПЕРВИЧНЫЙ РЕНДЕР =====
        if not summary_state["rendered"]:
            if is_ip(val):
                # для IP ждём ТОЛЬКО OTX
                if summary_state["otx_done"]:
                    refresh_hash_quick_summary()
                    summary_state["rendered"] = True
            else:
                # для hash/domain/url — достаточно VT+OTX
                if summary_state["otx_done"]:
                    refresh_hash_quick_summary()
                    summary_state["rendered"] = True

        # ===== ДОПОЛНИТЕЛЬНЫЙ РЕНДЕР ДЛЯ MALWARE =====
        if (
            summary_state["rendered"]
            and not is_ip(val)
            and summary_state["malware_done"]
            and not summary_state["malware_rendered"]
        ):
            refresh_hash_quick_summary()
            summary_state["malware_rendered"] = True

        # ===== продолжаем polling, пока всё не готово =====
        if not (summary_state["malware_done"] and summary_state["otx_done"]):
            root.after(300, poll_external_sources_and_refresh)


    def refresh_hash_quick_summary():
        # ❗ чистим ТОЛЬКО верхнюю часть (до AbuseIPDB)
        if hash_summary_text.search("🧨 AbuseIPDB", "1.0", tk.END):
            pos = hash_summary_text.search("🧨 AbuseIPDB", "1.0", tk.END)
            hash_summary_text.delete("1.0", pos)
        else:
            hash_summary_text.delete("1.0", tk.END)

        malicious = last_vt_stats.get("malicious", 0)
        total = last_vt_stats.get("total", 1)

        # === VirusTotal ===
        hash_summary_text.insert("end", "🧪 VirusTotal\n", "h")
        hash_summary_text.insert(
            "end",
            f"  Engines: {total}\n"
            f"  Malicious: {malicious}\n\n",
            "bad" if malicious > 0 else "ok"
        )

        # === Malware Feeds (ТОЛЬКО ДЛЯ НЕ-IP) ===
        val = current_ioc_holder.get("val", "")
        if not is_ip(val):
            mf_found = getattr(malware_ui, "last_found", None)
            mf_sources = getattr(malware_ui, "last_sources", [])

            hash_summary_text.insert("end", "🧬 Malware Feeds\n", "h")

            if mf_found is True:
                hash_summary_text.insert(
                    "end",
                    f"  Detected in: {', '.join(mf_sources)}\n",
                    "bad"
                )
            elif mf_found is False:
                hash_summary_text.insert(
                    "end",
                    "  Not found in Malware feeds\n",
                    "ok"
                )
            else:
                hash_summary_text.insert(
                    "end",
                    "  Checking…\n",
                    "muted"
                )

            hash_summary_text.insert("end", "\n")

        # === OTX ===
        pulses = getattr(otx_ui, "last_pulses", None)

        hash_summary_text.insert("end", "🛰️ OTX\n", "h")

        # ⏳ ещё идёт запрос
        if pulses is None:
            hash_summary_text.insert("end", "  Checking…\n", "muted")

        # ❌ pulses нет вообще
        elif isinstance(pulses, list) and not pulses:
            hash_summary_text.insert("end", "  Not found in OTX\n", "ok")

        # ✅ pulses есть
        else:
            tags, has_more = extract_otx_tags(pulses)

            # 🏷️ есть теги
            if tags:
                hash_summary_text.insert("end", "  Tags: ", "muted")
                for i, t in enumerate(tags):
                    hash_summary_text.insert("end", t, "tag")
                    if i < len(tags) - 1:
                        hash_summary_text.insert("end", ", ")
                if has_more:
                    hash_summary_text.insert("end", ", ...")
                hash_summary_text.insert("end", "\n")

            # ⚠️ pulse есть, тегов нет
            else:
                hash_summary_text.insert(
                    "end",
                    f"  Pulse exists ({len(pulses)}), no tags\n",
                    "warn"
                )



    def poll_result_queue():
        try:
            result = result_queue.get_nowait()
        except queue.Empty:
            root.after(100, poll_result_queue)
            return

        # === остановка прогресса ===
        progress.stop()
        progress.pack_forget()
        status_label.config(text="")

        if result.get("error"):
            info_text.insert("1.0", f"Ошибка: {result['error']}\n")
            return

        val = result["val"]
        if val != current_ioc_holder.get("val"):
            return  # устаревший результат

        attrs = result["vt_attrs"]
        obj_type = result["obj_type"]
        last_vt_attrs.clear()
        last_vt_attrs.update(attrs or {})

        malicious = result["malicious"]
        suspicious = result["suspicious"]
        harmless = result["harmless"]
        undetected = result["undetected"]
        total = result["total"]

        # ===== VT GAUGE ANIMATION (СТАРАЯ, АНИМИРОВАННАЯ) =====
        animate_gauge(
            gauge_label,
            target_value=malicious,
            total=total,
            steps=30,
            delay=15
        )

        last_vt_stats.clear()
        last_vt_stats.update({
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
        })


        label = attrs.get("popular_threat_label", "-")
        families = attrs.get("popular_threat_name", "-")

        last_analysis_str = ""
        ts = result.get("last_analysis_ts")
        if ts:
            last_analysis_str = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(ts)
            )

        extra_bits = []
        if obj_type == "ip":
            if attrs.get("country"):
                extra_bits.append(f"страна: {attrs.get('country')}")
            if attrs.get("asn"):
                extra_bits.append(f"ASN: {attrs.get('asn')}")
        elif obj_type in ("domain", "url"):
            cats = attrs.get("categories", {}) or {}
            if cats:
                extra_bits.append("категории: " + ", ".join(list(cats.values())[:3]))


        # ===== SUMMARY (ЕДИНСТВЕННОЕ МЕСТО СБОРКИ) =====
        summary_parts = [
            f"IOC: {val}",
            f"тип: {obj_type}",
            f"детекты: {malicious}/{total}",
        ]

        if last_analysis_str:
            summary_parts.append(f"last_analysis: {last_analysis_str}")

        if label and label != "-":
            summary_parts.append(f"label: {label}")
        if families and families != "-":
            summary_parts.append(f"семейства: {families}")

        if extra_bits:
            summary_parts.append("(" + "; ".join(extra_bits) + ")")

        summary_line = "; ".join(summary_parts)
        summary_text_holder["text"] = summary_line


        if malicious == 0:
            banner_bg = "#1f5f3a"
        elif malicious <= 5:
            banner_bg = "#7a5f1f"
        else:
            banner_bg = "#7a1f1f"

        summary_label.config(
            text=summary_line,
            bg=banner_bg,
            fg="#ffffff"
        )

        # ===== Информация =====
        info_text.insert("end", "=== 📌 IOC ===\n")
        info_text.insert("end", f"• IOC: {val}\n")
        info_text.insert("end", f"• Тип объекта: {obj_type}\n")
        name = attrs.get("meaningful_name")
        if name:
            info_text.insert("end", f"• Имя объекта: {name}\n")
        if last_analysis_str:
            info_text.insert("end", f"• Last analysis: {last_analysis_str}\n")
        info_text.insert("end", f"• Детекты: {malicious}/{total}\n")

        info_text.insert("end", "-" * 60 + "\n\n")

        info_text.insert("end", "=== 🔐 Хэши ===\n")
        for field in ("md5", "sha1", "sha256", "vhash", "authentihash", "imphash"):
            info_text.insert(
                "end",
                f"• {field.upper():<12}: {attrs.get(field, '-')}\n"
            )


        info_text.insert("end", "\n=== 📦 Информация о файле ===\n")
        info_text.insert("end", f"• Type: {attrs.get('type_description', '-')}\n")
        info_text.insert("end", f"• Magic: {attrs.get('magic', '-')}\n")

        size_val = attrs.get("size")
        if size_val:
            info_text.insert("end", f"• Size: {round(size_val / 1024, 2)} KB\n")
        else:
            info_text.insert("end", "• Size: -\n")

        # ===== Threat Info (НЕ для IP) =====
        if obj_type != "ip":
            info_text.insert("end", "\n=== 🚨 Threat Info ===\n")
            info_text.insert("end", f"• Label: {label or '-'}\n")

            cat = attrs.get("popular_threat_category")
            info_text.insert("end", f"• Categories: {cat or '-'}\n")

            info_text.insert("end", f"• Families: {families or '-'}\n")


        if obj_type == "ip":
            info_text.insert("end", "\n=== 🌍 Информация по IP ===\n")
            info_text.insert("end", f"• Страна: {attrs.get('country', '-')}\n")
            info_text.insert("end", f"• ASN: {attrs.get('asn', '-')}\n")
            info_text.insert("end", f"• Организация (AS Owner): {attrs.get('as_owner', '-')}\n")

        elif obj_type in ("domain", "url"):
            info_text.insert("end", "\n=== 🏷️ Категории ===\n")
            cats = attrs.get("categories", {}) or {}
            if cats:
                for k, v in cats.items():
                    info_text.insert("end", f"• {k}: {v}\n")
            else:
                info_text.insert("end", "• (категории отсутствуют)\n")

            if obj_type == "domain":
                subs = attrs.get("subdomains", []) or []
                if subs:
                    info_text.insert("end", "\n=== 🌐 Поддомены (первые 10) ===\n")
                    for s in subs[:10]:
                        info_text.insert("end", f"• {s}\n")


        # ===== Антивирусные движки =====
        av_text.insert("end", "=== 🧪 Статистика по движкам ===\n")
        av_text.insert(
            "end",
            f"• Всего движков: {total}\n"
            f"• Malicious: {malicious}\n"
            f"• Suspicious: {suspicious}\n"
            f"• Harmless: {harmless}\n"
            f"• Undetected: {undetected}\n"
        )
        av_text.insert("end", "-" * 70 + "\n\n")

        engines = attrs.get("last_analysis_results", {}) or {}
        for engine, r in engines.items():
            cat = (r.get("category") or "-").lower()
            res = r.get("result") or "-"
            icon = "➖"
            tag = None

            if "malicious" in cat:
                icon, tag = "❌", "malicious"
            elif "suspicious" in cat:
                icon, tag = "⚠️", "suspicious"
            elif "clean" in cat or "harmless" in cat or "undetected" in cat:
                icon, tag = "✅", "clean"

            av_text.insert(
                "end",
                f"{icon:<3} {engine:<22} | {res}\n",
                tag
            )

        av_text.tag_config("malicious", foreground="#FF5555")
        av_text.tag_config("suspicious", foreground="#FFA500")
        av_text.tag_config("clean", foreground="#66CC66")

        root.after(300, poll_external_sources_and_refresh)

    return frame