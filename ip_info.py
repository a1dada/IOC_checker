# ip_info.py
import requests
import ipaddress
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk
import threading
import queue


def create_ip_info_tab(
    parent,
    FRAME_BG,
    OUTPUT_BG,
    TEXT_COLOR,
    abuse_api_key,
    censys_token,
    HEADERS_CENSYS,
):


    frame = tk.Frame(parent, bg=OUTPUT_BG)
    frame.pack(fill="both", expand=True)

    # публичные поля для главного окна
    frame.last_abuse_score = None
    frame.last_country = None
    frame.last_ptr = None
    frame.on_abuse_ready = None

    # внутренняя синхронизация Abuse
    frame._abuse_q = queue.Queue()
    frame._abuse_req_id = 0
    frame._abuse_polling = False
    frame._abuse_ready_fired_for_req = None
    frame._current_ioc = ""

    # ================= AbuseIPDB UI =================

    abuse_top = tk.Frame(frame, bg=OUTPUT_BG)
    abuse_top.pack(fill="x", padx=5, pady=(5, 0))

    abuse_score_label = tk.Label(abuse_top, text="", bg=OUTPUT_BG, fg=TEXT_COLOR)
    abuse_score_label.pack(side="left", anchor="w")

    abuse_progress = ttk.Progressbar(
        abuse_top,
        orient="horizontal",
        length=200,
        mode="determinate"
    )
    abuse_progress.pack(side="right", pady=2)

    abuse_text = tk.Text(frame, wrap="word", bg=OUTPUT_BG, fg=TEXT_COLOR, height=10)
    abuse_text.configure(font=("Consolas", 9))
    abuse_text.pack(fill="x", padx=5, pady=(5, 10))

    # ================= Censys UI =================

    censys_text = tk.Text(frame, wrap="word", bg=OUTPUT_BG, fg=TEXT_COLOR)
    censys_text.configure(font=("Consolas", 9))
    censys_text.pack(fill="both", expand=True, padx=5, pady=(5, 5))

    # ================= Style =================

    style = ttk.Style()
    style.configure(
        "Abuse.Horizontal.TProgressbar",
        troughcolor=FRAME_BG,
        background="#00cc44"
    )
    abuse_progress.configure(style="Abuse.Horizontal.TProgressbar")

    # ================= Helpers =================

    def is_ip(val: str) -> bool:
        try:
            ipaddress.ip_address(val)
            return True
        except ValueError:
            return False

    def extract_domain_or_self(ioc: str) -> str:
        if ioc.startswith("http"):
            host = urlparse(ioc).hostname
            return host or ioc
        return ioc

    def detect_censys_type(ioc: str) -> str:
        if is_ip(ioc):
            return "host"
        elif "." in ioc and not ioc.startswith("http"):
            return "domain"
        elif ioc.startswith("http"):
            host = urlparse(ioc).hostname
            if host and "." in host:
                return "domain"
        return "unknown"

    # ================= Clear =================

    def clear():
        # тексты
        abuse_text.delete("1.0", tk.END)
        censys_text.delete("1.0", tk.END)

        # progress + label
        abuse_progress["value"] = 0
        abuse_score_label.config(text="")
        style.configure(
            "Abuse.Horizontal.TProgressbar",
            troughcolor=FRAME_BG,
            background="#00cc44"
        )

        # состояния
        frame.last_abuse_score = None
        frame.last_country = None
        frame.last_ptr = None

    # ================= AbuseIPDB (BACKGROUND SAFE) =================

    def _abuse_worker(ioc: str, req_id: int):
        """
        Фоновый поток: только сеть + парсинг.
        В UI не лезем. Результат кладём в очередь.
        """
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": abuse_api_key, "Accept": "application/json"}
            params = {"ipAddress": ioc, "maxAgeInDays": 90}

            resp = requests.get(url, headers=headers, params=params, timeout=20)
            if resp.status_code != 200:
                frame._abuse_q.put({
                    "req_id": req_id,
                    "ioc": ioc,
                    "ok": False,
                    "error": f"Ошибка HTTP {resp.status_code}\n{resp.text}"
                })
                return

            data = resp.json().get("data", {}) or {}
            frame._abuse_q.put({
                "req_id": req_id,
                "ioc": ioc,
                "ok": True,
                "data": data
            })
        except Exception as e:
            frame._abuse_q.put({
                "req_id": req_id,
                "ioc": ioc,
                "ok": False,
                "error": f"Ошибка запроса AbuseIPDB: {e}"
            })

    def _apply_abuse_result(payload: dict):
        """
        Главный поток: безопасно обновляем UI.
        """
        data = payload.get("data") or {}
        score = data.get("abuseConfidenceScore", 0) or 0

        frame.last_abuse_score = score
        frame.last_country = data.get("countryCode")
        frame.last_abuse_found = data.get("totalReports", 0) > 0

        # перерисовываем блок полностью
        abuse_text.delete("1.0", tk.END)
        abuse_text.insert("end", "=== 🧨 AbuseIPDB ===\n")
        abuse_text.insert("end", f"• IP: {payload.get('ioc', '-')}\n")
        abuse_text.insert("end", f"• Abuse Confidence Score: {score}%\n")
        abuse_text.insert("end", f"• Репорты: {data.get('totalReports', 0)}\n")
        abuse_text.insert("end", f"• Страна: {data.get('countryCode', '-')}\n")
        abuse_text.insert("end", f"• ISP: {data.get('isp', '-')}\n")
        abuse_text.insert("end", f"• Домен: {data.get('domain', '-')}\n")
        abuse_text.insert("end", f"• Тип: {data.get('usageType', '-')}\n")
        abuse_text.insert("end", f"• Последний репорт: {data.get('lastReportedAt', '-')}\n")

        abuse_progress["value"] = score

        if score < 21:
            color = "#00cc44"
        elif score < 71:
            color = "#cccc00"
        else:
            color = "#cc3333"

        style.configure(
            "Abuse.Horizontal.TProgressbar",
            troughcolor=FRAME_BG,
            background=color
        )

        abuse_score_label.config(text=f"Abuse Confidence Score: {score}%")

    def _poll_abuse_queue():
        """
        Главный поток: вытаскиваем ответы из очереди и применяем только актуальный req_id.
        """
        any_item = False
        while True:
            try:
                payload = frame._abuse_q.get_nowait()
            except queue.Empty:
                break

            any_item = True

            req_id = payload.get("req_id")
            # игнорируем старые ответы
            if req_id != frame._abuse_req_id:
                continue

            if not payload.get("ok"):
                abuse_text.delete("1.0", tk.END)
                abuse_text.insert("end", payload.get("error", "Ошибка AbuseIPDB"))
                # даже при ошибке считаем, что ответ получен — чтобы убрать вечное «ожидание»
                frame.last_abuse_score = 0
            else:
                _apply_abuse_result(payload)

            # on_abuse_ready — ровно 1 раз на req_id
            if frame._abuse_ready_fired_for_req != req_id:
                frame._abuse_ready_fired_for_req = req_id
                cb = getattr(frame, "on_abuse_ready", None)
                if callable(cb):
                    cb()

        # продолжаем поллинг, пока не получили актуальный ответ
        if frame._abuse_ready_fired_for_req != frame._abuse_req_id:
            frame.after(100, _poll_abuse_queue)
        else:
            frame._abuse_polling = False

    def fetch_abuse_async(ioc: str):
        # базовые проверки (главный поток)
        abuse_text.delete("1.0", tk.END)

        if not abuse_api_key:
            abuse_text.insert("end", "API-ключ AbuseIPDB не задан.")
            frame.last_abuse_score = 0
            return

        if not is_ip(ioc):
            abuse_text.insert("end", "AbuseIPDB работает только с IP-адресами.")
            frame.last_abuse_score = 0
            return

        # новый запрос
        frame._abuse_req_id += 1
        req_id = frame._abuse_req_id
        frame._abuse_ready_fired_for_req = None

        abuse_text.insert("end", "⏳ Запрос к AbuseIPDB...\n")

        t = threading.Thread(target=_abuse_worker, args=(ioc, req_id), daemon=True)
        t.start()

        # стартуем polling один раз
        if not frame._abuse_polling:
            frame._abuse_polling = True
            frame.after(100, _poll_abuse_queue)

    # ================= Censys =================

    def fetch_censys(ioc: str):
        if not censys_token:
            censys_text.insert("1.0", "API-токен Censys не задан.")
            return

        ioc_clean = extract_domain_or_self(ioc)
        c_type = detect_censys_type(ioc_clean)

        if c_type == "unknown":
            censys_text.insert("1.0", "Censys: поддерживаются только IP и домены.")
            return

        if c_type == "host":
            url = f"https://api.platform.censys.io/v3/global/asset/host/{ioc_clean}"
        else:
            url = f"https://api.platform.censys.io/v3/global/asset/domain/{ioc_clean}"

        resp = requests.get(url, headers=HEADERS_CENSYS, timeout=25)
        if resp.status_code != 200:
            censys_text.insert("1.0", f"Ошибка HTTP {resp.status_code}\n{resp.text}")
            return

        resource = (resp.json().get("result") or {}).get("resource") or {}

        # ===== Header =====
        if c_type == "host":
            censys_text.insert("end", "=== 🔭 Censys: Host Asset ===\n")
            censys_text.insert("end", f"• IP: {resource.get('ip', ioc_clean)}\n")
        else:
            censys_text.insert("end", "=== 🌐 Censys: Domain Asset ===\n")
            censys_text.insert("end", f"• Домен: {resource.get('domain', ioc_clean)}\n")

        # ===== Location =====
        loc = resource.get("location") or {}
        if loc:
            censys_text.insert("end", "\n=== 🌍 Локация ===\n")
            censys_text.insert("end", f"• Континент: {loc.get('continent', '-')}\n")
            censys_text.insert("end", f"• Страна: {loc.get('country', '-')} ({loc.get('country_code', '-')})\n")
            censys_text.insert("end", f"• Регион: {loc.get('province', '-')}\n")
            censys_text.insert("end", f"• Город: {loc.get('city', '-')}\n")
            coords = loc.get("coordinates") or {}
            censys_text.insert(
                "end",
                f"• Широта/долгота: {coords.get('latitude', '-')}, {coords.get('longitude', '-')}\n"
            )
            censys_text.insert("end", f"• Часовой пояс: {loc.get('timezone', '-')}\n")

        # ===== ASN =====
        asys = resource.get("autonomous_system") or {}
        if asys:
            censys_text.insert("end", "\n=== 🛰 Автономная система ===\n")
            censys_text.insert("end", f"• ASN: {asys.get('asn', '-')}\n")
            censys_text.insert("end", f"• Имя: {asys.get('name', '-')}\n")
            censys_text.insert("end", f"• BGP Prefix: {asys.get('bgp_prefix', '-')}\n")
            censys_text.insert("end", f"• Страна: {asys.get('country_code', '-')}\n")

        # ===== WHOIS =====
        whois = resource.get("whois") or {}
        net = whois.get("network") or {}
        org = whois.get("organization") or {}
        if net or org:
            censys_text.insert("end", "\n=== 📜 WHOIS ===\n")
        if net:
            censys_text.insert("end", f"• Сеть: {net.get('name', '-')} ({net.get('handle', '-')})\n")
            cidrs = net.get("cidrs") or []
            if cidrs:
                censys_text.insert("end", f"• CIDR: {', '.join(cidrs)}\n")
        if org:
            censys_text.insert("end", f"• Организация: {org.get('name', '-')} ({org.get('handle', '-')})\n")
            censys_text.insert("end", f"• Страна org: {org.get('country', '-')}\n")
            abuse = org.get("abuse_contacts") or []
            if abuse:
                censys_text.insert("end", f"• Abuse email: {abuse[0].get('email', '-')}\n")

        # ===== Services =====
        services = resource.get("services") or []
        if services:
            censys_text.insert("end", "\n=== 🧩 Открытые сервисы ===\n")
            for s in services:
                port = s.get("port", "-")
                proto = s.get("transport_protocol", "-") or s.get("protocol", "-")
                scan_time = s.get("scan_time", "-")
                censys_text.insert("end", f"• {port}/{proto} (scan: {scan_time})\n")

        # ===== DNS =====
        dns = resource.get("dns") or {}
        if dns:
            censys_text.insert("end", "\n=== 🌐 DNS ===\n")

            names = dns.get("names") or []
            if names:
                censys_text.insert("end", f"• Имена: {', '.join(names)}\n")

            rdns = dns.get("reverse_dns") or {}
            rnames = rdns.get("names") or []
            if rnames:
                frame.last_ptr = rnames[0]
                censys_text.insert("end", f"• PTR: {', '.join(rnames)}\n")

    # ================= Public API =================

    def fetch_all(ioc: str):
        clear()
        frame._current_ioc = ioc

        fetch_abuse_async(ioc)

        censys_text.insert("end", "\n")
        fetch_censys(ioc)

    frame.fetch_all = fetch_all
    return frame
