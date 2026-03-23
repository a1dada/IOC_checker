# cve_check.py
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import webbrowser
import re
from datetime import datetime

import settings

VULNERS_ID_URL = "https://vulners.com/api/v3/search/id/"
VULNERS_LUCENE_URL = "https://vulners.com/api/v3/search/lucene/"

# ============================================================
#                    TRANSLATIONS / MAPS
# ============================================================

SEVERITY_RU = {
    "CRITICAL": "Критическая",
    "HIGH": "Высокая",
    "MEDIUM": "Средняя",
    "LOW": "Низкая",
    "NONE": "Не определена"
}

YESNO_RU = {"NONE": "Нет", "REQUIRED": "Требуется"}

VECTOR_TRANSLATE = {
    "NETWORK": "Удалённая (Network)",
    "LOCAL": "Локальная (Local)",
    "ADJACENT": "Смежная сеть (Adjacent)",
    "PHYSICAL": "Физический доступ (Physical)",

    "NONE": "Не требуется (None)",
    "LOW": "Низкая (Low)",
    "HIGH": "Высокая (High)",

    "CHANGED": "Выходит за пределы компонента (Changed)",
    "UNCHANGED": "В рамках компонента (Unchanged)",

    "REQUIRED": "Требуется (Required)"
}

IMPACT_TRANSLATE = {
    "NONE": "Нет",
    "LOW": "Низкое",
    "HIGH": "Высокое",
}

# ============================================================
#                    HELPERS
# ============================================================

def normalize_cve(text: str) -> str:
    replace = {
        "С": "C", "с": "C",
        "М": "V", "м": "V",
        "У": "E", "у": "E",
        "–": "-", "—": "-",
        " ": ""
    }
    for k, v in replace.items():
        text = text.replace(k, v)
    return text.upper().strip()


def _get_vulners_key() -> str:
    return settings.load_api_keys().get("vuln", "").strip()


def _is_valid_cve(cve: str) -> bool:
    return bool(re.match(r"^CVE-\d{4}-\d{4,7}$", cve))


def _open(url: str):
    try:
        webbrowser.open(url)
    except Exception:
        pass


def _fmt_date(d):
    if not d:
        return "-"
    if "T" in d:
        return d.split("T")[0]
    return d


def _severity_color(score: float) -> str:
    if score >= 9:
        return "#d9534f"   # красный
    if score >= 7:
        return "#f0ad4e"   # оранжевый
    if score >= 4:
        return "#ffd966"   # желтый
    return "#5cb85c"       # зелёный


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _extract_score(info: dict) -> float:

    try:
        s = float(info.get("cvss", {}).get("score", 0.0) or 0.0)
        if s > 0:
            return s
    except Exception:
        pass

    try:
        cvss3 = info.get("cvss3", {})
        cvssV31 = cvss3.get("cvssV31", {}) if isinstance(cvss3, dict) else {}
        s = float(cvssV31.get("baseScore", 0.0) or 0.0)
        if s > 0:
            return s
    except Exception:
        pass

    try:
        ench = info.get("enchantments", {})
        score_obj = ench.get("score", {})
        s = float(score_obj.get("value", 0.0) or 0.0)
        if s > 0:
            return s
    except Exception:
        pass

    try:
        s = float(info.get("vulnersScore", 0.0) or 0.0)
        if s > 0:
            return s
    except Exception:
        pass

    return 0.0


def _extract_cvss_block(info: dict) -> dict:

    try:
        m = info.get("metrics", {}).get("cna", {}).get("cvss31", {})
        if m and isinstance(m, dict):
            return m
    except Exception:
        pass

    return {}


def _extract_epss(info: dict):

    epss_list = info.get("epss", [])
    if not epss_list:
        return None
    e = epss_list[0]
    try:
        return {
            "epss": float(e.get("epss", 0.0) or 0.0),
            "percentile": float(e.get("percentile", 0.0) or 0.0),
            "date": e.get("date", "")
        }
    except Exception:
        return None


def _safe_list(x):
    return x if isinstance(x, list) else []


def translate_google_free(text: str, target: str = "ru") -> str:

    if not text or len(text) < 5:
        return text

    url = "https://translate.googleapis.com/translate_a/single"
    params = {
        "client": "gtx",
        "sl": "auto",
        "tl": target,
        "dt": "t",
        "q": text
    }

    try:
        r = requests.get(url, params=params, timeout=12)
        r.raise_for_status()
        data = r.json()

        # перевод лежит в [0][*][0]
        translated = "".join(
            part[0] for part in data[0] if part and isinstance(part, list)
        )
        return translated.strip() or text

    except Exception:
        return text





# ============================================================
#        GLOBAL COPY / PASTE / ENTER (WINDOWS SAFE)
# ============================================================

def install_global_hotkeys(root, text_widget, entry_widget, on_enter):

    def copy():
        try:
            sel = text_widget.get("sel.first", "sel.last")
        except tk.TclError:
            return
        root.clipboard_clear()
        root.clipboard_append(sel)

    def paste():
        try:
            entry_widget.insert("insert", root.clipboard_get())
        except Exception:
            pass

    def handler(event):
        widget = root.focus_get()

        # Ctrl + C
        if event.state & 0x4 and event.keycode == 67:
            if widget == text_widget:
                copy()
                return "break"

        # Ctrl + V
        if event.state & 0x4 and event.keycode == 86:
            if widget == entry_widget:
                paste()
                return "break"

        # Enter
        if event.keycode == 13:
            if widget == entry_widget:
                on_enter()
                return "break"

    root.bind_all("<KeyPress>", handler)




# ============================================================
#                    API
# ============================================================

def get_cve(cve: str, key: str) -> dict:
    r = requests.post(
        VULNERS_ID_URL,
        headers={"X-Api-Key": key, "Content-Type": "application/json"},
        json={"id": cve, "fields": ["*"]},
        timeout=25
    )
    r.raise_for_status()
    j = r.json()
    docs = (j.get("data") or {}).get("documents") or {}
    if not docs:
        raise RuntimeError("Vulners: пустой ответ documents")
    return next(iter(docs.values()))


def get_related(cve: str, key: str, size: int = 50) -> list:

    r = requests.post(
        VULNERS_LUCENE_URL,
        headers={"X-Api-Key": key, "Content-Type": "application/json"},
        json={
            "query": f"cvelist:{cve}",
            "size": size,
            "fields": ["id", "title", "bulletinFamily", "published", "href", "sourceHref", "vhref", "cvelist", "type"]
        },
        timeout=30
    )
    r.raise_for_status()
    j = r.json()
    data = j.get("data") or {}
    docs = data.get("search") or data.get("documents") or []
    # В ответе Vulners lucene обычно data.search = list
    return docs if isinstance(docs, list) else []


# ============================================================
#                    UI RENDERING
# ============================================================

def create_cve_check_frame(root, parent, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG):
    frame = ttk.LabelFrame(parent, text="CVE info", padding=10, style="Custom.TLabelframe")

    # ---------- INPUT ----------
    top = tk.Frame(frame, bg=FRAME_BG)
    top.pack(fill="x")

    tk.Label(top, text="CVE:", bg=FRAME_BG, fg=TEXT_COLOR).pack(side="left")
    entry = tk.Entry(top, width=28, bg=OUTPUT_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
    entry.pack(side="left", padx=5)
    entry.insert(0, "CVE-")

    btn = tk.Button(top, text="Проверить", bg=BTN_COLOR, fg=TEXT_COLOR)
    btn.pack(side="left", padx=5)

    btn_open_vulners = tk.Button(top, text="Открыть Vulners", bg=BTN_COLOR, fg=TEXT_COLOR)
    btn_open_vulners.pack(side="left", padx=5)

    # ---------- SEVERITY BAR ----------
    canvas = tk.Canvas(frame, height=28, bg=OUTPUT_BG, highlightthickness=0)
    canvas.pack(fill="x", pady=(8, 8))

    # ---------- OUTPUT ----------
    text = tk.Text(frame, bg=OUTPUT_BG, fg=TEXT_COLOR, wrap="word", height=28, cursor="arrow", padx=10, pady=8)
    text.pack(fill="both", expand=True)


    # ----- Tags (beauty) -----
    text.tag_config("h1", font=("Arial", 13, "bold"))
    text.tag_config("h2", font=("Arial", 11, "bold"))
    text.tag_config("muted", foreground="#9aa4b2")
    text.tag_config("ok", foreground="#5cb85c")
    text.tag_config("warn", foreground="#f0ad4e")
    text.tag_config("bad", foreground="#d9534f")
    text.tag_config("link", foreground="#6aa9ff", underline=True)
    text.tag_config(
        "link_item",
        foreground="#6aa9ff",
        underline=True,
        lmargin1=28,   
        lmargin2=40    
    )
    text.tag_config("mono", font=("Consolas", 10))
    text.tag_config("bullet", lmargin1=16, lmargin2=28)

    def add_link(label: str, url: str):
        if not url:
            return

        start = text.index("end-1c")
        text.insert("end", label, ("link",))
        end = text.index("end-1c")

        tag = f"link_{start}"
        text.tag_add(tag, start, end)
        text.tag_bind(tag, "<Button-1>", lambda e, u=url: _open(u))

        text.insert("end", "\n")


    def add_list_link(label: str, url: str):
        if not url:
            return

        text.insert("end", "🔗 ", ("bullet",))

        start = text.index("end-1c")
        text.insert("end", label, ("link_item",))
        end = text.index("end-1c")

        tag = f"link_{start}"
        text.tag_add(tag, start, end)
        text.tag_bind(tag, "<Button-1>", lambda e, u=url: _open(u))

        text.insert("end", "\n")


    def add_kv(k: str, v: str):
        text.insert("end", f"{k}: ", ("muted",))
        text.insert("end", f"{v}\n")

    def draw_severity_bar(score: float, sev_key: str):
        canvas.delete("all")
        w = canvas.winfo_width() or 700
        fill = _severity_color(score)
        canvas.create_rectangle(0, 0, int(w * (max(0.0, min(score, 10.0)) / 10.0)), 28, fill=fill, outline="")
        sev_ru = SEVERITY_RU.get(sev_key, "Не определена")
        canvas.create_text(
            12, 14,
            anchor="w",
            text=f"CVSS: {score:.1f}  |  {sev_ru}",
            fill=TEXT_COLOR,
            font=("Arial", 10, "bold")
        )

    def group_related(items: list) -> dict:

        groups = {
            "exploit": [],
            "scanner": [],
            "cisa_kev": [],
            "cve": [],
            "vendor": [],
            "info": [],
            "tools": [],
            "other": []
        }

        for it in items:
            src = it.get("_source", it) if isinstance(it, dict) else {}
            fam = (src.get("bulletinFamily") or "").lower()
            typ = (src.get("type") or "").lower()

            row = {
                "title": (src.get("title") or src.get("id") or "").strip(),
                "id": (src.get("id") or "").strip(),
                "published": _fmt_date(src.get("published")),
                "href": (src.get("href") or src.get("sourceHref") or src.get("vhref") or "").strip(),
                "vhref": (src.get("vhref") or "").strip(),
                "family": fam or typ or "other"
            }

            if fam == "exploit":
                groups["exploit"].append(row)
            elif fam == "scanner":
                groups["scanner"].append(row)
            elif typ == "cisa_kev" or fam == "cisa_kev":
                groups["cisa_kev"].append(row)
            elif fam in ("cve", "nvd", "cvelist"):
                groups["cve"].append(row)
            elif fam in ("unix", "software", "microsoft", "redhat", "debian", "ubuntu", "susecve", "oracle", "amazon"):
                groups["vendor"].append(row)
            elif fam in ("info",):
                groups["info"].append(row)
            elif fam in ("tools",):
                groups["tools"].append(row)
            else:
                groups["other"].append(row)

        def sort_key(r):
            p = r.get("published") or ""
            try:
                return datetime.strptime(p, "%Y-%m-%d")
            except Exception:
                return datetime.min

        for k in groups:
            groups[k].sort(key=sort_key, reverse=True)

        return groups

    def run():
        raw = entry.get()
        cve = normalize_cve(raw)

        entry.delete(0, tk.END)
        entry.focus_set()

        key = _get_vulners_key()
        if not key:
            messagebox.showerror(
                "Ошибка",
                "Vulners API key не задан (settings → API-ключи → Vulners)."
            )
            return

        if not _is_valid_cve(cve):
            messagebox.showerror(
                "Ошибка",
                "Некорректный формат CVE. Пример: CVE-2021-44228"
            )
            return


        text.config(state="normal")
        text.delete("1.0", "end")
        canvas.delete("all")

        try:
            info = get_cve(cve, key)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось получить CVE из Vulners:\n{e}")
            return

        # --- score / severity ---
        score = _extract_score(info)
        sev_key = _severity_from_score(score)

        draw_severity_bar(score, sev_key)

        # --- EPSS ---
        epss = _extract_epss(info)

        # --- headline ---
        title = (info.get("title") or cve).strip()
        short = (info.get("short_description") or "").strip()

        text.insert("end", f"{cve}\n", ("h1",))
        text.insert("end", f"{title}\n", ("h2",))
        if short and short.lower() != title.lower():
            text.insert("end", f"{short}\n", ("muted",))
        text.insert("end", "\n")

        # --- summary block ---
        sev_ru = SEVERITY_RU.get(sev_key, "Не определена")
        add_kv("Критичность", f"{sev_ru} (CVSS {score:.1f})")

        if epss:
            epss_pct = epss["epss"] * 100.0
            perc = epss["percentile"] * 100.0
            add_kv("EPSS", f"{epss_pct:.2f}% (перцентиль {perc:.2f}%, дата {epss.get('date','-')})")
            text.insert(
                "end",
                "EPSS — вероятностная оценка того, что уязвимость будет эксплуатироваться в ближайшее время (на основе телеметрии).\n",
                ("muted",)
            )
        text.insert("end", "\n")

        # --- description ---
        text.insert("end", "Описание\n", ("h2",))

        desc = (info.get("description") or "-").strip()

        # перевод ТОЛЬКО описания
        desc_ru = translate_google_free(desc)

        text.insert("end", desc_ru + "\n", ())
        if desc_ru != desc:
            text.insert("end", "\nОригинал (EN)\n", ("muted",))
            text.insert("end", desc + "\n", ("muted",))

        text.insert("end", "\n")

        # --- CVSS details (если есть) ---
        m = _extract_cvss_block(info)
        if m:
            text.insert("end", "Параметры атаки (CVSS)\n", ("h2",))
            av = VECTOR_TRANSLATE.get(m.get("attackVector"), m.get("attackVector", "-"))
            ac = VECTOR_TRANSLATE.get(m.get("attackComplexity"), m.get("attackComplexity", "-"))
            pr = VECTOR_TRANSLATE.get(m.get("privilegesRequired"), m.get("privilegesRequired", "-"))
            ui = VECTOR_TRANSLATE.get(m.get("userInteraction"), m.get("userInteraction", "-"))
            sc = VECTOR_TRANSLATE.get(m.get("scope"), m.get("scope", "-"))

            c = IMPACT_TRANSLATE.get(m.get("confidentialityImpact"), m.get("confidentialityImpact", "-"))
            i = IMPACT_TRANSLATE.get(m.get("integrityImpact"), m.get("integrityImpact", "-"))
            a = IMPACT_TRANSLATE.get(m.get("availabilityImpact"), m.get("availabilityImpact", "-"))

            text.insert("end", f"• Вектор атаки: {av}\n", ("bullet",))
            text.insert("end", f"• Сложность атаки: {ac}\n", ("bullet",))
            text.insert("end", f"• Требуемые привилегии: {pr}\n", ("bullet",))
            text.insert("end", f"• Взаимодействие пользователя: {ui}\n", ("bullet",))
            text.insert("end", f"• Область влияния: {sc}\n", ("bullet",))
            text.insert("end", f"• Влияние (C/I/A): {c} / {i} / {a}\n", ("bullet",))
            text.insert("end", "\n")

        # --- dates ---
        text.insert("end", "Даты\n", ("h2",))
        add_kv("Опубликована", _fmt_date(info.get("published")))
        add_kv("Обновлена", _fmt_date(info.get("modified")))
        text.insert("end", "\n")

        # --- links (cve.org / vulners) ---
        text.insert("end", "Основные ссылки\n", ("h2",))
        vulners_url = f"https://vulners.com/cve/{cve}"
        add_link(f"Vulners: {vulners_url}", vulners_url)


        cve_org = info.get("href")  
        if cve_org:
            add_link(f"CVE.org: {cve_org}", cve_org)

        refs = _safe_list(info.get("references"))
        nvd_ref = next((r for r in refs if "nvd.nist.gov" in r or "web.nvd.nist.gov" in r), "")
        if nvd_ref:
            add_link(f"NVD: {nvd_ref}", nvd_ref)

        text.insert("end", "\n")

        if refs:
            text.insert("end", "Референсы (официальные/публичные источники)\n", ("h2",))
            for r in refs[:25]:
                add_list_link(r, r)

            if len(refs) > 25:
                text.insert("end", f"... и ещё {len(refs)-25}\n", ("muted",))
            text.insert("end", "\n")

        try:
            related = get_related(cve, key, size=80)
        except Exception as e:
            related = []
            text.insert("end", f"Не удалось получить связанные документы (lucene): {e}\n", ("muted",))

        if related:
            groups = group_related(related)

            def render_group(title_ru: str, items: list, limit: int = 20):
                if not items:
                    return
                text.insert("end", title_ru + "\n", ("h2",))
                for it in items[:limit]:
                    t = it["title"] or it["id"] or "-"
                    p = it["published"] or "-"
                    url = it["href"] or it["vhref"] or ""
                    if url:
                        text.insert("end", "🔗 ", ("bullet",))
                        start = text.index("end-1c")
                        text.insert("end", f"[{p}] {t}", ("link_item",))
                        end = text.index("end-1c")

                        tag = f"link_{start}"
                        text.tag_add(tag, start, end)
                        text.tag_bind(tag, "<Button-1>", lambda e, u=url: _open(u))

                        text.insert("end", "\n")
                    else:
                        text.insert("end", f"🔗 [{p}] {t}\n", ("bullet",))
                if len(items) > limit:
                    text.insert("end", f"... и ещё {len(items)-limit}\n", ("muted",))
                text.insert("end", "\n")

            render_group("Эксплойты / PoC (по Vulners)", groups["exploit"], limit=15)
            render_group("Сканеры / шаблоны детекта", groups["scanner"], limit=15)
            render_group("CISA KEV / подтверждённая эксплуатация", groups["cisa_kev"], limit=10)
            render_group("Vendor advisories / бюллетени", groups["vendor"], limit=20)
            render_group("CVE / NVD / CVEList (зеркала)", groups["cve"], limit=10)
            render_group("Аналитика / статьи", groups["info"], limit=10)
            render_group("Инструменты", groups["tools"], limit=10)
            render_group("Прочее", groups["other"], limit=10)

        # lock
        text.config(state="disabled")

    install_global_hotkeys(
        root=root,
        text_widget=text,
        entry_widget=entry,
        on_enter=run
    )       

    def open_vulners():
        cve = normalize_cve(entry.get())
        if _is_valid_cve(cve):
            _open(f"https://vulners.com/cve/{cve}")
        else:
            messagebox.showerror("Ошибка", "Сначала введите корректный CVE (например CVE-2021-44228).")

    btn.config(command=run)
    btn_open_vulners.config(command=open_vulners)

    return frame
