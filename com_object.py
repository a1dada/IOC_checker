# com_object.py
# SOC Helper — COM Objects (CLSID) analyzer
# Reads: strontic-xcyclopedia_COM.json (UTF-8 with BOM supported)
# UI: Detailed report + full parameter table + per-field explanations + RAW JSON tab

import json
import tkinter as tk
from tkinter import ttk
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional


JSON_FILE = "com_base.json"


# =============================================================================
# Explanations (detailed, SOC-friendly)
# =============================================================================

# Per-path explanations: use normalized key names and/or path suffix matching.
# We intentionally provide strong explanations for the "important for CLSID" parts,
# and placeholders for the rest (you can fill later).
FIELD_DOC = {
    # Top-level
    "CLSID": {
        "title": "CLSID",
        "what": "Уникальный идентификатор COM-класса (Component Object Model).",
        "why": (
            "CLSID используется системой и приложениями для создания COM-объекта. "
            "В SOC контексте CLSID важен как 'точка входа' в загрузку DLL/запуск EXE через COM, "
            "а также как объект для COM hijacking (персистентность/эскалация/обход контроля)."
        ),
        "values": "Формат: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}",
        "soc": "Ищи аномальные CLSID, неизвестные компоненты, несоответствие пути сервера, TreatAs, нестандартные каталоги."
    },
    "(default)": {
        "title": "Имя объекта (Default)",
        "what": "Человекочитаемое название COM-класса в реестре.",
        "why": (
            "Помогает быстро понять назначение объекта. Не является гарантом безопасности: "
            "вредонос может подделать название."
        ),
        "values": "Строка.",
        "soc": "Сравнивай имя с путём сервера и контекстом. Если имя 'Microsoft/Windows', а путь нестандартный — подозрительно."
    },
    "AppID": {
        "title": "AppID",
        "what": "Идентификатор DCOM-приложения, связанный с CLSID (не всегда присутствует).",
        "why": (
            "AppID используется для настроек запуска/безопасности DCOM: права, разрешения, контекст, изоляция. "
            "Важно, если объект может активироваться удалённо или в особом контексте."
        ),
        "values": "GUID в фигурных скобках.",
        "soc": "Если AppID есть — стоит смотреть DCOM-настройки (Launch/Access permissions) и кто может активировать объект."
    },

    # Registry subkeys
    "Registry": {
        "title": "Registry",
        "what": "Блок данных, отражающий типовую структуру регистрации CLSID в реестре Windows.",
        "why": (
            "Здесь находятся ключи, определяющие КАК именно COM-объект создаётся: "
            "какой сервер (DLL/EXE/служба), threading model, ProgID, TypeLib и т.п."
        ),
        "values": "Содержит подпункты (InProcServer32/LocalServer32/ProgID/TypeLib/…).",
        "soc": "Это основной источник для COM hijacking/abuse."
    },
    "Registry\\InProcServer32": {
        "title": "InProcServer32",
        "what": "Указывает DLL (COM-сервер), которая будет загружена внутрь процесса клиента.",
        "why": (
            "Это классический механизм: при создании COM-объекта DLL загружается в адресное пространство процесса. "
            "Если злоумышленник подменяет путь DLL или саму DLL — получаем выполнение кода."
        ),
        "values": "Обычно путь к DLL. Дополнительно может быть ThreadingModel.",
        "soc": (
            "Высокий риск: путь вне System32/Program Files, наличие DLL в user-writable директории, "
            "неожиданные расширения/пробелы/кавычки, side-loading."
        )
    },
    "Registry\\LocalServer32": {
        "title": "LocalServer32",
        "what": "Указывает EXE (локальный COM-сервер), который запускается как отдельный процесс.",
        "why": (
            "Создание COM-объекта приведёт к запуску EXE. Часто используется в автоматизации и системных компонентах, "
            "но также может быть abused для запуска нежелательных процессов."
        ),
        "values": "Командная строка/путь к EXE (часто в кавычках).",
        "soc": "Риск: запуск EXE из нестандартных мест, пользовательские каталоги, странные аргументы."
    },
    "Registry\\LocalService": {
        "title": "LocalService",
        "what": "Имя службы Windows, через которую может активироваться COM-сервер (Service-based COM).",
        "why": "COM может запускаться/хоститься службой. Это важный контекст безопасности.",
        "values": "Имя службы (строка).",
        "soc": "Проверь соответствующую службу: бинарь, учетную запись запуска, триггеры, изменения."
    },
    "Registry\\InProcHandler32": {
        "title": "InProcHandler32",
        "what": "COM handler (обработчик) — вспомогательный DLL-компонент, который может перехватывать/обрабатывать вызовы.",
        "why": "Реже встречается, но также может быть точкой внедрения.",
        "values": "Путь к DLL.",
        "soc": "Подозрительно, если handler из нестандартных путей."
    },
    "Registry\\ProgID": {
        "title": "ProgID",
        "what": "Программный идентификатор COM-класса (читаемое имя для скриптов/автоматизации).",
        "why": (
            "Позволяет создавать объект по имени (например, CreateObject(\"InternetExplorer.Application\")). "
            "Используется PowerShell/VBScript/Office-макросами."
        ),
        "values": "Строка вида Vendor.Component.Version",
        "soc": "Часто встречается в цепочках initial access / execution (макросы/скрипты)."
    },
    "Registry\\VersionIndependentProgID": {
        "title": "VersionIndependentProgID",
        "what": "ProgID без версии (универсальный идентификатор).",
        "why": (
            "Позволяет обращаться к объекту независимо от версии. "
            "Иногда злоумышленники предпочитают этот идентификатор для совместимости."
        ),
        "values": "Строка вида Vendor.Component",
        "soc": "Используется в автоматизации; сопоставляй с ProgID и фактическим сервером."
    },
    "Registry\\TypeLib": {
        "title": "TypeLib",
        "what": "GUID библиотеки типов — описание интерфейсов COM (методы/свойства), используемое для автоматизации.",
        "why": "Позволяет понять API объекта (что он умеет), особенно важно при анализе злоупотреблений автоматизацией.",
        "values": "GUID в фигурных скобках.",
        "soc": "Если объект предоставляет опасные методы (запуск, запись файлов, сеть) — повышай риск."
    },
    "Registry\\ThreadingModel": {
        "title": "ThreadingModel",
        "what": "Модель потоков, в которой COM-сервер работает (важно для COM runtime).",
        "why": (
            "Влияет на то, как COM проксирует вызовы между потоками. "
            "Для SOC: полезный контекст, но не главный индикатор компрометации."
        ),
        "values": (
            "Возможные значения:\n"
            "- Apartment (STA)\n"
            "- Free (MTA)\n"
            "- Both (STA+MTA)\n"
            "- Neutral (реже)\n"
        ),
        "soc": "Если ThreadingModel отсутствует/странный — может быть криво зарегистрированный объект."
    },
    "Registry\\TreatAs": {
        "title": "TreatAs",
        "what": "Механизм 'подмены' CLSID: один CLSID может указывать на другой.",
        "why": (
            "Используется для совместимости, но также может применяться в COM hijacking: "
            "подменить поведение легитимного CLSID."
        ),
        "values": "GUID другого CLSID.",
        "soc": "TreatAs в сочетании с нестандартным сервером — сильный индикатор abuse."
    },
    "Registry\\PersistentHandler": {
        "title": "PersistentHandler",
        "what": "Обработчик постоянного хранения — часто связывает COM с типами файлов/объектов хранения.",
        "why": "Может использоваться при открытии файлов/обработке контента (возможны сценарии злоупотребления).",
        "values": "GUID обработчика.",
        "soc": "Смотри связки с расширениями/обработчиками оболочки (Shell extensions)."
    },
    "Registry\\Elevation": {
        "title": "Elevation",
        "what": "Параметры Elevation (UAC/автоподнятие) для COM.",
        "why": "Иногда COM может активироваться с повышением (auto-elevate) в определённых условиях.",
        "values": "Набор значений (Enabled/…); структура зависит от ключа.",
        "soc": "Если объект связан с elevation и может быть abused — потенциальная эскалация."
    },

    # Instance
    "Instance": {
        "title": "Instance",
        "what": "Описательная часть: методы/свойства и тип (как в dataset).",
        "why": (
            "Это справочная информация: что объект умеет. "
            "Полезно для аналитика, но не всегда нужно показывать полностью."
        ),
        "values": "Подразделы Methods / Properties / Type.",
        "soc": "Если методы включают Navigate/Run/Execute/Write — оцени риск в контексте."
    },
    "Instance\\Methods": {
        "title": "Methods",
        "what": "Список доступных методов COM-объекта (с сигнатурами).",
        "why": "Понимание возможностей объекта при автоматизации/abuse.",
        "values": "Метод → сигнатура.",
        "soc": "Опасны методы, позволяющие выполнять команды, записывать файлы, обращаться в сеть."
    },
    "Instance\\Properties": {
        "title": "Properties",
        "what": "Список доступных свойств COM-объекта.",
        "why": "Помогает понять, какие параметры можно читать/менять скриптом.",
        "values": "Свойство → тип/сигнатура.",
        "soc": "Опасно, если свойства позволяют управлять поведением (URL, Path, CommandLine)."
    },

    # Generic placeholders (will be used if unknown)
    "__UNKNOWN__": {
        "title": "Не описано",
        "what": "Описание для этого параметра пока не заполнено.",
        "why": "Можно добавить позже, когда решим, что именно важно для SOC.",
        "values": "—",
        "soc": "—"
    }
}


# =============================================================================
# Helpers
# =============================================================================

def _safe_json_load(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Не найден файл базы COM: {path}")
    # utf-8-sig fixes BOM
    with p.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def _norm_guid(s: str) -> str:
    s = (s or "").strip()
    # keep braces if provided; dataset uses {GUID}
    return s


def _get_doc_for_path(path: str) -> Dict[str, str]:
    """
    Match explanations by exact key or by suffix-like normalized paths:
    Example: "Registry\\InProcServer32\\(default)" -> match "Registry\\InProcServer32"
    """
    if path in FIELD_DOC:
        return FIELD_DOC[path]
    # Try trimming leafs like "\(default)" or value names
    parts = path.split("\\")
    while len(parts) > 1:
        parts.pop()
        candidate = "\\".join(parts)
        if candidate in FIELD_DOC:
            return FIELD_DOC[candidate]
    # Try single key
    if path.split("\\")[-1] in FIELD_DOC:
        return FIELD_DOC[path.split("\\")[-1]]
    return FIELD_DOC["__UNKNOWN__"]


def _extract_key_values(obj: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """
    Returns list of (path, key, value_str) flattened for UI table.
    path includes backslashes, key is leaf key, value_str is human string.
    """
    rows: List[Tuple[str, str, str]] = []

    def walk(node: Any, prefix: str = ""):
        if isinstance(node, dict):
            for k, v in node.items():
                p = f"{prefix}\\{k}" if prefix else str(k)
                if isinstance(v, dict):
                    # still add the node (so user sees sections)
                    rows.append((p, str(k), "{...}"))
                    walk(v, p)
                elif isinstance(v, list):
                    rows.append((p, str(k), f"[list:{len(v)}]"))
                    # optional: walk list items if they are dicts
                    for i, it in enumerate(v):
                        ip = f"{p}\\[{i}]"
                        if isinstance(it, dict):
                            rows.append((ip, f"[{i}]", "{...}"))
                            walk(it, ip)
                        else:
                            rows.append((ip, f"[{i}]", str(it)))
                else:
                    rows.append((p, str(k), "" if v is None else str(v)))
        else:
            rows.append((prefix or "value", "value", str(node)))

    walk(obj)
    return rows


def _pick_summary(obj: Dict[str, Any]) -> Dict[str, str]:
    """
    Build the most useful SOC-friendly summary.
    """
    reg = obj.get("Registry", {}) if isinstance(obj.get("Registry"), dict) else {}
    name = obj.get("(default)", "—")

    # server type + path
    server_type = "—"
    server_path = "—"

    def _get_default(d: Any) -> str:
        if isinstance(d, dict):
            return d.get("(default)", "—")
        return "—"

    # LocalServer32 preferred, then InProcServer32 variants, then LocalService
    if "LocalServer32" in reg:
        server_type = "Local COM Server (EXE)"
        server_path = _get_default(reg.get("LocalServer32"))
    elif "InProcServer32" in reg:
        server_type = "In-Process COM Server (DLL)"
        server_path = _get_default(reg.get("InProcServer32"))
    elif "InprocServer32" in reg:
        server_type = "In-Process COM Server (DLL)"
        server_path = _get_default(reg.get("InprocServer32"))
    elif "LocalService" in reg:
        server_type = "Service-based COM"
        server_path = str(reg.get("LocalService", "—"))

    threading = str(reg.get("ThreadingModel", "—"))
    progid = "—"
    viprogid = "—"
    typelib = "—"
    treatas = "—"
    appid = str(obj.get("AppID") or obj.get("AppId") or "—")

    if isinstance(reg.get("ProgID"), dict):
        progid = reg["ProgID"].get("(default)", "—")
    elif "ProgID" in reg and isinstance(reg.get("ProgID"), str):
        progid = reg.get("ProgID", "—")

    if isinstance(reg.get("VersionIndependentProgID"), dict):
        viprogid = reg["VersionIndependentProgID"].get("(default)", "—")
    elif "VersionIndependentProgID" in reg and isinstance(reg.get("VersionIndependentProgID"), str):
        viprogid = reg.get("VersionIndependentProgID", "—")

    if isinstance(reg.get("TypeLib"), dict):
        typelib = reg["TypeLib"].get("(default)", "—")
    elif "TypeLib" in reg and isinstance(reg.get("TypeLib"), str):
        typelib = reg.get("TypeLib", "—")

    if isinstance(reg.get("TreatAs"), dict):
        treatas = reg["TreatAs"].get("(default)", "—")
    elif "TreatAs" in reg and isinstance(reg.get("TreatAs"), str):
        treatas = reg.get("TreatAs", "—")

    return {
        "Имя объекта": str(name),
        "Тип сервера": server_type,
        "Сервер (путь/команда)": server_path,
        "ThreadingModel": threading,
        "ProgID": progid,
        "VersionIndependentProgID": viprogid,
        "TypeLib": typelib,
        "TreatAs": treatas,
        "AppID": appid,
    }


def _build_detailed_report(clsid: str, obj: Dict[str, Any]) -> str:
    """
    Big, readable, detailed report (parameter → value + meaning).
    """
    s = _pick_summary(obj)
    lines: List[str] = []
    lines.append("COM Object (CLSID) — подробный отчёт")
    lines.append("=" * 78)
    lines.append(f"CLSID: {clsid}")
    lines.append("")

    # Summary block
    lines.append("Краткая сводка (самое важное для SOC):")
    lines.append("-" * 78)
    for k in [
        "Имя объекта", "Тип сервера", "Сервер (путь/команда)",
        "ThreadingModel", "ProgID", "VersionIndependentProgID",
        "TypeLib", "TreatAs", "AppID"
    ]:
        lines.append(f"{k:28} : {s.get(k,'—')}")
    lines.append("")

    # Explanations for summary fields
    lines.append("Пояснения к ключевым полям:")
    lines.append("-" * 78)

    explain_map = [
        ("Имя объекта", "(default)"),
        ("AppID", "AppID"),
        ("Тип сервера", "Registry\\LocalServer32"),  # generic explanation anchored to server path
        ("Сервер (путь/команда)", "Registry\\LocalServer32"),
        ("ThreadingModel", "Registry\\ThreadingModel"),
        ("ProgID", "Registry\\ProgID"),
        ("VersionIndependentProgID", "Registry\\VersionIndependentProgID"),
        ("TypeLib", "Registry\\TypeLib"),
        ("TreatAs", "Registry\\TreatAs"),
    ]
    for label, path in explain_map:
        doc = _get_doc_for_path(path)
        lines.append(f"[{label}]")
        lines.append(f"  Что это: {doc['what']}")
        lines.append(f"  Зачем нужно: {doc['why']}")
        if doc.get("values") and doc["values"] != "—":
            vals = doc["values"].splitlines()
            lines.append("  Возможные значения:")
            for v in vals:
                lines.append(f"    {v}")
        if doc.get("soc") and doc["soc"] != "—":
            lines.append(f"  SOC-заметки: {doc['soc']}")
        lines.append("")

    # Instance info (compact)
    inst = obj.get("Instance", {}) if isinstance(obj.get("Instance"), dict) else {}
    if inst:
        lines.append("Интерфейсы (справочно):")
        lines.append("-" * 78)
        m = inst.get("Methods", {}) if isinstance(inst.get("Methods"), dict) else {}
        p = inst.get("Properties", {}) if isinstance(inst.get("Properties"), dict) else {}
        lines.append(f"Методы: {len(m)}  |  Свойства: {len(p)}")
        lines.append("Если нужно — смотри вкладку «Интерфейсы» и «RAW» для деталей.")
        lines.append("")

    return "\n".join(lines)


# =============================================================================
# UI
# =============================================================================

def create_com_object_frame(
    root,
    parent_frame,
    BG_COLOR,
    BTN_COLOR,
    TEXT_COLOR,
    FRAME_BG,
    OUTPUT_BG
):
    frame = tk.Frame(parent_frame, bg=FRAME_BG)

    # --- Load data once ---
    try:
        db = _safe_json_load(JSON_FILE)
    except Exception as e:
        tk.Label(
            frame,
            text=f"Ошибка загрузки базы COM: {e}",
            bg=FRAME_BG,
            fg="red"
        ).pack(anchor="w", padx=10, pady=10)
        return frame

    # --- Header / input ---
    header = tk.Frame(frame, bg=FRAME_BG)
    header.pack(fill="x", padx=10, pady=(10, 6))

    tk.Label(
        header,
        text="COM-objects (CLSID) — анализатор",
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        font=("Segoe UI", 12, "bold")
    ).pack(anchor="w")

    row = tk.Frame(frame, bg=FRAME_BG)
    row.pack(fill="x", padx=10, pady=(0, 8))

    tk.Label(row, text="CLSID:", bg=FRAME_BG, fg=TEXT_COLOR).pack(side="left")

    entry = tk.Entry(
        row,
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR
    )
    entry.pack(side="left", fill="x", expand=True, padx=(8, 8))

    btn_analyze = tk.Button(
        row,
        text="Анализировать",
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        command=lambda: None
    )
    btn_analyze.pack(side="left")

    btn_paste = tk.Button(
        row,
        text="Вставить и анализировать",
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        command=lambda: None
    )
    btn_paste.pack(side="left", padx=(8, 0))

    # --- Notebook (tabs) ---
    nb = ttk.Notebook(frame)
    nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    tab_report = tk.Frame(nb, bg=FRAME_BG)
    tab_params = tk.Frame(nb, bg=FRAME_BG)
    tab_iface = tk.Frame(nb, bg=FRAME_BG)
    tab_raw = tk.Frame(nb, bg=FRAME_BG)

    nb.add(tab_report, text="Отчёт")
    nb.add(tab_params, text="Параметры")
    nb.add(tab_iface, text="Интерфейсы")
    nb.add(tab_raw, text="RAW")

    # --- Report tab ---
    report = tk.Text(
        tab_report,
        wrap="word",
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        height=18
    )
    report.pack(fill="both", expand=True, padx=8, pady=8)

    # --- Params tab: left table + right explanation panel ---
    params_root = tk.Frame(tab_params, bg=FRAME_BG)
    params_root.pack(fill="both", expand=True, padx=8, pady=8)

    left = tk.Frame(params_root, bg=FRAME_BG)
    left.pack(side="left", fill="both", expand=True)

    right = tk.Frame(params_root, bg=FRAME_BG, width=380)
    right.pack(side="right", fill="y")
    right.pack_propagate(False)

    # Table
    cols = ("path", "value")
    tree = ttk.Treeview(left, columns=cols, show="headings", height=16)
    tree.heading("path", text="Параметр (путь)")
    tree.heading("value", text="Значение")
    tree.column("path", width=520, anchor="w")
    tree.column("value", width=520, anchor="w")
    tree.pack(fill="both", expand=True)

    # Scrollbar
    sb = ttk.Scrollbar(left, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")

    # Right panel (details)
    tk.Label(
        right,
        text="Пояснение выбранного параметра",
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        font=("Segoe UI", 10, "bold")
    ).pack(anchor="w", padx=10, pady=(0, 6))

    detail = tk.Text(
        right,
        wrap="word",
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        height=18
    )
    detail.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # --- Interfaces tab ---
    iface_root = tk.Frame(tab_iface, bg=FRAME_BG)
    iface_root.pack(fill="both", expand=True, padx=8, pady=8)

    iface_left = tk.Frame(iface_root, bg=FRAME_BG)
    iface_left.pack(side="left", fill="both", expand=True)

    iface_right = tk.Frame(iface_root, bg=FRAME_BG, width=380)
    iface_right.pack(side="right", fill="y")
    iface_right.pack_propagate(False)

    tk.Label(
        iface_left,
        text="Методы / Свойства (список)",
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        font=("Segoe UI", 10, "bold")
    ).pack(anchor="w")

    iface_list = tk.Listbox(iface_left, bg=OUTPUT_BG, fg=TEXT_COLOR)
    iface_list.pack(fill="both", expand=True, pady=(6, 0))

    tk.Label(
        iface_right,
        text="Детали выбранного элемента",
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        font=("Segoe UI", 10, "bold")
    ).pack(anchor="w", padx=10, pady=(0, 6))

    iface_detail = tk.Text(
        iface_right,
        wrap="word",
        bg=OUTPUT_BG,
        fg=TEXT_COLOR,
        height=18
    )
    iface_detail.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # --- RAW tab ---
    raw = tk.Text(tab_raw, wrap="none", bg=OUTPUT_BG, fg=TEXT_COLOR)
    raw.pack(fill="both", expand=True, padx=8, pady=8)

    # state
    current_obj: Optional[Dict[str, Any]] = None
    current_rows: List[Tuple[str, str, str]] = []
    iface_map: Dict[int, Tuple[str, str]] = {}  # index -> (kind, signature)

    # --- UI helpers ---
    def set_report(text: str):
        report.delete("1.0", tk.END)
        report.insert(tk.END, text)

    def set_detail_text(text: str):
        detail.delete("1.0", tk.END)
        detail.insert(tk.END, text)

    def set_iface_detail(text: str):
        iface_detail.delete("1.0", tk.END)
        iface_detail.insert(tk.END, text)

    def clear_all():
        nonlocal current_obj, current_rows, iface_map
        current_obj = None
        current_rows = []
        iface_map = {}
        set_report("")
        raw.delete("1.0", tk.END)
        tree.delete(*tree.get_children())
        iface_list.delete(0, tk.END)
        set_detail_text("Выбери параметр в таблице слева — тут появится объяснение.\n")
        set_iface_detail("Выбери метод/свойство — тут появится сигнатура.\n")

    def analyze():
        nonlocal current_obj, current_rows, iface_map

        clsid = _norm_guid(entry.get())
        clear_all()

        if not clsid:
            set_report("Введите CLSID в формате {GUID}.")
            return

        obj = db.get(clsid)
        if not isinstance(obj, dict):
            set_report(f"CLSID не найден в базе: {clsid}")
            return

        current_obj = obj

        # Report
        set_report(_build_detailed_report(clsid, obj))

        # RAW
        raw.insert(tk.END, json.dumps(obj, indent=2, ensure_ascii=False))

        # Parameters table (flatten)
        rows = _extract_key_values(obj)
        # Sort: show key sections first
        def sort_key(r: Tuple[str, str, str]):
            path = r[0]
            pri = 9
            if path == "(default)":
                pri = 0
            elif path.startswith("Registry"):
                pri = 1
            elif path.startswith("AppID") or path.startswith("AppId"):
                pri = 2
            elif path.startswith("Instance"):
                pri = 3
            return (pri, path.lower())

        rows.sort(key=sort_key)
        current_rows = rows

        for p, k, v in rows:
            # Keep table compact: value trimmed, full value shown in right panel
            vv = v
            if len(vv) > 160:
                vv = vv[:160] + " …"
            tree.insert("", "end", values=(p, vv))

        # Interfaces
        inst = obj.get("Instance", {}) if isinstance(obj.get("Instance"), dict) else {}
        methods = inst.get("Methods", {}) if isinstance(inst.get("Methods"), dict) else {}
        props = inst.get("Properties", {}) if isinstance(inst.get("Properties"), dict) else {}

        iface_map = {}
        idx = 0
        if methods:
            iface_list.insert(tk.END, "=== METHODS ===")
            iface_map[idx] = ("header", "")
            idx += 1
            for name, sig in methods.items():
                iface_list.insert(tk.END, f"{name}")
                iface_map[idx] = ("method", str(sig))
                idx += 1

        if props:
            iface_list.insert(tk.END, "=== PROPERTIES ===")
            iface_map[idx] = ("header", "")
            idx += 1
            for name, sig in props.items():
                iface_list.insert(tk.END, f"{name}")
                iface_map[idx] = ("property", str(sig))
                idx += 1

        # Default hint
        set_detail_text(
            "Выбери строку в таблице слева.\n\n"
            "Здесь будет:\n"
            "- Полное значение (без обрезки)\n"
            "- Что это значит\n"
            "- Возможные значения (если применимо)\n"
            "- SOC-заметки\n"
        )

    def paste_and_analyze():
        try:
            entry.delete(0, tk.END)
            entry.insert(0, root.clipboard_get())
            analyze()
        except tk.TclError:
            pass

    btn_analyze.config(command=analyze)
    btn_paste.config(command=paste_and_analyze)

    # --- Selection handlers ---
    def on_tree_select(_=None):
        sel = tree.selection()
        if not sel or current_obj is None:
            return
        item = sel[0]
        path = tree.item(item, "values")[0]

        # find full value from current_rows
        full_value = ""
        for p, _, v in current_rows:
            if p == path:
                full_value = v
                break

        doc = _get_doc_for_path(path)

        lines = []
        lines.append(f"Параметр: {path}")
        lines.append("-" * 60)
        lines.append("Значение:")
        lines.append(full_value if full_value else "—")
        lines.append("")
        lines.append("Что это:")
        lines.append(doc.get("what", "—"))
        lines.append("")
        lines.append("Зачем нужно:")
        lines.append(doc.get("why", "—"))
        lines.append("")
        lines.append("Возможные значения:")
        lines.append(doc.get("values", "—"))
        lines.append("")
        lines.append("SOC-заметки:")
        lines.append(doc.get("soc", "—"))

        set_detail_text("\n".join(lines))

    tree.bind("<<TreeviewSelect>>", on_tree_select)

    def on_iface_select(_=None):
        sel = iface_list.curselection()
        if not sel:
            return
        i = sel[0]
        kind_sig = iface_map.get(i)
        if not kind_sig:
            return
        kind, sig = kind_sig
        name = iface_list.get(i)

        if kind == "header":
            set_iface_detail("Раздел-метка. Выберите конкретный метод или свойство ниже.")
            return

        if kind == "method":
            text = (
                f"METHOD: {name}\n"
                f"{'-'*50}\n"
                f"Сигнатура:\n{sig}\n\n"
                f"Пояснение:\n"
                f"- Это вызываемая функция COM-объекта.\n"
                f"- В SOC контексте методы важны как 'что можно сделать через объект'.\n"
                f"- Мы не расшифровываем каждую сигнатуру — здесь важен обзор возможностей.\n"
            )
            set_iface_detail(text)
        elif kind == "property":
            text = (
                f"PROPERTY: {name}\n"
                f"{'-'*50}\n"
                f"Сигнатура:\n{sig}\n\n"
                f"Пояснение:\n"
                f"- Это свойство COM-объекта (чтение/запись).\n"
                f"- Свойства, влияющие на URL/Path/Command — могут быть важны для abuse.\n"
            )
            set_iface_detail(text)

    iface_list.bind("<<ListboxSelect>>", on_iface_select)

    # --- Hotkeys: Russian layout safe (keycode based like your UAC) ---
    def _copy_entry(_=None):
        try:
            root.clipboard_clear()
            root.clipboard_append(entry.get())
        except tk.TclError:
            pass
        return "break"

    def _paste_entry(_=None):
        try:
            entry.delete(0, tk.END)
            entry.insert(0, root.clipboard_get())
        except tk.TclError:
            pass
        return "break"

    def _on_ctrl_key(event):
        # keycode 67=C, 86=V (works even in RU layout)
        if event.keycode == 67:
            return _copy_entry(event)
        if event.keycode == 86:
            _paste_entry(event)
            analyze()
            return "break"

    entry.bind("<Control-KeyPress>", _on_ctrl_key)
    entry.bind("<Return>", lambda e: (analyze(), "break"))
    entry.bind("<KP_Enter>", lambda e: (analyze(), "break"))

    # initial text
    set_report(
        "Введите CLSID и нажмите Enter.\n\n"
        "Подсказка: CLSID должен быть в формате {GUID}.\n"
        f"База: {JSON_FILE}\n"
    )
    set_detail_text("Выбери параметр в таблице слева — тут появится подробное объяснение.\n")
    set_iface_detail("Выбери метод/свойство — тут появится сигнатура.\n")

    return frame
