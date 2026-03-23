import tkinter as tk
from tkinter import ttk, messagebox
import tkinter.font as tkfont
import json
import os

TASKS_FILE = "tasks.json"
NOTES_FILE = "notes.txt"


def load_tasks():

    days = ["Понедельник", "Вторник", "Среда",
            "Четверг", "Пятница", "Суббота", "Воскресенье"]

    loaded = {}
    if os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, "r", encoding="utf-8") as file:
            try:
                data = file.read().strip()
                loaded = json.loads(data) if data else {}
            except json.JSONDecodeError:
                loaded = {}

    result = {}
    for day in days:
        v = loaded.get(day, {"todo": [], "done": []})
        if isinstance(v, list):
            result[day] = {"todo": v, "done": []}
        elif isinstance(v, dict):
            result[day] = {
                "todo": v.get("todo", []),
                "done": v.get("done", [])
            }
        else:
            result[day] = {"todo": [], "done": []}
    return result


def save_tasks(tasks):
    with open(TASKS_FILE, "w", encoding="utf-8") as file:
        json.dump(tasks, file, ensure_ascii=False)


def load_notes():
    if os.path.exists(NOTES_FILE):
        with open(NOTES_FILE, "r", encoding="utf-8") as f:
            return f.read()
    return ""


def save_notes(text):
    with open(NOTES_FILE, "w", encoding="utf-8") as f:
        f.write(text)


def create_task_manager_frame(parent_frame, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG):
    tasks = load_tasks()
    frame = tk.Frame(parent_frame, bg=FRAME_BG)

    # Шрифты
    todo_font = tkfont.Font(family="Segoe UI", size=10)
    done_font = tkfont.Font(family="Segoe UI", size=10, overstrike=1)
    day_font = tkfont.Font(family="Segoe UI", size=10, weight="bold")

    show_done = tk.BooleanVar(value=True)

    # ================= ВЕРХНЯЯ ПАНЕЛЬ ==================
    top_input = tk.Frame(frame, bg=FRAME_BG)
    top_input.pack(fill="x", padx=12, pady=(10, 0))

    day_var = tk.StringVar(value="Понедельник")
    day_menu = ttk.Combobox(
        top_input,
        values=["Понедельник", "Вторник", "Среда",
                "Четверг", "Пятница", "Суббота", "Воскресенье"],
        textvariable=day_var,
        state="readonly",
        width=16
    )
    day_menu.pack(side="left", padx=(0, 6))

    entry_task = tk.Entry(
        top_input,
        width=32,
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR,
        relief="flat",
    )
    entry_task.pack(side="left", padx=(0, 6), fill="x", expand=True, ipady=3)

    def add_task_global():
        task = entry_task.get().strip()
        if task:
            tasks[day_var.get()]["todo"].append(task)
            entry_task.delete(0, tk.END)
            save_tasks(tasks)
            refresh_tasks()

    entry_task.bind("<Return>", lambda e: add_task_global())

    tk.Button(
        top_input,
        text="Добавить",
        command=add_task_global,
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        relief="flat",
        padx=10,
        pady=2
    ).pack(side="left", padx=(0, 6))

    def toggle_show_done():
        show_done.set(not show_done.get())
        btn_show_done.config(
            text="Скрыть выполненные"
            if show_done.get() else "Показать выполненные"
        )
        refresh_tasks()

    btn_show_done = tk.Button(
        top_input,
        text="Скрыть выполненные" if show_done.get() else "Показать выполненные",
        command=toggle_show_done,
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        relief="flat",
        padx=10,
        pady=2
    )
    btn_show_done.pack(side="left")

    # ================= СЕТКА ДНЕЙ (КОЛОНКИ) ==================
    days_frame = tk.Frame(frame, bg=FRAME_BG)
    days_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # Контекст для ПКМ
    context = {"day": None, "index": None, "status": None, "label": None}
    popup = tk.Menu(frame, tearoff=0)

    def delete_task(day, index, status):
        tasks[day][status].pop(index)
        save_tasks(tasks)
        refresh_tasks()

    def delete_task_from_context():
        day = context["day"]
        idx = context["index"]
        status = context["status"]
        if day is None or idx is None or status is None:
            return
        delete_task(day, idx, status)

    def clear_day(day):
        if messagebox.askyesno("Очистить день", f"Удалить все задачи за {day}?"):
            tasks[day] = {"todo": [], "done": []}
            save_tasks(tasks)
            refresh_tasks()

    def clear_day_from_context():
        day = context["day"]
        if day is None:
            return
        clear_day(day)

    def edit_task_inline():
        day = context["day"]
        idx = context["index"]
        status = context["status"]
        lbl = context["label"]
        if day is None or idx is None or status is None or lbl is None:
            return

        old_text = tasks[day][status][idx]
        parent = lbl.master

        lbl.pack_forget()

        entry = tk.Entry(
            parent,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR,
            font=todo_font if status == "todo" else done_font,
            relief="flat"
        )
        entry.insert(0, old_text)
        entry.pack(fill="both", expand=True, padx=4, pady=4)
        entry.focus_set()

        def finish_edit(event=None):
            new_text = entry.get().strip()
            if new_text:
                tasks[day][status][idx] = new_text
                save_tasks(tasks)
            entry.destroy()
            refresh_tasks()

        entry.bind("<Return>", finish_edit)
        entry.bind("<FocusOut>", finish_edit)

    def build_popup():
        popup.delete(0, "end")
        popup.add_command(label="Изменить задачу", command=edit_task_inline)
        popup.add_separator()
        popup.add_command(label="Удалить задачу", command=delete_task_from_context)
        popup.add_separator()
        popup.add_command(label="Очистить день", command=clear_day_from_context)

    def on_task_right_click(event, day, index, status, label_widget):
        context["day"] = day
        context["index"] = index
        context["status"] = status
        context["label"] = label_widget
        build_popup()
        try:
            popup.tk_popup(event.x_root, event.y_root)
        finally:
            popup.grab_release()

    def on_check(day, index, status, var):
        if status == "todo" and var.get():
            item = tasks[day]["todo"].pop(index)
            tasks[day]["done"].append(item)
        elif status == "done" and not var.get():
            item = tasks[day]["done"].pop(index)
            tasks[day]["todo"].append(item)
        else:
            return
        save_tasks(tasks)
        refresh_tasks()

    def clear_all():
        if messagebox.askyesno("Очистить все", "Удалить задачи за всю неделю?"):
            for d in tasks:
                tasks[d] = {"todo": [], "done": []}
            save_tasks(tasks)
            refresh_tasks()

    def refresh_tasks():
        # очистка сетки
        for widget in days_frame.winfo_children():
            widget.destroy()

        # 7 равных колонок по ширине
        for col in range(7):
            days_frame.columnconfigure(col, weight=1, uniform="daycol")

        days_order = ["Понедельник", "Вторник", "Среда",
                      "Четверг", "Пятница", "Суббота", "Воскресенье"]

        for col, day in enumerate(days_order):
            day_data = tasks.get(day, {"todo": [], "done": []})
            todo_items = day_data.get("todo", [])
            done_items = day_data.get("done", [])

            # внешняя «карточка дня»
            day_outer = tk.Frame(days_frame, bg=FRAME_BG)
            day_outer.grid(row=0, column=col, padx=4, pady=4, sticky="nwe")

            # сама колонка дня
            day_card = tk.Frame(
                day_outer,
                bg=FRAME_BG,
                bd=0,
                relief="flat",
            )
            day_card.pack(fill="x", expand=False, padx=2, pady=2)

            # ----- ШАПКА ДНЯ -----
            header = tk.Frame(day_card, bg=BG_COLOR)
            header.pack(fill="x", padx=2, pady=(2, 0))

            tk.Label(
                header,
                text=day,
                bg=BG_COLOR,
                fg=TEXT_COLOR,
                font=day_font,
                anchor="w"
            ).pack(side="left", fill="x", expand=True, padx=(6, 2), pady=4)

            count_todo = len(todo_items)
            count_done = len(done_items)
            counter_text = f"{count_todo} • {count_done}"  # активные • выполненные
            tk.Label(
                header,
                text=counter_text,
                bg=BG_COLOR,
                fg="#cccccc",
                font=("Segoe UI", 8)
            ).pack(side="right", padx=(0, 6))

            # тонкая линия под шапкой
            tk.Frame(day_card, bg="#555555", height=1)\
              .pack(fill="x", padx=4, pady=(0, 4))

            # контейнер задач
            task_container = tk.Frame(day_card, bg=FRAME_BG)
            task_container.pack(fill="both", expand=True, padx=4, pady=(0, 6))

            card_bg = BG_COLOR  # «плитка» на фоне колонки
            wrap = 170  # ширина текста по строкам

            # ---- невыполненные задачи ----
            for i, task in enumerate(todo_items):
                card = tk.Frame(task_container, bg=FRAME_BG)
                card.pack(fill="x", pady=4)

                inner = tk.Frame(
                    card,
                    bg=card_bg,
                    bd=0,
                    relief="flat",
                    highlightthickness=1,
                    highlightbackground="#555555"
                )
                inner.pack(fill="both", expand=True, padx=1, pady=1)

                var = tk.BooleanVar(value=False)
                chk = tk.Checkbutton(
                    inner,
                    variable=var,
                    command=lambda d=day, idx=i, s="todo", v=var: on_check(d, idx, s, v),
                    bg=card_bg,
                    activebackground=card_bg,
                    relief="flat",
                    highlightthickness=0
                )
                chk.pack(side="left", padx=(6, 2), pady=4)

                lbl = tk.Label(
                    inner,
                    text=task,
                    bg=card_bg,
                    fg=TEXT_COLOR,
                    anchor="w",
                    justify="left",
                    wraplength=wrap,
                    font=todo_font
                )
                lbl.pack(side="left", fill="both", expand=True, padx=4, pady=4)

                # ПКМ по карточке
                for widget in (inner, lbl, card):
                    widget.bind(
                        "<Button-3>",
                        lambda e, d=day, idx=i, s="todo", lw=lbl:
                        on_task_right_click(e, d, idx, s, lw)
                    )

            # ---- выполненные задачи ----
            if show_done.get():
                for i, task in enumerate(done_items):
                    card = tk.Frame(task_container, bg=FRAME_BG)
                    card.pack(fill="x", pady=3)

                    inner = tk.Frame(
                        card,
                        bg=card_bg,
                        bd=0,
                        relief="flat",
                        highlightthickness=1,
                        highlightbackground="#444444"
                    )
                    inner.pack(fill="both", expand=True, padx=1, pady=1)

                    var = tk.BooleanVar(value=True)
                    chk = tk.Checkbutton(
                        inner,
                        variable=var,
                        command=lambda d=day, idx=i, s="done", v=var: on_check(d, idx, s, v),
                        bg=card_bg,
                        activebackground=card_bg,
                        relief="flat",
                        highlightthickness=0
                    )
                    chk.pack(side="left", padx=(6, 2), pady=4)

                    lbl = tk.Label(
                        inner,
                        text=task,
                        bg=card_bg,
                        fg="#999999",
                        anchor="w",
                        justify="left",
                        wraplength=wrap,
                        font=done_font
                    )
                    lbl.pack(side="left", fill="both", expand=True, padx=4, pady=4)

                    for widget in (inner, lbl, card):
                        widget.bind(
                            "<Button-3>",
                            lambda e, d=day, idx=i, s="done", lw=lbl:
                            on_task_right_click(e, d, idx, s, lw)
                        )

    # кнопка "Очистить все дни"
    tk.Button(
        frame,
        text="Очистить все дни",
        command=clear_all,
        bg=BTN_COLOR,
        fg=TEXT_COLOR,
        relief="flat",
        padx=12,
        pady=3
    ).pack(pady=(0, 10))

    # ================= НИЖНИЙ БЛОК: ЗАМЕТКИ ==================
    bottom = tk.Frame(frame, bg=FRAME_BG)
    bottom.pack(fill="both", padx=10, pady=10)

    notes = tk.Text(
        bottom,
        height=8,
        width=80,
        bg=FRAME_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR,
        relief="flat"
    )
    notes.insert("1.0", load_notes())
    notes.pack(side="left", fill="both", expand=True, padx=(0, 10))

    notes.bind("<FocusOut>", lambda e: save_notes(notes.get("1.0", "end").strip()))
    notes.bind("<Control-s>", lambda e: save_notes(notes.get("1.0", "end").strip()))

    refresh_tasks()
    return frame
