import tkinter as tk

def create_googlecalendar_frame(root, parent_frame, BG_COLOR, BTN_COLOR, TEXT_COLOR, FRAME_BG, OUTPUT_BG):
    frame = tk.Frame(parent_frame, bg=FRAME_BG)
    
    tk.Label(frame, text="Google Calendar интеграция в разработке...",
             bg=FRAME_BG, fg=TEXT_COLOR, font=("Arial", 12, "bold")).pack(padx=10, pady=10)

    return frame
