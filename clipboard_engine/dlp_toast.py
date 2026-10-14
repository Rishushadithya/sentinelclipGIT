"""
SentinelClip — Desktop DLP Toast Notification

Displays a modern Windows 11 style Data Loss Prevention notification card
in the bottom-right corner of the desktop, matching enterprise DLP alerts.
Mentions the specific violation, source, and action taken.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import tkinter as tk
from typing import Optional


# Mapping of policy rule names to user-friendly classification categories
RULE_CLASSIFICATIONS = {
    "Credit Card Number": "Financial data",
    "Password Assignment": "Credentials / Passwords",
    "AWS Access Key": "Cloud API credentials",
    "Generic API Key": "Secret API keys",
    "JWT Token": "Authentication tokens",
    "NIC / National ID (LK)": "Government identification",
    "Private IP Address": "Internal network infrastructure",
    "Public IP Address": "Network IP address",
    "Email Address": "Personal email address",
    "Company Email Address": "Company email address",
}


def get_violation_category(rule_name: str) -> str:
    """Return friendly category for a policy rule."""
    return RULE_CLASSIFICATIONS.get(rule_name, "Sensitive data")


def show_dlp_toast(
    rule_name: str,
    action: str = "BLOCK",
    source_filename: Optional[str] = None,
    detail: Optional[str] = None,
    timeout: int = 8,
) -> None:
    """
    Spawn a non-blocking modern DLP toast notification at the bottom right.
    
    Args:
        rule_name: The name of the violated rule (e.g. 'Credit Card Number').
        action: The action taken ('BLOCK', 'WARN', 'REDACT', 'OBFUSCATE').
        source_filename: Optional filename if a file was copied (e.g. 'Cards.docx').
        detail: Optional extra details (e.g. masked preview or severity).
        timeout: Seconds before auto-dismissing.
    """
    thread = threading.Thread(
        target=_run_toast_window,
        args=(rule_name, action, source_filename, detail, timeout),
        daemon=True,
    )
    thread.start()


def _run_toast_window(
    rule_name: str,
    action: str,
    source_filename: Optional[str],
    detail: Optional[str],
    timeout: int,
) -> None:
    """Internal runner for the Tkinter toast window in a background thread."""
    try:
        root = tk.Tk()
        root.title("SentinelClip DLP")
        root.overrideredirect(True)
        root.attributes("-topmost", True)
        
        # Colors
        bg_dark = "#172033"
        card_border = "#2e3b52"
        text_primary = "#f8fafc"
        text_muted = "#94a3b8"
        text_body = "#cbd5e1"
        btn_bg = "#232e44"
        btn_hover = "#303d59"
        btn_border = "#374663"

        root.configure(bg=card_border)

        # Window dimensions
        width = 370
        height = 340

        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()

        # Position at bottom-right above taskbar
        margin_x = 24
        margin_y = 64
        x = screen_w - width - margin_x
        y = screen_h - height - margin_y
        root.geometry(f"{width}x{height}+{x}+{y}")

        # Inner container with 1px border margin
        inner = tk.Frame(root, bg=bg_dark, bd=0)
        inner.pack(fill="both", expand=True, padx=1, pady=1)

        # -------------------------------------------------------------------
        # Top Graphic: 3D Shield & Document Illustration (Canvas)
        # -------------------------------------------------------------------
        canvas_h = 130
        canvas = tk.Canvas(inner, width=width - 2, height=canvas_h, bg=bg_dark, highlightthickness=0)
        canvas.pack(fill="x", pady=(8, 0))

        # Circular backdrop glow
        canvas.create_oval(115, 10, 255, 120, fill="#1e293b", outline="")

        # Draw Folder / Document on right
        # Back folder flap
        canvas.create_polygon(180, 45, 230, 45, 240, 55, 265, 55, 265, 105, 180, 105, fill="#475569", outline="#64748b", width=1)
        # White document sticking out
        canvas.create_polygon(195, 30, 245, 30, 255, 42, 255, 85, 195, 85, fill="#f1f5f9", outline="#cbd5e1", width=1)
        # Document lines
        canvas.create_line(205, 46, 235, 46, fill="#94a3b8", width=2)
        canvas.create_line(205, 56, 240, 56, fill="#94a3b8", width=2)
        canvas.create_line(205, 66, 230, 66, fill="#94a3b8", width=2)
        # Front folder flap
        canvas.create_polygon(175, 55, 265, 55, 265, 105, 175, 105, fill="#64748b", outline="#94a3b8", width=1)

        # Draw 3D Golden/Yellow Shield in front on left
        # Shield shadow
        canvas.create_polygon(120, 35, 165, 35, 170, 75, 142, 110, 115, 75, fill="#0f172a", outline="")
        # Outer shield
        canvas.create_polygon(122, 32, 168, 32, 172, 72, 145, 108, 118, 72, fill="#d97706", outline="")
        # Shield left facet (lighter gold)
        canvas.create_polygon(125, 35, 145, 35, 145, 104, 120, 70, fill="#fbbf24", outline="")
        # Shield right facet (rich amber)
        canvas.create_polygon(145, 35, 165, 35, 168, 70, 145, 104, fill="#f59e0b", outline="")
        # Highlight gloss on shield
        canvas.create_line(128, 40, 138, 70, fill="#fef08a", width=2)

        # -------------------------------------------------------------------
        # Header line: Shield icon + "Data Loss Prevention" + close 'X'
        # -------------------------------------------------------------------
        header_frame = tk.Frame(inner, bg=bg_dark)
        header_frame.pack(fill="x", padx=16, pady=(4, 6))

        title_lbl = tk.Label(
            header_frame,
            text="SENTINELCLIP // DATA LOSS PREVENTION",
            bg=bg_dark,
            fg=text_muted,
            font=("Segoe UI", 9, "bold"),
        )
        title_lbl.pack(side="left")

        def close_window():
            try:
                root.destroy()
            except Exception:
                pass

        close_btn = tk.Label(
            header_frame,
            text="✕",
            bg=bg_dark,
            fg="#64748b",
            font=("Segoe UI", 10),
            cursor="hand2",
        )
        close_btn.pack(side="right")
        close_btn.bind("<Button-1>", lambda e: close_window())
        close_btn.bind("<Enter>", lambda e: close_btn.configure(fg=text_primary))
        close_btn.bind("<Leave>", lambda e: close_btn.configure(fg="#64748b"))

        # -------------------------------------------------------------------
        # Warning Headline
        # -------------------------------------------------------------------
        is_block = (action.upper() in ("BLOCK", "REDACT", "OBFUSCATE"))
        headline_text = "[SECURITY BLOCK] Operation Not Permitted" if is_block else "[SECURITY WARNING] Sensitive Data Detected"

        headline_lbl = tk.Label(
            inner,
            text=headline_text,
            bg=bg_dark,
            fg=text_primary,
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        )
        headline_lbl.pack(fill="x", padx=16, pady=(2, 4))

        # -------------------------------------------------------------------
        # Violation Description Text (Mentioning what violation occurred!)
        # -------------------------------------------------------------------
        category = get_violation_category(rule_name)

        if source_filename:
            body_text = (
                f"{category} copy detected in {source_filename}\n"
                f"Violation: {rule_name} — Action: Blocked"
                if is_block else
                f"{category} detected in {source_filename}\n"
                f"Violation: {rule_name} — Proceed with caution"
            )
        else:
            body_text = (
                f"{category} copy to clipboard detected\n"
                f"Violation: {rule_name} — Action: Blocked"
                if is_block else
                f"{category} copy to clipboard detected\n"
                f"Violation: {rule_name} — Proceed with caution"
            )

        if detail:
            body_text += f"\n({detail})"

        msg_lbl = tk.Label(
            inner,
            text=body_text,
            bg=bg_dark,
            fg=text_body,
            font=("Segoe UI", 9),
            justify="left",
            anchor="w",
            wraplength=width - 32,
        )
        msg_lbl.pack(fill="x", padx=16, pady=(2, 12))

        # -------------------------------------------------------------------
        # Dismiss Button
        # -------------------------------------------------------------------
        btn_frame = tk.Frame(inner, bg=bg_dark)
        btn_frame.pack(fill="x", padx=16, pady=(0, 14), side="bottom")

        dismiss_btn = tk.Button(
            btn_frame,
            text="Dismiss",
            bg=btn_bg,
            fg=text_primary,
            activebackground=btn_hover,
            activeforeground=text_primary,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=btn_border,
            highlightcolor=btn_border,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
            command=close_window,
            pady=6,
        )
        dismiss_btn.pack(fill="x")

        dismiss_btn.bind("<Enter>", lambda e: dismiss_btn.configure(bg=btn_hover))
        dismiss_btn.bind("<Leave>", lambda e: dismiss_btn.configure(bg=btn_bg))

        # Auto-dismiss after timeout
        root.after(int(timeout * 1000), close_window)

        root.mainloop()
    except Exception as exc:
        print(f"[SentinelClip DLP Toast Error]: {exc}", file=sys.stderr)


if __name__ == "__main__":
    # Test notification
    show_dlp_toast("Credit Card Number", action="BLOCK", source_filename="Cards.docx")
    time.sleep(3)
