"""Small post-install helper for loading and registering browser extensions."""

import tkinter as tk
from tkinter import messagebox, ttk
import webbrowser

from register_native_host import APP_ROOT, register_native_host


def main():
    root = tk.Tk()
    root.title("SentinelClip Browser Setup")
    root.resizable(False, False)
    root.columnconfigure(1, weight=1)

    ttk.Label(
        root,
        text="Load the unpacked extension in each browser first, then enter its ID.",
        wraplength=450,
    ).grid(row=0, column=0, columnspan=2, padx=16, pady=(16, 10), sticky="w")
    ttk.Label(root, text="Extension folder:").grid(row=1, column=0, padx=16, sticky="w")
    ttk.Label(root, text=str(APP_ROOT / "browser_extension"), wraplength=400).grid(
        row=1, column=1, padx=8, sticky="w"
    )

    chrome_id = tk.StringVar()
    edge_id = tk.StringVar()
    ttk.Label(root, text="Chrome ID:").grid(row=2, column=0, padx=16, pady=(14, 4), sticky="w")
    ttk.Entry(root, textvariable=chrome_id, width=44).grid(
        row=2, column=1, padx=8, pady=(14, 4), sticky="ew"
    )
    ttk.Label(root, text="Edge ID:").grid(row=3, column=0, padx=16, pady=4, sticky="w")
    ttk.Entry(root, textvariable=edge_id, width=44).grid(
        row=3, column=1, padx=8, pady=4, sticky="ew"
    )

    buttons = ttk.Frame(root)
    buttons.grid(row=4, column=0, columnspan=2, padx=16, pady=16, sticky="ew")
    ttk.Button(
        buttons,
        text="Open Chrome Extensions",
        command=lambda: webbrowser.open("chrome://extensions"),
    ).pack(side="left")
    ttk.Button(
        buttons,
        text="Open Edge Extensions",
        command=lambda: webbrowser.open("edge://extensions"),
    ).pack(side="left", padx=(8, 0))

    def register():
        try:
            browsers = register_native_host(chrome_id.get(), edge_id.get())
        except (OSError, ValueError) as exc:
            messagebox.showerror("Browser setup failed", str(exc), parent=root)
            return
        messagebox.showinfo(
            "Browser setup complete",
            "Native messaging registered for " + ", ".join(browsers) + ". Restart the browser to apply it.",
            parent=root,
        )

    ttk.Button(root, text="Register Native Host", command=register).grid(
        row=5, column=0, columnspan=2, padx=16, pady=(0, 16), sticky="e"
    )
    root.mainloop()


if __name__ == "__main__":
    main()