import os
import threading
import time
import customtkinter as ctk
from tkinter import messagebox
from PIL import Image, ImageOps

from steam_logic import SteamHandler
from network_logic import NetworkManager
from file_manager import FileManager

try:
    import windnd
    _HAS_WINDND = True
except:
    _HAS_WINDND = False

class TecnoUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.steam = SteamHandler()
        self.net = NetworkManager()
        self.fm = FileManager(".cache")

        self.title("tecno tools")
        self.geometry("1100x760")
        self.minsize(900, 600)

        self.server_bases = {
            "First Repo": "add your repo or api donot forget useing a varible {appid}",
        }

        self.steam_path = self.steam.get_steam_path()
        self.target_dir = os.path.join(self.steam_path, "config", "stplug-in") if self.steam_path else ""
        self._image_refs = {}

        self.setup_ui()

        if _HAS_WINDND:
            try:
                windnd.hook_dropfiles(self, self.handle_drop)
            except:
                pass

        self.scan_library()

    def setup_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(12, 6))

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", anchor="w")

        ctk.CTkLabel(title_frame, text="tecno tools", font=("Segoe UI", 20, "bold"), text_color="#2ecc71").pack(anchor="w")
        ctk.CTkLabel(title_frame, text="Manifest Downloader", font=("Segoe UI", 11), text_color="gray70").pack(anchor="w", pady=(2, 0))

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.pack(side="right", anchor="e")

        ctk.CTkButton(controls, text="Open Folder 📂", width=140, fg_color="#34495e", command=self.open_steam_dir).grid(row=0, column=0, padx=6)
        ctk.CTkButton(controls, text="Restart Steam ⚡", width=140, fg_color="#e67e22", command=lambda: self.steam.restart_steam(self.steam_path)).grid(row=0, column=1, padx=6)
        ctk.CTkButton(controls, text="Fix Steam", width=140, fg_color="#27ae60", command=self.fix_steam_action).grid(row=0, column=2, padx=6)

        main = ctk.CTkFrame(self)
        main.pack(fill="both", expand=True, padx=12, pady=(6, 12))

        sidebar = ctk.CTkFrame(main, width=260, fg_color="#111")
        sidebar.pack(side="left", fill="y", padx=(0, 12), pady=4)
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text="Info", font=("Segoe UI", 13, "bold")).pack(anchor="nw", pady=(10, 4), padx=10)
        self.path_lbl = ctk.CTkLabel(sidebar, text=self.steam_path or "Not Found", wraplength=220, font=("Segoe UI", 9), text_color="gray70")
        self.path_lbl.pack(anchor="nw", padx=10)

        ctk.CTkLabel(sidebar, text="Server Source", font=("Segoe UI", 12, "bold")).pack(anchor="nw", pady=(12, 4), padx=10)
        self.server_option = ctk.CTkOptionMenu(sidebar, values=list(self.server_bases.keys()), width=220)
        self.server_option.set(list(self.server_bases.keys())[0])
        self.server_option.pack(anchor="nw", padx=10, pady=(0, 8))

        content = ctk.CTkFrame(main)
        content.pack(side="left", fill="both", expand=True)

        search_frame = ctk.CTkFrame(content, fg_color="transparent")
        search_frame.pack(fill="x", padx=4, pady=(6, 10))

        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search Game...", width=640, height=44, textvariable=self.search_var)
        self.search_entry.pack(side="left", padx=(0, 8))
        self.search_entry.bind("<KeyRelease>", lambda e: self.run_search())

        status_frame = ctk.CTkFrame(content, fg_color="transparent")
        status_frame.pack(fill="x", padx=4, pady=(4, 8))

        self.progress = ctk.CTkProgressBar(status_frame, width=520)
        self.progress.set(0.0)
        self.progress.pack(side="left", padx=(0, 8))

        self.status_label = ctk.CTkLabel(status_frame, text="Ready", text_color="gray", font=("Segoe UI", 9))
        self.status_label.pack(side="left")

        self.results_frame = ctk.CTkScrollableFrame(content, fg_color="#0f0f0f")
        self.results_frame.pack(fill="both", expand=True, padx=4, pady=4)

        library_panel = ctk.CTkFrame(main, width=360, fg_color="#111")
        library_panel.pack(side="right", fill="y", padx=(12, 0), pady=4)
        library_panel.pack_propagate(False)

        ctk.CTkLabel(library_panel, text="Library", font=("Segoe UI", 13, "bold")).pack(anchor="nw", pady=(10, 4), padx=10)
        self.library_frame = ctk.CTkScrollableFrame(library_panel, fg_color="#0f0f0f")
        self.library_frame.pack(padx=10, pady=(8, 10), fill="both", expand=True)

    def fix_steam_action(self):
        url = "add here your own dll unlocker as in the dll unlocker"
        if not self.steam_path: return
        if messagebox.askyesno("Fix", "Apply Steam fix?"):
            threading.Thread(target=lambda: self.steam.download_fix_dll(self.steam_path, url), daemon=True).start()

    def handle_drop(self, files):
        count = self.fm.process_dropped_files(files, self.target_dir)
        self.status_label.configure(text=f"Imported {count} files", text_color="#2ecc71")
        self.scan_library()

    def run_search(self):
        query = self.search_var.get().strip()
        if len(query) < 2: return
        threading.Thread(target=self._exec_search, args=(query,), daemon=True).start()

    def _exec_search(self, query):
        items = self.net.search_games(query)
        self.after(0, lambda: self.display_results(items))

    def display_results(self, items):
        for w in self.results_frame.winfo_children(): w.destroy()
        for item in items:
            row = ctk.CTkFrame(self.results_frame, height=130, fg_color="#151515")
            row.pack(fill="x", padx=10, pady=8)
            
            name = item.get('name', 'Unknown')
            appid = item.get('id', '0')

            info_frame = ctk.CTkFrame(row, fg_color="transparent")
            info_frame.pack(side="left", padx=15)
            ctk.CTkLabel(info_frame, text=name, font=("Segoe UI", 12, "bold")).pack(anchor="w")
            ctk.CTkLabel(info_frame, text=f"ID: {appid}", font=("Segoe UI", 9), text_color="gray").pack(anchor="w")

            btn = ctk.CTkButton(row, text="Download", width=100, command=lambda a=appid, n=name: self.start_download(a, n))
            btn.pack(side="right", padx=15)

    def start_download(self, appid, name):
        template = self.server_bases[self.server_option.get()]
        threading.Thread(target=self._exec_download, args=(appid, name, template), daemon=True).start()

    def _exec_download(self, appid, name, template):
        url = self.net.get_manifest_url(template, appid)
        if url:
            import requests
            r = requests.get(url)
            with open(os.path.join(self.target_dir, f"{appid}.lua"), "wb") as f:
                f.write(r.content)
            self.after(0, lambda: messagebox.showinfo("Success", f"{name} Downloaded"))
            self.scan_library()
        else:
            self.after(0, lambda: messagebox.showerror("Error", "Not found on server"))

    def scan_library(self):
        for w in self.library_frame.winfo_children(): w.destroy()
        if not self.target_dir or not os.path.exists(self.target_dir): return
        
        for fname in os.listdir(self.target_dir):
            if fname.endswith(".lua"):
                card = ctk.CTkFrame(self.library_frame, fg_color="#151515")
                card.pack(fill="x", padx=5, pady=5)
                ctk.CTkLabel(card, text=fname, font=("Segoe UI", 10)).pack(side="left", padx=10, pady=5)
                ctk.CTkButton(card, text="X", width=30, fg_color="#c0392b", command=lambda f=fname: self.delete_file(f)).pack(side="right", padx=5)

    def delete_file(self, fname):
        if messagebox.askyesno("Delete", f"Remove {fname}?"):
            os.remove(os.path.join(self.target_dir, fname))
            self.scan_library()

    def open_steam_dir(self):
        if self.target_dir: os.startfile(self.target_dir)