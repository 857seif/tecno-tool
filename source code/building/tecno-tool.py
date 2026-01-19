import os
import re
import winreg
import requests
import threading
import subprocess
import shutil
import customtkinter as ctk
from tkinter import messagebox
import windnd
import time
from datetime import datetime


try:
    import pyperclip
    _HAS_PYPERCLIP = True
except Exception:
    pyperclip = None
    _HAS_PYPERCLIP = False


try:
    from PIL import Image, ImageOps
    _HAS_PIL = True
except Exception:
    Image = None
    ImageOps = None
    _HAS_PIL = False


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

APP_FONT = ("Segoe UI", 11)
TITLE_FONT = ("Segoe UI", 20, "bold")
SMALL_FONT = ("Segoe UI", 9)


COVER_SIZE = 120


class tecnoPro(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("tecno tools")
        self.geometry("1100x760")
        self.minsize(900, 600)


        self.server_bases = {
            "First Repo": "add your repo or api donot forget useing a varible {appid}",
        }


        self.steam_path = self.get_steam_path()
        self.target_dir = os.path.join(self.steam_path, "config", "stplug-in") if self.steam_path else ""


        self.cache_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), ".cache")
        os.makedirs(self.cache_dir, exist_ok=True)


        self._image_refs = {}

        self.setup_ui()


        try:
            windnd.hook_dropfiles(self, self.handle_drop)
        except Exception:
            pass


        self.scan_library()

    def get_steam_path(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam")
            path, _ = winreg.QueryValueEx(key, "SteamPath")
            return os.path.normpath(path)
        except Exception:
            return None

    def setup_ui(self):

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(12, 6))

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", anchor="w")

        self.title_lbl = ctk.CTkLabel(title_frame, text="tecno tools", font=TITLE_FONT, text_color="#2ecc71")
        self.title_lbl.pack(anchor="w")
        ctk.CTkLabel(title_frame, text="Manifest Downloader", font=APP_FONT, text_color="gray70").pack(anchor="w", pady=(2, 0))

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.pack(side="right", anchor="e")

        self.open_folder_btn = ctk.CTkButton(controls, text="Open Folder 📂", width=140, fg_color="#34495e", command=self.open_steam_dir)
        self.open_folder_btn.grid(row=0, column=0, padx=6)
        self.restart_btn = ctk.CTkButton(controls, text="Restart Steam ⚡", width=140, fg_color="#e67e22", command=self.restart_steam)
        self.restart_btn.grid(row=0, column=1, padx=6)


        self.fix_btn = ctk.CTkButton(controls, text="Fix Steam", width=140, fg_color="#27ae60", command=self.fix_steam)
        self.fix_btn.grid(row=0, column=2, padx=6)


        main = ctk.CTkFrame(self)
        main.pack(fill="both", expand=True, padx=12, pady=(6, 12))


        sidebar = ctk.CTkFrame(main, width=260, fg_color="#111")
        sidebar.pack(side="left", fill="y", padx=(0, 12), pady=4)
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text="Info", font=("Segoe UI", 13, "bold")).pack(anchor="nw", pady=(10, 4), padx=10)
        steam_path_text = self.steam_path if self.steam_path else "Steam path not found"
        self.path_lbl = ctk.CTkLabel(sidebar, text=steam_path_text, wraplength=220, font=SMALL_FONT, text_color="gray70")
        self.path_lbl.pack(anchor="nw", padx=10)

        ctk.CTkLabel(sidebar, text="Server Source", font=("Segoe UI", 12, "bold")).pack(anchor="nw", pady=(12, 4), padx=10)
        self.server_option = ctk.CTkOptionMenu(sidebar, values=list(self.server_bases.keys()), width=220)
        self.server_option.set(list(self.server_bases.keys())[0])
        self.server_option.pack(anchor="nw", padx=10, pady=(0, 8))

        ctk.CTkLabel(sidebar, text="Drag & Drop", font=("Segoe UI", 12, "bold")).pack(anchor="nw", pady=(8, 4), padx=10)
        ctk.CTkLabel(sidebar, text="Drop .lua files or folders anywhere on the window to import.", wraplength=220, font=SMALL_FONT, text_color="gray70").pack(anchor="nw", padx=10)


        content = ctk.CTkFrame(main)
        content.pack(side="left", fill="both", expand=True)

        search_frame = ctk.CTkFrame(content, fg_color="transparent")
        search_frame.pack(fill="x", padx=4, pady=(6, 10))

        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search Game Name or ID...", width=640, height=44, textvariable=self.search_var, font=APP_FONT)
        self.search_entry.pack(side="left", padx=(0, 8), pady=2)
        self.search_entry.bind("<KeyRelease>", self.on_key_release)

        self.search_btn = ctk.CTkButton(search_frame, text="Search 🔎", width=120, command=lambda: self.perform_search(self.search_var.get().strip()))
        self.search_btn.pack(side="left", padx=(0, 6))

        status_frame = ctk.CTkFrame(content, fg_color="transparent")
        status_frame.pack(fill="x", padx=4, pady=(4, 8))

        self.progress = ctk.CTkProgressBar(status_frame, width=520)
        self.progress.set(0.0)
        self.progress.pack(side="left", padx=(0, 8))

        self.status_label = ctk.CTkLabel(status_frame, text="Ready", text_color="gray", font=SMALL_FONT)
        self.status_label.pack(side="left", padx=(6, 0))


        result_height = max(88, COVER_SIZE + 16)
        self.results_frame = ctk.CTkScrollableFrame(content, width=640, height=520, fg_color="#0f0f0f")
        self.results_frame.pack(fill="both", expand=True, padx=4, pady=4)


        library_panel = ctk.CTkFrame(main, width=360, fg_color="#111")
        library_panel.pack(side="right", fill="y", padx=(12, 0), pady=4)
        library_panel.pack_propagate(False)

        ctk.CTkLabel(library_panel, text="Library", font=("Segoe UI", 13, "bold")).pack(anchor="nw", pady=(10, 4), padx=10)
        ctk.CTkLabel(library_panel, text="Local .lua files in Steam config/stplug-in", font=SMALL_FONT, text_color="gray70", wraplength=320).pack(anchor="nw", padx=10)


        self.library_frame = ctk.CTkScrollableFrame(library_panel, width=340, height=620, fg_color="#0f0f0f")
        self.library_frame.pack(padx=10, pady=(8, 10), fill="both", expand=True)


        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(fill="x", padx=12, pady=(4, 8))
        ctk.CTkLabel(footer, text="Tip: Drag folders or .lua files onto the app to copy them into Steam config. Use Library to manage local .lua files.", font=SMALL_FONT, text_color="gray60").pack(anchor="w")


    def fix_steam(self):

        dll_url = "add here your own dll unlocker as in the dll unlocker"
        if not self.steam_path:
            messagebox.showerror("Steam Path Not Found", "Steam path not detected in registry. Cannot fix Steam.")
            return

        if not messagebox.askyesno("Fix Steam", f"this will fix steam:\n\n{self.steam_path}\n\nProceed?"):
            return


        threading.Thread(target=self._download_and_place_dll, args=(dll_url,), daemon=True).start()

    def _download_and_place_dll(self, url):
        try:
            self.after(0, lambda: self.status_label.configure(text="Downloading fix...", text_color="yellow"))
            resp = requests.get(url, stream=True, timeout=20)
            if resp.status_code != 200:
                self.after(0, lambda: messagebox.showerror("Download Failed", f"Failed to download file (status {resp.status_code})."))
                self.after(0, lambda: self.status_label.configure(text="Fix failed", text_color="red"))
                return


            target_path = os.path.join(self.steam_path, "xinput1_4.dll")

            if os.path.exists(target_path):
                try:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_name = f"xinput1_4.dll.bak.{ts}"
                    backup_path = os.path.join(self.steam_path, backup_name)
                    shutil.move(target_path, backup_path)
                except Exception:

                    pass


            try:
                with open(target_path, "wb") as fh:
                    for chunk in resp.iter_content(8192):
                        if chunk:
                            fh.write(chunk)
            except PermissionError:

                self.after(0, lambda: messagebox.showerror(
                    "Permission Error",
                    f"Could not write to {self.steam_path}. Try running the app as Administrator."
                ))
                self.after(0, lambda: self.status_label.configure(text="Fix failed (permission)", text_color="red"))
                return
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Write Error", f"Failed to save file: {e}"))
                self.after(0, lambda: self.status_label.configure(text="Fix failed", text_color="red"))
                return


            self.after(0, lambda: messagebox.showinfo("Success", f"steam fixed enjoy "))
            self.after(0, lambda: self.status_label.configure(text="Fix applied", text_color="#2ecc71"))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Failed to apply fix: {e}"))
            self.after(0, lambda: self.status_label.configure(text="Fix failed", text_color="red"))


    def handle_drop(self, files):
        threading.Thread(target=self._process_drop, args=(files,), daemon=True).start()

    def _process_drop(self, files):
        try:
            added_count = 0
            if not self.target_dir:
                self.after(0, lambda: messagebox.showerror("Error", "Steam path not found!"))
                return

            os.makedirs(self.target_dir, exist_ok=True)
            all_lua_files = []

            for path in files:
                try:
                    path_str = path.decode('utf-8') if isinstance(path, bytes) else path
                except Exception:
                    continue

                if os.path.isdir(path_str):
                    for root, _, filenames in os.walk(path_str):
                        for f in filenames:
                            if f.lower().endswith(".lua"):
                                all_lua_files.append(os.path.join(root, f))
                elif path_str.lower().endswith(".lua"):
                    all_lua_files.append(path_str)

            for file_path in all_lua_files:
                try:
                    file_name = os.path.basename(file_path)
                    destination = os.path.join(self.target_dir, file_name)
                    shutil.copy2(file_path, destination)
                    added_count += 1
                except Exception:
                    continue

            if added_count > 0:
                self.after(0, lambda: self.status_label.configure(text=f"Imported {added_count} .lua files", text_color="#2ecc71"))
            else:
                self.after(0, lambda: self.status_label.configure(text="No .lua files found in dropped items", text_color="gray70"))

            self.scan_library()
        except Exception:
            self.after(0, lambda: self.status_label.configure(text="Drop failed (see console)", text_color="red"))


    def scan_library(self):
        threading.Thread(target=self._scan_library_thread, daemon=True).start()

    def _scan_library_thread(self):
        try:
            files = []
            if self.target_dir and os.path.exists(self.target_dir):
                for fname in os.listdir(self.target_dir):
                    if fname.lower().endswith(".lua"):
                        files.append(fname)
            files.sort()
            self.after(0, lambda: self._populate_library(files))
        except Exception:
            self.after(0, lambda: self.status_label.configure(text="Failed to scan library", text_color="red"))

    def _populate_library(self, files):

        for w in self.library_frame.winfo_children():
            w.destroy()

        lib_image_refs = {}


        for fname in files:
            card = ctk.CTkFrame(self.library_frame, corner_radius=10, fg_color="#151515")
            card.pack(fill="x", padx=6, pady=8)


            img_container = ctk.CTkFrame(card, width=COVER_SIZE, height=COVER_SIZE, fg_color="transparent")
            img_container.pack(pady=(12, 6))
            img_container.pack_propagate(False)

            initial = (fname[0] if fname else "?").upper()
            icon_lbl = ctk.CTkLabel(img_container, text=initial, width=COVER_SIZE, height=COVER_SIZE, corner_radius=8, fg_color="#2b2b2b", font=("Segoe UI", max(10, int(COVER_SIZE/6)), "bold"))
            icon_lbl.pack(expand=True)


            title_lbl = ctk.CTkLabel(card, text=fname, anchor="center", font=("Segoe UI", 11, "bold"), wraplength=300)
            title_lbl.pack(pady=(6, 4))


            btns = ctk.CTkFrame(card, fg_color="transparent")
            btns.pack(pady=(4, 12))

            del_btn = ctk.CTkButton(btns, text="Delete", width=int(COVER_SIZE * 0.9), height=34, fg_color="#c0392b", command=lambda f=fname: self._confirm_delete(f))
            del_btn.pack(pady=(0, 6))

            open_btn = ctk.CTkButton(btns, text="Open", width=int(COVER_SIZE * 0.9), height=34, fg_color="#3b8ed0", command=lambda f=fname: self._open_local_file_folder(f))
            open_btn.pack()


            appid = self._extract_appid_from_filename(fname)
            if _HAS_PIL and appid:
                threading.Thread(target=self._load_cover_for_local, args=(appid, icon_lbl, lib_image_refs), daemon=True).start()


        self._image_refs['library'] = lib_image_refs

    def _extract_appid_from_filename(self, fname):
        nums = re.findall(r'\d{2,}', fname)
        if nums:
            return nums[0]
        return ""

    def _open_local_file_folder(self, fname):
        try:
            if not self.target_dir:
                messagebox.showwarning("Steam Not Found", "Steam path not detected.")
                return
            file_path = os.path.join(self.target_dir, fname)
            if os.path.exists(file_path):
                os.startfile(os.path.dirname(file_path))
            else:
                messagebox.showinfo("Not Found", f"{fname} not found in plugin folder.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {e}")

    def _confirm_delete(self, fname):
        if messagebox.askyesno("Delete", f"Delete {fname}?"):
            threading.Thread(target=self._delete_file_thread, args=(fname,), daemon=True).start()

    def _delete_file_thread(self, fname):
        try:
            file_path = os.path.join(self.target_dir, fname)
            if os.path.exists(file_path):
                os.remove(file_path)
                appid = self._extract_appid_from_filename(fname)
                if appid:
                    cache_path = os.path.join(self.cache_dir, f"{appid}.jpg")
                    try:
                        if os.path.exists(cache_path):
                            os.remove(cache_path)
                    except Exception:
                        pass
                self.after(0, lambda: self.status_label.configure(text=f"Deleted {fname}", text_color="#2ecc71"))
            else:
                self.after(0, lambda: self.status_label.configure(text=f"{fname} not found", text_color="red"))

            self.scan_library()
        except Exception:
            self.after(0, lambda: self.status_label.configure(text="Delete failed", text_color="red"))

    def _load_cover_for_local(self, appid, icon_label, refs_dict):
        try:
            cache_path = os.path.join(self.cache_dir, f"{appid}.jpg")
            if not os.path.exists(cache_path):
                info_url = f"https://store.steampowered.com/api/appdetails?appids={appid}&l=english"
                try:
                    resp = requests.get(info_url, timeout=6)
                    data = resp.json() if resp.ok else None
                    if data and str(appid) in data:
                        appdata = data.get(str(appid), {})
                        if appdata.get("success"):
                            header = appdata.get("data", {}).get("header_image")
                            if header:
                                try:
                                    rimg = requests.get(header, stream=True, timeout=8)
                                    if rimg.status_code == 200:
                                        with open(cache_path, "wb") as fh:
                                            for chunk in rimg.iter_content(1024):
                                                fh.write(chunk)
                                except Exception:
                                    pass
                except Exception:
                    pass

            if os.path.exists(cache_path):
                try:
                    img = Image.open(cache_path).convert("RGBA")
                    contained = ImageOps.contain(img, (COVER_SIZE, COVER_SIZE), Image.LANCZOS)
                    bg = Image.new("RGBA", (COVER_SIZE, COVER_SIZE), (0, 0, 0, 0))
                    x = (COVER_SIZE - contained.width) // 2
                    y = (COVER_SIZE - contained.height) // 2
                    bg.paste(contained, (x, y), contained)
                    ctk_img = ctk.CTkImage(light_image=bg, dark_image=bg, size=(COVER_SIZE, COVER_SIZE))

                    def apply_image():
                        try:
                            icon_label.configure(image=ctk_img, text="")
                            refs_dict[icon_label] = ctk_img
                        except Exception:
                            pass

                    self.after(0, apply_image)
                except Exception:
                    pass
        except Exception:
            pass


    def on_key_release(self, event):
        query = self.search_var.get().strip()
        if len(query) < 2:
            return
        threading.Thread(target=self.search_steam, args=(query,), daemon=True).start()

    def perform_search(self, query):
        if not query or len(query) < 2:
            self.status_label.configure(text="Type at least 2 characters to search", text_color="gray70")
            return
        threading.Thread(target=self.search_steam, args=(query,), daemon=True).start()

    def search_steam(self, query):
        try:
            self.after(0, lambda: self.status_label.configure(text=f"Searching for: {query}", text_color="yellow"))
            url = f"https://store.steampowered.com/api/storesearch/?term={requests.utils.quote(query)}&l=english&cc=US"
            resp = requests.get(url, timeout=6)
            data = resp.json() if resp.ok else None
            items = data.get('items') if data else None
            if items:
                self.after(0, self.display_results, items)
                self.after(0, lambda: self.status_label.configure(text=f"Found {len(items)} results", text_color="#2ecc71"))
            else:
                self.after(0, lambda: self.status_label.configure(text="No results found", text_color="gray70"))
                self.after(0, lambda: self.clear_results())
        except Exception:
            self.after(0, lambda: self.status_label.configure(text="Search failed", text_color="red"))

    def clear_results(self):
        for w in self.results_frame.winfo_children():
            w.destroy()
        self._image_refs.pop('results', None)

    def display_results(self, items):
        self.clear_results()
        results_refs = {}
        for item in items:
            name = item.get('name') or "Unknown"
            appid = item.get('id') or item.get('appid') or "0"

            result_row_height = max(88, COVER_SIZE + 16)
            result_row = ctk.CTkFrame(self.results_frame, height=result_row_height, corner_radius=8, fg_color="#151515")
            result_row.pack(fill="x", padx=10, pady=8)

            icon_container = ctk.CTkFrame(result_row, width=COVER_SIZE, height=COVER_SIZE, fg_color="transparent")
            icon_container.pack(side="left", padx=10, pady=8)
            icon_container.pack_propagate(False)

            initial = (name[0] if name else "?").upper()
            icon_lbl = ctk.CTkLabel(icon_container, text=initial, width=COVER_SIZE, height=COVER_SIZE, corner_radius=8, fg_color="#2b2b2b", font=("Segoe UI", int(COVER_SIZE/5), "bold"))
            icon_lbl.pack(expand=True)

            text_frame = ctk.CTkFrame(result_row, fg_color="transparent")
            text_frame.pack(side="left", fill="both", expand=True, padx=(12, 8))

            title_lbl = ctk.CTkLabel(text_frame, text=name, anchor="w", font=("Segoe UI", 12, "bold"))
            title_lbl.pack(fill="x")
            id_lbl = ctk.CTkLabel(text_frame, text=f"ID: {appid}", anchor="w", font=SMALL_FONT, text_color="gray70")
            id_lbl.pack(fill="x", pady=(6, 0))

            btn_frame = ctk.CTkFrame(result_row, fg_color="transparent")
            btn_frame.pack(side="right", padx=8, pady=8)

            dl_btn = ctk.CTkButton(btn_frame, text="Download", width=120, height=36, command=lambda a=appid, n=name: self.download_manifest(a, n))
            dl_btn.pack(pady=(4, 8))

            open_btn = ctk.CTkButton(btn_frame, text="Open Folder", width=120, height=36, fg_color="#3b8ed0", command=lambda a=appid: self.open_item_folder(a))
            open_btn.pack(pady=(0, 8))

            copy_btn = ctk.CTkButton(btn_frame, text="Copy ID", width=120, height=36, fg_color="#555", command=lambda a=appid: self.copy_id(a))
            copy_btn.pack()

            if _HAS_PIL:
                threading.Thread(target=self._load_and_set_cover, args=(appid, icon_lbl, results_refs), daemon=True).start()

        self._image_refs['results'] = results_refs

    def _load_and_set_cover(self, appid, icon_label, refs_dict):
        try:
            cache_path = os.path.join(self.cache_dir, f"{appid}.jpg")
            if not os.path.exists(cache_path):
                info_url = f"https://store.steampowered.com/api/appdetails?appids={appid}&l=english"
                try:
                    resp = requests.get(info_url, timeout=6)
                    data = resp.json() if resp.ok else None
                    if data and str(appid) in data:
                        appdata = data.get(str(appid), {})
                        if appdata.get("success"):
                            header = appdata.get("data", {}).get("header_image")
                            if header:
                                try:
                                    rimg = requests.get(header, stream=True, timeout=8)
                                    if rimg.status_code == 200:
                                        with open(cache_path, "wb") as fh:
                                            for chunk in rimg.iter_content(1024):
                                                fh.write(chunk)
                                except Exception:
                                    pass
                except Exception:
                    pass

            if os.path.exists(cache_path):
                try:
                    img = Image.open(cache_path).convert("RGBA")
                    contained = ImageOps.contain(img, (COVER_SIZE, COVER_SIZE), Image.LANCZOS)
                    bg = Image.new("RGBA", (COVER_SIZE, COVER_SIZE), (0, 0, 0, 0))
                    x = (COVER_SIZE - contained.width) // 2
                    y = (COVER_SIZE - contained.height) // 2
                    bg.paste(contained, (x, y), contained)
                    ctk_img = ctk.CTkImage(light_image=bg, dark_image=bg, size=(COVER_SIZE, COVER_SIZE))

                    def apply_image():
                        try:
                            icon_label.configure(image=ctk_img, text="")
                            refs_dict[icon_label] = ctk_img
                        except Exception:
                            pass

                    self.after(0, apply_image)
                except Exception:
                    pass
        except Exception:
            pass


    def open_steam_dir(self):
        try:
            if not self.steam_path:
                messagebox.showwarning("Steam Not Found", "Steam path not detected.")
                return
            if not os.path.exists(self.target_dir):
                os.makedirs(self.target_dir, exist_ok=True)
            os.startfile(self.target_dir)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {e}")

    def restart_steam(self):
        try:
            os.system("taskkill /f /im steam.exe")
            steam_exe = os.path.join(self.steam_path, "steam.exe") if self.steam_path else "steam.exe"
            subprocess.Popen([steam_exe])
            self.status_label.configure(text="Steam restarted", text_color="#2ecc71")
        except Exception:
            self.status_label.configure(text="Could not restart Steam", text_color="red")

    def copy_id(self, appid):
        text = str(appid)
        if _HAS_PYPERCLIP:
            try:
                pyperclip.copy(text)
                self.status_label.configure(text=f"Copied {appid} to clipboard", text_color="#2ecc71")
                return
            except Exception:
                pass

        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
            self.status_label.configure(text=f"Copied {appid} to clipboard", text_color="#2ecc71")
        except Exception:
            self.status_label.configure(text="Could not copy to clipboard", text_color="red")

    def open_item_folder(self, appid):
        try:
            if not self.target_dir:
                messagebox.showwarning("Steam Not Found", "Steam path not detected.")
                return
            file_path = os.path.join(self.target_dir, f"{appid}.lua")
            if os.path.exists(file_path):
                folder = os.path.dirname(file_path)
                os.startfile(folder)
            else:
                messagebox.showinfo("Not Found", f"{appid}.lua not found in plugin folder.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {e}")

    def download_manifest(self, appid, name):
        selected_server = self.server_option.get()
        url_template = self.server_bases[selected_server]
        self.status_label.configure(text=f"Searching for {name} manifest...", text_color="yellow")
        self.progress.set(0.0)

        def run_download():
            branches = ["main", "master"]
            success = False
            for branch in branches:
                final_url = url_template.format(branch=branch, appid=appid)
                try:
                    r = requests.get(final_url, stream=True, timeout=10)
                    if r.status_code == 200:
                        if not os.path.exists(self.target_dir):
                            os.makedirs(self.target_dir, exist_ok=True)
                        file_path = os.path.join(self.target_dir, f"{appid}.lua")

                        total = r.headers.get('content-length')
                        if total is None:
                            with open(file_path, "wb") as f:
                                f.write(r.content)
                            self.after(0, lambda: self.progress.set(1.0))
                        else:
                            total = int(total)
                            chunk_size = 8192
                            written = 0
                            with open(file_path, "wb") as f:
                                for chunk in r.iter_content(chunk_size=chunk_size):
                                    if chunk:
                                        f.write(chunk)
                                        written += len(chunk)
                                        progress_val = min(1.0, written / total)
                                        self.after(0, lambda v=progress_val: self.progress.set(v))

                        self.after(0, lambda: messagebox.showinfo("Success", f"File saved: {appid}.lua"))
                        self.after(0, lambda: self.status_label.configure(text="Download Success!", text_color="#2ecc71"))
                        success = True
                        break
                except Exception:
                    continue

            if not success:
                self.after(0, lambda: messagebox.showerror("Not Found", "Manifest file not found on this server."))
                self.after(0, lambda: self.status_label.configure(text="Download Failed", text_color="red"))
                self.after(0, lambda: self.progress.set(0.0))
            else:
                self.scan_library()
                time.sleep(0.25)
                self.after(0, lambda: self.progress.set(0.0))

        threading.Thread(target=run_download, daemon=True).start()


if __name__ == "__main__":
    app = tecnoPro()
    app.mainloop()