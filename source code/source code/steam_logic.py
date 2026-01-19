import os
import winreg
import subprocess
import requests
import shutil
from datetime import datetime

class SteamHandler:
    @staticmethod
    def get_steam_path():
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam")
            path, _ = winreg.QueryValueEx(key, "SteamPath")
            return os.path.normpath(path)
        except:
            return None

    @staticmethod
    def restart_steam(steam_path):
        os.system("taskkill /f /im steam.exe")
        steam_exe = os.path.join(steam_path, "steam.exe") if steam_path else "steam.exe"
        subprocess.Popen([steam_exe])

    @staticmethod
    def download_fix_dll(steam_path, url):
        target_path = os.path.join(steam_path, "xinput1_4.dll")
        if os.path.exists(target_path):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            shutil.move(target_path, os.path.join(steam_path, f"xinput1_4.dll.bak.{ts}"))
        
        resp = requests.get(url, stream=True, timeout=20)
        with open(target_path, "wb") as f:
            for chunk in resp.iter_content(8192):
                f.write(chunk)