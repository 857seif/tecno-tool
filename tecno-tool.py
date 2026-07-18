import sys, os, json, zipfile, tempfile, shutil, subprocess, urllib3, requests, ssl, uuid, re
from pathlib import Path
from io import BytesIO
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QScrollArea, QFrame, QGridLayout,
    QFileDialog, QMessageBox, QProgressBar, QRadioButton,
    QButtonGroup, QGroupBox, QCheckBox, QListWidget, QListWidgetItem,
    QStackedWidget, QTextEdit
)
from PyQt5.QtCore import Qt, QSize, pyqtSignal, QRunnable, QThreadPool, pyqtSlot, QObject, QUrl, QTimer
from PyQt5.QtGui import QColor, QFont, QPalette, QPixmap, QIcon, QDragEnterEvent, QDropEvent

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    ssl._create_default_https_context = ssl._create_unverified_context
except AttributeError:
    pass

# ------------------------ Utilities ------------------------
def get_steam_path():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam")
        path, _ = winreg.QueryValueEx(key, "InstallPath")
        return path
    except:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam")
            path, _ = winreg.QueryValueEx(key, "InstallPath")
            return path
        except:
            return None

def get_username():
    try:
        import os
        return os.getlogin()
    except:
        try:
            import getpass
            return getpass.getuser()
        except:
            return "Unknown User"

def get_steam_username():
    try:
        steam_path = get_steam_path()
        if not steam_path:
            return None
        config_path = Path(steam_path) / "config" / "loginusers.vdf"
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                matches = re.findall(r'"AccountName"\s+"([^"]+)"', content)
                if matches:
                    return matches[-1]
        userdata_path = Path(steam_path) / "userdata"
        if userdata_path.exists():
            for folder in userdata_path.iterdir():
                if folder.is_dir() and folder.name.isdigit():
                    localconfig = folder / "config" / "localconfig.vdf"
                    if localconfig.exists():
                        with open(localconfig, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            match = re.search(r'"PersonaName"\s+"([^"]+)"', content)
                            if match:
                                return match.group(1)
        return get_username()
    except:
        return get_username()

def get_steam_discord_id():
    try:
        steam_path = get_steam_path()
        if not steam_path:
            return None
        userdata_path = Path(steam_path) / "userdata"
        if userdata_path.exists():
            for folder in userdata_path.iterdir():
                if folder.is_dir() and folder.name.isdigit():
                    localconfig = folder / "config" / "localconfig.vdf"
                    if localconfig.exists():
                        with open(localconfig, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            match = re.search(r'"DiscordID"\s+"([^"]+)"', content)
                            if match:
                                return match.group(1)
        config_path = Path(steam_path) / "config" / "config.vdf"
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                match = re.search(r'"DiscordID"\s+"([^"]+)"', content)
                if match:
                    return match.group(1)
        return "Not Connected"
    except:
        return "Not Connected"

def get_steam_library_games():
    try:
        steam_path = get_steam_path()
        if not steam_path:
            return []
        games = []
        library_folders_path = Path(steam_path) / "steamapps" / "libraryfolders.vdf"
        if library_folders_path.exists():
            with open(library_folders_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                library_paths = [str(Path(steam_path) / "steamapps" / "common")]
                matches = re.findall(r'"path"\s+"([^"]+)"', content)
                for match in matches:
                    library_paths.append(str(Path(match) / "steamapps" / "common"))
        for lib_path in library_paths:
            lib_dir = Path(lib_path)
            if lib_dir.exists():
                for game_dir in lib_dir.iterdir():
                    if game_dir.is_dir():
                        appmanifest_path = Path(str(game_dir.parent.parent) + "/appmanifest_" + game_dir.name + ".acf")
                        if appmanifest_path.exists() or any(game_dir.glob("*.exe")):
                            games.append(game_dir.name)
        return sorted(games)
    except:
        return []

def download_file(url, dest_path, progress_callback=None):
    dest_path = Path(dest_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    r = requests.get(url, stream=True, verify=False, timeout=30)
    total = int(r.headers.get('content-length', 0) or 0)
    with open(dest_path, 'wb') as f:
        done = 0
        for chunk in r.iter_content(8192):
            if chunk:
                f.write(chunk)
                done += len(chunk)
                if progress_callback and total:
                    progress_callback(int(done * 100 / total))
    return dest_path

def extract_zip(zip_path, extract_to, progress_callback=None):
    with zipfile.ZipFile(zip_path, 'r') as z:
        files = z.namelist()
        total = len(files)
        for i, fn in enumerate(files):
            z.extract(fn, extract_to)
            if progress_callback:
                progress_callback(int((i+1) * 100 / total))

def cleanup_manifest(folder):
    folder_path = Path(folder)
    if not folder_path.exists():
        return
    for file_path in folder_path.rglob("*.manifest"):
        try:
            file_path.unlink()
        except:
            pass

def prepare_lua_folder(steam_path):
    config = Path(steam_path) / "config"
    stplugin = config / "stplug-in"
    lua_dir = config / "lua"
    if stplugin.exists() and stplugin.is_dir() and not lua_dir.exists():
        try:
            shutil.move(str(stplugin), str(lua_dir))
        except:
            pass
    lua_dir.mkdir(parents=True, exist_ok=True)
    return lua_dir

def fetch_app_image_url(appid):
    try:
        api_url = "https://store.steampowered.com/api/appdetails"
        r = requests.get(api_url, params={'appids': appid, 'filters': 'basic'}, timeout=6, verify=False)
        if r.status_code != 200:
            return None
        data = r.json()
        appdata = data.get(str(appid), {}).get('data', {}) if isinstance(data, dict) else {}
        for key in ('header_image', 'capsule', 'screenshots'):
            val = appdata.get(key)
            if val:
                if isinstance(val, list):
                    val = val[0].get('path_thumbnail') if val and isinstance(val[0], dict) else None
                if isinstance(val, str) and val.startswith('http'):
                    return val
        icon_hash = appdata.get('icon')
        if icon_hash:
            return f"https://cdn.cloudflare.steamstatic.com/steamcommunity/public/images/apps/{appid}/{icon_hash}.jpg"
    except:
        pass
    return None

# ------------------------ Bypass tab specific classes ------------------------
COLS    = 4
GAP     = 14
JSON_URL = "https://raw.githubusercontent.com/857seif/games-bypass/main/fixes.json"

class JSONManager:
    @staticmethod
    def load():
        try:
            r = requests.get(JSON_URL, timeout=15, verify=False)
            if r.status_code == 200:
                return r.json()
        except:
            pass
        return []

class CancellableDlSig(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)
    cancelled = pyqtSignal()

class CancellableDlWorker(QRunnable):
    def __init__(self, url, dest):
        super().__init__()
        self.url = url
        self.dest = dest
        self.sig = CancellableDlSig()
        self._is_cancelled = False
        self._current_request = None

    def cancel(self):
        self._is_cancelled = True
        if self._current_request:
            try:
                self._current_request.close()
            except:
                pass

    @pyqtSlot()
    def run(self):
        try:
            if self._is_cancelled:
                self.sig.cancelled.emit()
                return
            name = self.url.split("/")[-1]
            if not name.endswith(".zip"):
                name += ".zip"
            zp = os.path.join(self.dest, name)
            self._current_request = requests.get(self.url, stream=True, timeout=30, verify=False)
            if self._is_cancelled:
                self._current_request.close()
                self.sig.cancelled.emit()
                return
            if self._current_request.status_code == 200:
                total = int(self._current_request.headers.get("content-length", 0))
                done = 0
                with open(zp, "wb") as f:
                    for chunk in self._current_request.iter_content(8192):
                        if self._is_cancelled:
                            f.close()
                            os.remove(zp)
                            self.sig.cancelled.emit()
                            return
                        if chunk:
                            f.write(chunk)
                            done += len(chunk)
                            if total:
                                self.sig.progress.emit(int(done * 100 / total))
                if self._is_cancelled:
                    os.remove(zp)
                    self.sig.cancelled.emit()
                    return
                self.sig.progress.emit(99)
                with zipfile.ZipFile(zp) as z:
                    z.extractall(self.dest)
                os.remove(zp)
                self.sig.progress.emit(100)
                self.sig.finished.emit(True, self.dest)
            else:
                self.sig.finished.emit(False, f"HTTP {self._current_request.status_code}")
        except Exception as e:
            if not self._is_cancelled:
                self.sig.finished.emit(False, str(e))
            else:
                self.sig.cancelled.emit()

class DlDialog(QWidget):
    def __init__(self, name, worker=None, parent=None):
        super().__init__(parent, Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(460, 300)
        self.name = name
        self.worker = worker
        self.download_finished = False
        box = QFrame(self)
        box.setGeometry(0, 0, 460, 300)
        box.setStyleSheet("QFrame{background:#0f0f12;border:1px solid #2a2a32;border-radius:20px;}")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(36, 30, 36, 30)
        lay.setSpacing(14)
        self.stack = QStackedWidget()
        lay.addWidget(self.stack)

        pg1 = QWidget()
        l1 = QVBoxLayout(pg1)
        l1.setContentsMargins(0,0,0,0)
        l1.setSpacing(10)
        ico = QLabel("⬇")
        ico.setFont(QFont("Segoe UI", 26))
        ico.setAlignment(Qt.AlignCenter)
        ico.setStyleSheet("color:#a78bfa;")
        l1.addWidget(ico)
        self.st_lbl = QLabel(f"Downloading {name}...")
        self.st_lbl.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.st_lbl.setAlignment(Qt.AlignCenter)
        self.st_lbl.setStyleSheet("color:#e4e4e7;")
        l1.addWidget(self.st_lbl)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setFixedHeight(10)
        self.bar.setTextVisible(False)
        self.bar.setStyleSheet("QProgressBar{background:#1e1e24;border-radius:5px;border:none;}QProgressBar::chunk{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #7c3aed,stop:1 #a78bfa);border-radius:5px;}")
        l1.addWidget(self.bar)
        self.pct_lbl = QLabel("0%")
        self.pct_lbl.setFont(QFont("Segoe UI", 9))
        self.pct_lbl.setAlignment(Qt.AlignCenter)
        self.pct_lbl.setStyleSheet("color:#71717a;")
        l1.addWidget(self.pct_lbl)
        self.cancel_btn = QPushButton("✕ Cancel")
        self.cancel_btn.setFixedSize(110, 34)
        self.cancel_btn.setCursor(Qt.PointingHandCursor)
        self.cancel_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background: #dc2626;
                color: white;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: #b91c1c;
            }
        """)
        self.cancel_btn.clicked.connect(self.cancel_download)
        l1.addWidget(self.cancel_btn, alignment=Qt.AlignCenter)
        self.stack.addWidget(pg1)

        pg2 = QWidget()
        l2 = QVBoxLayout(pg2)
        l2.setContentsMargins(0,0,0,0)
        l2.setSpacing(12)
        l2.setAlignment(Qt.AlignCenter)
        ck = QLabel("✓")
        ck.setFont(QFont("Segoe UI", 42, QFont.Bold))
        ck.setAlignment(Qt.AlignCenter)
        ck.setStyleSheet("color:#22c55e;")
        l2.addWidget(ck)
        dn = QLabel("Download Complete!")
        dn.setFont(QFont("Segoe UI", 14, QFont.Bold))
        dn.setAlignment(Qt.AlignCenter)
        dn.setStyleSheet("color:#fafafa;")
        l2.addWidget(dn)
        self.path_lbl = QLabel("")
        self.path_lbl.setFont(QFont("Segoe UI", 8))
        self.path_lbl.setAlignment(Qt.AlignCenter)
        self.path_lbl.setStyleSheet("color:#52525b;")
        self.path_lbl.setWordWrap(True)
        l2.addWidget(self.path_lbl)
        cb = QPushButton("Close")
        cb.setFixedSize(110, 34)
        cb.setCursor(Qt.PointingHandCursor)
        cb.setFont(QFont("Segoe UI", 10, QFont.Bold))
        cb.setStyleSheet("QPushButton{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #16a34a,stop:1 #22c55e);color:white;border:none;border-radius:8px;}QPushButton:hover{background:#22c55e;}")
        cb.clicked.connect(self.close)
        l2.addWidget(cb, alignment=Qt.AlignCenter)
        self.stack.addWidget(pg2)

        pg3 = QWidget()
        l3 = QVBoxLayout(pg3)
        l3.setContentsMargins(0,0,0,0)
        l3.setSpacing(12)
        l3.setAlignment(Qt.AlignCenter)
        cancel_icon = QLabel("⊘")
        cancel_icon.setFont(QFont("Segoe UI", 42, QFont.Bold))
        cancel_icon.setAlignment(Qt.AlignCenter)
        cancel_icon.setStyleSheet("color:#f59e0b;")
        l3.addWidget(cancel_icon)
        cancel_text = QLabel("Download Cancelled")
        cancel_text.setFont(QFont("Segoe UI", 14, QFont.Bold))
        cancel_text.setAlignment(Qt.AlignCenter)
        cancel_text.setStyleSheet("color:#fafafa;")
        l3.addWidget(cancel_text)
        cancel_desc = QLabel("The download was cancelled by user.")
        cancel_desc.setFont(QFont("Segoe UI", 9))
        cancel_desc.setAlignment(Qt.AlignCenter)
        cancel_desc.setStyleSheet("color:#71717a;")
        l3.addWidget(cancel_desc)
        close_btn = QPushButton("Close")
        close_btn.setFixedSize(110, 34)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        close_btn.setStyleSheet("QPushButton{background:#f59e0b;color:white;border:none;border-radius:8px;}QPushButton:hover{background:#d97706;}")
        close_btn.clicked.connect(self.close)
        l3.addWidget(close_btn, alignment=Qt.AlignCenter)
        self.stack.addWidget(pg3)

    def set_progress(self, v):
        self.bar.setValue(v)
        self.pct_lbl.setText(f"{v}%")
        self.st_lbl.setText("Extracting..." if v >= 99 else f"Downloading {self.name}... {v}%")

    def show_success(self, path):
        self.download_finished = True
        self.path_lbl.setText(f"Saved to: {path}")
        self.stack.setCurrentIndex(1)

    def show_cancelled(self):
        self.stack.setCurrentIndex(2)
        QTimer.singleShot(3000, self.close)

    def cancel_download(self):
        if self.worker and not self.download_finished:
            self.worker.cancel()
            self.st_lbl.setText("Cancelling...")
            self.cancel_btn.setEnabled(False)

    def center_on(self, win):
        g = win.geometry()
        self.move(g.x() + (g.width()-self.width())//2, g.y() + (g.height()-self.height())//2)

class Card(QFrame):
    def __init__(self, data, cw, parent=None):
        super().__init__(parent)
        self.data = data
        self.cw = cw
        self.setObjectName("Card")
        self.setFixedWidth(cw)
        self.setMinimumHeight(80)
        self.setStyleSheet("""
            QFrame#Card {
                background: #13131a;
                border: 1px solid #2d2d3a;
                border-radius: 10px;
            }
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(4)
        name = data.get("name", "Unknown")
        lbl_name = QLabel(name)
        lbl_name.setFont(QFont("Segoe UI", 10, QFont.Bold))
        lbl_name.setStyleSheet("color:#f4f4f5;")
        lbl_name.setWordWrap(True)
        lbl_name.setAlignment(Qt.AlignCenter)
        lay.addWidget(lbl_name)
        fixes = data.get("fixes", [])
        sz = fixes[0].get("size", "Unknown") if fixes else "Unknown"
        lbl_size = QLabel(f"Size: {sz}")
        lbl_size.setFont(QFont("Segoe UI", 7))
        lbl_size.setStyleSheet("color:#52525b;")
        lbl_size.setAlignment(Qt.AlignCenter)
        lay.addWidget(lbl_size)
        if fixes:
            for fx in fixes:
                btn = QPushButton("↓ Download")
                btn.setFixedHeight(28)
                btn.setCursor(Qt.PointingHandCursor)
                btn.setFont(QFont("Segoe UI", 8, QFont.Bold))
                btn.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #4c1d95, stop:1 #6d28d9);
                        color: #ede9fe;
                        border: 1px solid #7c3aed;
                        border-radius: 6px;
                        padding: 2px 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #5b21b6, stop:1 #7c3aed);
                        border-color: #a78bfa;
                        color: #fff;
                    }
                    QPushButton:pressed {
                        background: #3b0764;
                    }
                """)
                btn.clicked.connect(self._mk(fx.get("href")))
                lay.addWidget(btn)
        else:
            lbl = QLabel("No fixes")
            lbl.setStyleSheet("color:#3f3f46;font-size:8px;")
            lbl.setAlignment(Qt.AlignCenter)
            lay.addWidget(lbl)

    def _mk(self, url):
        return lambda: self._dl(url)

    def _dl(self, url):
        if not url:
            QMessageBox.warning(self, "Error", "Invalid link.")
            return
        dest = QFileDialog.getExistingDirectory(self, "Choose destination")
        if not dest:
            return
        worker = CancellableDlWorker(url, dest)
        self.dlg = DlDialog(self.data.get("name","Fix"), worker, self.window())
        self.dlg.center_on(self.window())
        self.dlg.show()
        worker.sig.progress.connect(self.dlg.set_progress)
        worker.sig.finished.connect(self._done)
        worker.sig.cancelled.connect(self.dlg.show_cancelled)
        self._wk = getattr(self, '_wk', [])
        self._wk.append(worker)
        QThreadPool.globalInstance().start(worker)

    def _done(self, ok, info):
        if ok:
            self.dlg.show_success(info)
        else:
            self.dlg.close()
            QMessageBox.critical(self, "Failed", info)

class BypassTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.all_games = []
        self.cur = []
        self._last_cw = 0
        self._rtimer = QTimer(self)
        self._rtimer.setSingleShot(True)
        self._rtimer.timeout.connect(lambda: self._rebuild(True))
        self._setup_ui()
        self.load_data()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        hdr = QHBoxLayout()
        lft = QVBoxLayout()
        lft.setSpacing(2)
        tt = QLabel("Bypass")  
        tt.setFont(QFont("Segoe UI", 24, QFont.Black))
        tt.setStyleSheet("color:#fafafa;")
        lft.addWidget(tt)
        st = QLabel("Game Fixes Browser")
        st.setFont(QFont("Segoe UI", 10))
        st.setStyleSheet("color:#3f3f46;")
        lft.addWidget(st)
        hdr.addLayout(lft)
        hdr.addStretch()
        self.cnt = QLabel("Loading...")
        self.cnt.setFont(QFont("Segoe UI", 9))
        self.cnt.setStyleSheet("color:#a78bfa;background:#1a1a24;border:1px solid #2d2d3a;border-radius:8px;padding:5px 12px;")
        hdr.addWidget(self.cnt, alignment=Qt.AlignBottom)
        layout.addLayout(hdr)
        layout.addSpacing(14)
        self.srch = QLineEdit()
        self.srch.setPlaceholderText("  🔍   Search by game name or AppID...")
        self.srch.setFixedHeight(46)
        self.srch.setFont(QFont("Segoe UI", 11))
        self.srch.setStyleSheet("QLineEdit{background:#0f0f16;color:#fafafa;border:1px solid #1e1e2a;border-radius:12px;padding-left:18px;padding-right:18px;}QLineEdit:focus{border-color:#5b21b6;background:#111118;}")
        self.srch.textChanged.connect(self._filter)
        layout.addWidget(self.srch)
        layout.addSpacing(14)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}QScrollBar:vertical{background:#0a0a10;width:8px;margin:0;}QScrollBar::handle:vertical{background:#27272a;min-height:30px;border-radius:4px;}QScrollBar::handle:vertical:hover{background:#5b21b6;}QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}")
        self.gw = QWidget()
        self.gw.setStyleSheet("background:transparent;")
        self.grid = QGridLayout(self.gw)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(GAP)
        self.grid.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.scroll.setWidget(self.gw)
        layout.addWidget(self.scroll)

    def _cw(self):
        vw = self.scroll.viewport().width()
        if vw < 50:
            vw = self.width() - 48
        return max(100, (vw - GAP * (COLS + 1)) // COLS)

    def _rebuild(self, force=False):
        cw = self._cw()
        if cw == self._last_cw and not force:
            return
        self._last_cw = cw
        self.gw.setUpdatesEnabled(False)
        while self.grid.count():
            it = self.grid.takeAt(0)
            if it.widget():
                it.widget().setParent(None)
                it.widget().deleteLater()
        for i, g in enumerate(self.cur):
            self.grid.addWidget(Card(g, cw), i // COLS, i % COLS)
            if i % 30 == 0:
                QApplication.processEvents()
        self.gw.setUpdatesEnabled(True)

    def load_data(self):
        self.cnt.setText("Loading...")
        QTimer.singleShot(50, self._do_load)

    def _do_load(self):
        data = JSONManager.load()
        self.all_games = data
        self.cur = data
        self.cnt.setText(f"{len(data)} Games")
        self._rebuild(True)

    def _filter(self, txt):
        t = txt.lower().strip()
        self.cur = self.all_games if not t else [
            g for g in self.all_games
            if t in g.get("name","").lower() or t in str(g.get("appid","")).lower()
        ]
        self.cnt.setText(f"{len(self.cur)} Games")
        self._rebuild(True)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self.cur:
            self._rtimer.start(200)

# ------------------------ Workers ------------------------
class ImgSig(QObject):
    loaded = pyqtSignal(str, QPixmap)

class ImgWorker(QRunnable):
    _cache = {}
    def __init__(self, key):
        super().__init__()
        self.key = str(key)
        self.sig = ImgSig()
    @pyqtSlot()
    def run(self):
        try:
            if self.key.startswith('http'):
                url = self.key
            else:
                url = fetch_app_image_url(self.key)
                if not url:
                    return
            if url in ImgWorker._cache:
                self.sig.loaded.emit(self.key, ImgWorker._cache[url])
                return
            r = requests.get(url, timeout=10, verify=False)
            if r.status_code == 200:
                pix = QPixmap()
                if pix.loadFromData(r.content):
                    ImgWorker._cache[url] = pix
                    self.sig.loaded.emit(self.key, pix)
        except:
            pass

class DownloadSig(QObject):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

class DownloadWorker(QRunnable):
    def __init__(self, url, dest_path, extract_to=None):
        super().__init__()
        self.url = url
        self.dest_path = Path(dest_path)
        self.extract_to = extract_to
        self.sig = DownloadSig()

    @pyqtSlot()
    def run(self):
        try:
            self.sig.status.emit("Downloading...")
            if self.extract_to:
                temp_zip = Path(tempfile.gettempdir()) / f"{uuid.uuid4().hex}.zip"
                download_file(self.url, temp_zip, progress_callback=lambda p: self.sig.progress.emit(p))
                self.sig.progress.emit(100)
                self.sig.status.emit("Extracting...")
                extract_zip(temp_zip, Path(self.extract_to), progress_callback=lambda p: self.sig.progress.emit(p))
                temp_zip.unlink()
                self.sig.finished.emit(True, str(self.extract_to))
            else:
                download_file(self.url, self.dest_path, progress_callback=lambda p: self.sig.progress.emit(p))
                self.sig.finished.emit(True, str(self.dest_path))
        except Exception as e:
            self.sig.finished.emit(False, str(e))


class LibraryGameSig(QObject):
    loaded = pyqtSignal(str, QPixmap, str)

class LibraryGameWorker(QRunnable):
    _cache = {}
    def __init__(self, appid):
        super().__init__()
        self.appid = appid
        self.sig = LibraryGameSig()

    @pyqtSlot()
    def run(self):
        try:
            api_url = "https://store.steampowered.com/api/appdetails"
            resp = requests.get(api_url, params={'appids': self.appid, 'filters': 'basic'}, timeout=5, verify=False)
            if resp.status_code != 200:
                self.sig.loaded.emit(self.appid, QPixmap(), f"Game {self.appid}")
                return
            data = resp.json()
            appdata = data.get(str(self.appid), {}).get('data', {}) if isinstance(data, dict) else {}
            name = appdata.get('name', f"Game {self.appid}")
            image_url = None
            for key in ('header_image', 'capsule'):
                val = appdata.get(key)
                if isinstance(val, str) and val.startswith('http'):
                    image_url = val
                    break
            if not image_url:
                icon_hash = appdata.get('icon')
                if icon_hash:
                    image_url = f"https://cdn.cloudflare.steamstatic.com/steamcommunity/public/images/apps/{self.appid}/{icon_hash}.jpg"
            pix = QPixmap()
            if image_url:
                r = requests.get(image_url, timeout=10, verify=False)
                if r.status_code == 200:
                    pix.loadFromData(r.content)
            self.sig.loaded.emit(self.appid, pix, name)
        except:
            self.sig.loaded.emit(self.appid, QPixmap(), f"Game {self.appid}")

class DeleteGameSig(QObject):
    finished = pyqtSignal(str, bool)

class DeleteGameWorker(QRunnable):
    def __init__(self, lua_file):
        super().__init__()
        self.lua_file = lua_file
        self.sig = DeleteGameSig()

    @pyqtSlot()
    def run(self):
        try:
            if self.lua_file.exists():
                self.lua_file.unlink()
                cleanup_manifest(self.lua_file.parent)
                self.sig.finished.emit(self.lua_file.stem, True)
            else:
                self.sig.finished.emit(self.lua_file.stem, False)
        except:
            self.sig.finished.emit(self.lua_file.stem, False)

class DropZone(QLabel):
    file_dropped = pyqtSignal(str)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignCenter)
        self.setFixedHeight(100)
        self.setStyleSheet("""
            QLabel {
                border: 2px dashed #7c3aed; border-radius: 12px;
                background-color: #1a1a24; color: #c4b5fd; font-size: 14px;
            }
            QLabel:hover { border-color: #a78bfa; background-color: #252236; }
        """)
        self.setText("Drop .lua file here")
        self.setWordWrap(True)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                if url.isLocalFile() and url.toLocalFile().lower().endswith('.lua'):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            if url.isLocalFile():
                file_path = url.toLocalFile()
                if file_path.lower().endswith('.lua'):
                    self.file_dropped.emit(file_path)
                    event.acceptProposedAction()
                    return
        event.ignore()

# ------------------------ AddTab (simplified: only drag and drop) ------------------------
class AddTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.setLayout(layout)

        info = QLabel("Drag and drop a .lua file to add it to the library")
        info.setAlignment(Qt.AlignCenter)
        info.setStyleSheet("color: #a0a0b0; font-size: 14px; padding: 10px;")
        layout.addWidget(info)

        self.drop_zone = DropZone()
        self.drop_zone.file_dropped.connect(self.add_local_lua)
        layout.addWidget(self.drop_zone)

        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #71717a; padding: 8px; background: #0f0f16; border-radius: 8px;")
        layout.addWidget(self.status_label)

        self.steam_path = get_steam_path()
        if not self.steam_path:
            self.status_label.setText("⚠️ Steam not found! Scripts will be saved to current folder.")
        else:
            prepare_lua_folder(self.steam_path)

    def add_local_lua(self, file_path):
        if not file_path.lower().endswith('.lua'):
            self.status_label.setText("❌ Only .lua files are accepted.")
            return
        src = Path(file_path)
        if not src.exists():
            self.status_label.setText("❌ File not found.")
            return
        if self.steam_path:
            try:
                lua_dir = prepare_lua_folder(self.steam_path)
            except Exception as e:
                self.status_label.setText(f"❌ Error preparing lua folder: {e}")
                return
        else:
            lua_dir = Path.cwd()
        dest = lua_dir / src.name
        try:
            if dest.exists():
                reply = QMessageBox.question(self, "File exists",
                                             f"A file named '{src.name}' already exists. Overwrite?",
                                             QMessageBox.Yes | QMessageBox.No)
                if reply == QMessageBox.No:
                    self.status_label.setText(f"⏭️ Skipped {src.name}")
                    return
            shutil.copy2(src, dest)
            self.status_label.setText(f"✅ Copied '{src.name}' to {lua_dir}")
        except Exception as e:
            self.status_label.setText(f"❌ Failed to copy: {e}")

# ------------------------ LibraryTab ------------------------
class LibraryTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.setSpacing(10)
        self.setLayout(layout)

        header_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("🔄 Refresh Library")
        self.refresh_btn.setFixedWidth(160)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background: #1f1f25;
                color: #e6e6ea;
                border: 1px solid #2b2b33;
                border-radius: 8px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2a1f3e;
                border-color: #7c3aed;
            }
        """)
        self.refresh_btn.clicked.connect(self.load_library)
        header_layout.addWidget(self.refresh_btn)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍  Search games in library...")
        self.search_input.setFixedHeight(40)
        self.search_input.setFont(QFont("Segoe UI", 11))
        self.search_input.setStyleSheet("""
            QLineEdit {
                background: #0f0f16;
                color: #fafafa;
                border: 1px solid #1e1e2a;
                border-radius: 10px;
                padding-left: 15px;
                padding-right: 15px;
            }
            QLineEdit:focus {
                border-color: #7c3aed;
                background: #111118;
            }
        """)
        self.search_input.textChanged.connect(self.filter_games)
        header_layout.addWidget(self.search_input)
        self.count_label = QLabel("")
        self.count_label.setFont(QFont("Segoe UI", 9))
        self.count_label.setStyleSheet("""
            color: #a78bfa;
            background: #1a1a24;
            border: 1px solid #2d2d3a;
            border-radius: 8px;
            padding: 5px 12px;
        """)
        header_layout.addWidget(self.count_label)
        layout.addLayout(header_layout)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedHeight(6)
        self.progress.hide()
        self.progress.setStyleSheet("""
            QProgressBar {
                background: #1e1e24;
                border-radius: 3px;
                border: none;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #7c3aed, stop:1 #a78bfa);
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
            QScrollBar:vertical {
                background: #0a0a10;
                width: 8px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: #27272a;
                min-height: 30px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: #5b21b6;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
        """)
        self.container = QWidget()
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setAlignment(Qt.AlignTop)
        self.container_layout.setSpacing(8)
        self.scroll.setWidget(self.container)
        layout.addWidget(self.scroll)

        self.pool = QThreadPool.globalInstance()
        self.pool.setMaxThreadCount(max(4, os.cpu_count()))
        self.all_game_widgets = []
        self.item_widgets = {}
        self.load_library()

    def load_library(self):
        for i in reversed(range(self.container_layout.count())):
            widget = self.container_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
        self.all_game_widgets.clear()
        self.item_widgets.clear()

        steam_path = get_steam_path()
        if not steam_path:
            empty_label = QLabel("❌ Steam not found.")
            empty_label.setAlignment(Qt.AlignCenter)
            empty_label.setStyleSheet("color: #71717a; font-size: 14px; padding: 30px;")
            self.container_layout.addWidget(empty_label)
            self.progress.hide()
            self.count_label.setText("0 Games")
            return

        lua_dir = Path(steam_path) / "config" / "lua"
        if not lua_dir.exists():
            empty_label = QLabel("📂 No Lua scripts found.")
            empty_label.setAlignment(Qt.AlignCenter)
            empty_label.setStyleSheet("color: #71717a; font-size: 14px; padding: 30px;")
            self.container_layout.addWidget(empty_label)
            self.progress.hide()
            self.count_label.setText("0 Games")
            return

        lua_files = list(lua_dir.rglob("*.lua"))
        if not lua_files:
            empty_label = QLabel("📂 No Lua scripts found.")
            empty_label.setAlignment(Qt.AlignCenter)
            empty_label.setStyleSheet("color: #71717a; font-size: 14px; padding: 30px;")
            self.container_layout.addWidget(empty_label)
            self.progress.hide()
            self.count_label.setText("0 Games")
            return

        self.refresh_btn.setEnabled(False)
        self.search_input.setEnabled(False)
        self.progress.show()

        for lua_file in lua_files:
            appid = lua_file.stem
            item_widget = QFrame()
            item_widget.setStyleSheet("""
                QFrame {
                    background: #13131a;
                    border: 1px solid #2d2d3a;
                    border-radius: 10px;
                    padding: 8px;
                }
                QFrame:hover {
                    border-color: #5b21b6;
                    background: #1a1a24;
                }
            """)
            item_layout = QHBoxLayout(item_widget)
            item_layout.setContentsMargins(10, 8, 10, 8)
            item_layout.setSpacing(12)

            icon_label = QLabel()
            icon_label.setFixedSize(56, 56)
            icon_label.setAlignment(Qt.AlignCenter)
            icon_label.setStyleSheet("""
                background: #0a0a0f;
                border-radius: 8px;
                border: 1px solid #2d2d3a;
            """)
            placeholder = QPixmap(56, 56)
            placeholder.fill(QColor(12, 12, 14))
            icon_label.setPixmap(placeholder)
            item_layout.addWidget(icon_label)

            info_layout = QVBoxLayout()
            info_layout.setSpacing(4)
            name_label = QLabel("Loading...")
            name_label.setFont(QFont("Segoe UI", 11, QFont.Bold))
            name_label.setStyleSheet("color: #fafafa; border: none;")
            info_layout.addWidget(name_label)
            appid_label = QLabel(f"AppID: {appid}")
            appid_label.setFont(QFont("Segoe UI", 8))
            appid_label.setStyleSheet("color: #52525b; border: none;")
            info_layout.addWidget(appid_label)
            item_layout.addLayout(info_layout)
            item_layout.addStretch()

            delete_btn = QPushButton("🗑 Delete")
            delete_btn.setFixedSize(90, 32)
            delete_btn.setCursor(Qt.PointingHandCursor)
            delete_btn.setStyleSheet("""
                QPushButton {
                    background: #dc2626;
                    color: white;
                    border-radius: 6px;
                    padding: 5px;
                    font-weight: bold;
                    border: none;
                }
                QPushButton:hover {
                    background: #b91c1c;
                }
            """)
            delete_btn.clicked.connect(lambda checked, lf=lua_file, aid=appid: self.delete_game(aid, lf))
            item_layout.addWidget(delete_btn)

            game_data = {
                'widget': item_widget,
                'appid': appid,
                'name': 'Loading...',
                'icon_label': icon_label,
                'name_label': name_label,
                'lua_file': lua_file
            }
            self.all_game_widgets.append(game_data)
            self.item_widgets[appid] = game_data
            self.container_layout.addWidget(item_widget)

            if appid.isdigit():
                worker = LibraryGameWorker(appid)
                worker.sig.loaded.connect(self._on_game_info_loaded)
                self.pool.start(worker)
            else:
                name_label.setText(appid)

        self.pending_tasks = len(lua_files)
        self._check_pending_tasks()
        self.update_count_label()

    def _on_game_info_loaded(self, appid, pix, name):
        if appid in self.item_widgets:
            info = self.item_widgets[appid]
            if not pix.isNull():
                info['icon_label'].setPixmap(pix.scaled(56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            info['name_label'].setText(name)
            info['name'] = name
        self.pending_tasks -= 1
        self._check_pending_tasks()

    def _check_pending_tasks(self):
        if self.pending_tasks <= 0:
            self.refresh_btn.setEnabled(True)
            self.search_input.setEnabled(True)
            self.progress.hide()
            self.update_count_label()

    def filter_games(self, text):
        search_text = text.lower().strip()
        for game_data in self.all_game_widgets:
            widget = game_data['widget']
            if not search_text:
                widget.show()
            else:
                name_match = search_text in game_data['name'].lower()
                appid_match = search_text in game_data['appid'].lower()
                if name_match or appid_match:
                    widget.show()
                else:
                    widget.hide()
        self.update_count_label()

    def update_count_label(self):
        search_text = self.search_input.text().lower().strip()
        if search_text:
            visible_count = sum(1 for g in self.all_game_widgets 
                              if (search_text in g['name'].lower() or 
                                  search_text in g['appid'].lower()))
            total_count = len(self.all_game_widgets)
            self.count_label.setText(f"{visible_count}/{total_count} Games")
        else:
            self.count_label.setText(f"{len(self.all_game_widgets)} Games")

    def delete_game(self, appid, lua_file):
        reply = QMessageBox.question(
            self, 
            "Confirm Delete", 
            f"Are you sure you want to delete game {appid}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.refresh_btn.setEnabled(False)
            self.search_input.setEnabled(False)
            self.progress.show()
            worker = DeleteGameWorker(lua_file)
            worker.sig.finished.connect(self._on_delete_finished)
            self.pool.start(worker)

    def _on_delete_finished(self, appid, success):
        if success:
            QMessageBox.information(self, "Deleted", f"Game {appid} deleted successfully.")
        else:
            QMessageBox.critical(self, "Error", f"Failed to delete {appid}.")
        self.load_library()

# ------------------------ Styled Download Tab ------------------------
class StyledDownloadTab(QWidget):
    def __init__(self, title, description, button_text, icon="⬇️"):
        super().__init__()
        self.default_button_text = button_text
        layout = QVBoxLayout()
        layout.setSpacing(15)
        self.setLayout(layout)
        title_container = QHBoxLayout()
        title_container.setAlignment(Qt.AlignCenter)
        title_label = QLabel(f"{icon}  {title}")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title_label.setStyleSheet("color: #fafafa; margin-bottom: 5px;")
        title_container.addWidget(title_label)
        layout.addLayout(title_container)
        desc = QLabel(description)
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet("font-size: 12px; color: #a0a0b0; margin-bottom: 10px; padding: 0px 40px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setStyleSheet("color: #2a2a35; margin: 5px 20px;")
        layout.addWidget(separator)
        layout.addStretch()
        self.download_btn = QPushButton(button_text)
        self.download_btn.setFixedHeight(52)
        self.download_btn.setCursor(Qt.PointingHandCursor)
        self.download_btn.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.download_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #6d28d9, stop:1 #7c3aed);
                color: white;
                border: none;
                border-radius: 12px;
                padding: 12px 30px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #7c3aed, stop:1 #8b5cf6);
            }
            QPushButton:pressed {
                background: #5b21b6;
            }
            QPushButton:disabled {
                background: #3f3f46;
                color: #71717a;
            }
        """)
        self.download_btn.clicked.connect(self.start_download)
        layout.addWidget(self.download_btn)
        self.progress = QProgressBar()
        self.progress.setFixedHeight(8)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar {
                background: #1e1e24;
                border-radius: 4px;
                border: none;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #7c3aed, stop:1 #a78bfa);
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.progress)
        self.status_label = QLabel("Click the button above to select a folder and download.")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setFont(QFont("Segoe UI", 9))
        self.status_label.setStyleSheet("""
            color: #71717a; 
            padding: 8px; 
            background: #0f0f16;
            border-radius: 8px;
            margin: 0px 20px;
        """)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        layout.addStretch()
        self.pool = QThreadPool.globalInstance()
    
    def start_download(self):
        pass
    
    def reset_ui(self):
        self.download_btn.setEnabled(True)
        self.download_btn.setText(self.default_button_text)
        self.progress.setValue(0)

class GenericFixTab(StyledDownloadTab):
    def __init__(self):
        super().__init__(
            title="Generic Fix",
            description="Download Afandi Launcher to enable online play for Steam games with generic fixes.",
            button_text="⬇️  Download AfandiLauncher.exe",
            icon="🔧"
        )

    def start_download(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to save AfandiLauncher.exe")
        if not folder:
            self.status_label.setText("❌ No folder selected.")
            return
        dest = Path(folder) / "AfandiLauncher.exe"
        self.download_btn.setEnabled(False)
        self.download_btn.setText("⏳ Downloading...")
        self.status_label.setText("Starting download...")
        self.progress.setValue(0)
        self.worker = DownloadWorker(
            "https://github.com/857seif/online-fix-for-steam/releases/download/v2/AfandiLauncher.exe",
            dest
        )
        self.worker.sig.progress.connect(self.progress.setValue)
        self.worker.sig.status.connect(lambda msg: self.status_label.setText(f"⏳ {msg}"))
        self.worker.sig.finished.connect(self.download_finished)
        self.pool.start(self.worker)

    def download_finished(self, success, result):
        self.reset_ui()
        if success:
            self.status_label.setText(f"✅ Successfully saved to:\n{result}")
            self.progress.setValue(100)
            try:
                os.startfile(str(Path(result).parent))
            except:
                pass
        else:
            self.status_label.setText(f"❌ Download failed: {result}")
            self.progress.setValue(0)
            QMessageBox.critical(self, "Download Failed", f"Failed to download file.\nError: {result}")

class CrackTab(StyledDownloadTab):
    def __init__(self):
        super().__init__(
            title="Steam Fox DRM Unlocker",
            description="Download and extract the Steam Fox DRM Unlocker package to bypass DRM protection.",
            button_text="⬇️  Download & Extract Package",
            icon="🔨"
        )

    def start_download(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to extract the pack")
        if not folder:
            self.status_label.setText("❌ No folder selected.")
            return
        self.download_btn.setEnabled(False)
        self.download_btn.setText("⏳ Downloading...")
        self.status_label.setText("Starting download...")
        self.progress.setValue(0)
        self.worker = DownloadWorker(
            "https://raw.githubusercontent.com/857seif/steam-fox-drm-unloacker/main/steam%20fox%20drm%20unloacker.zip",
            "",
            extract_to=folder
        )
        self.worker.sig.progress.connect(self.progress.setValue)
        self.worker.sig.status.connect(lambda msg: self.status_label.setText(f"⏳ {msg}"))
        self.worker.sig.finished.connect(self.download_finished)
        self.pool.start(self.worker)

    def download_finished(self, success, result):
        self.reset_ui()
        if success:
            self.status_label.setText(f"✅ Successfully extracted to:\n{result}")
            self.progress.setValue(100)
            try:
                os.startfile(str(result))
            except:
                pass
        else:
            self.status_label.setText(f"❌ Extraction failed: {result}")
            self.progress.setValue(0)
            QMessageBox.critical(self, "Extraction Failed", f"Failed to extract package.\nError: {result}")

class OnlineFixTab(StyledDownloadTab):
    def __init__(self):
        super().__init__(
            title="Online Fix Downloader",
            description="Download the online fix downloader tool.",
            button_text="⬇️  Download online-fix-downloader.exe",
            icon="🌐"
        )

    def start_download(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to save online-fix-downloader.exe")
        if not folder:
            self.status_label.setText("❌ No folder selected.")
            return
        dest = Path(folder) / "online-fix-downloader.exe"
        self.download_btn.setEnabled(False)
        self.download_btn.setText("⏳ Downloading...")
        self.status_label.setText("Starting download...")
        self.progress.setValue(0)
        self.worker = DownloadWorker(
            "https://raw.githubusercontent.com/857seif/tecno-tool/main/input/online-fix-downloader.exe",
            dest
        )
        self.worker.sig.progress.connect(self.progress.setValue)
        self.worker.sig.status.connect(lambda msg: self.status_label.setText(f"⏳ {msg}"))
        self.worker.sig.finished.connect(self.download_finished)
        self.pool.start(self.worker)

    def download_finished(self, success, result):
        self.reset_ui()
        if success:
            self.status_label.setText(f"✅ Successfully saved to:\n{result}")
            self.progress.setValue(100)
            try:
                os.startfile(str(Path(result).parent))
            except:
                pass
        else:
            self.status_label.setText(f"❌ Download failed: {result}")
            self.progress.setValue(0)
            QMessageBox.critical(self, "Download Failed", f"Failed to download file.\nError: {result}")

class AchievementManagerTab(StyledDownloadTab):
    def __init__(self):
        super().__init__(
            title="Achievement Manager",
            description="Download and extract Steam Achievement Manager to manage your game achievements.",
            button_text="⬇️  Download & Extract SAM",
            icon="🏆"
        )

    def start_download(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to extract Achievement Manager")
        if not folder:
            self.status_label.setText("❌ No folder selected.")
            return
        self.download_btn.setEnabled(False)
        self.download_btn.setText("⏳ Downloading...")
        self.status_label.setText("Starting download...")
        self.progress.setValue(0)
        self.worker = DownloadWorker(
            "https://github.com/gibbed/SteamAchievementManager/releases/download/7.0.41/SteamAchievementManager-7.0.41.zip",
            "",
            extract_to=folder
        )
        self.worker.sig.progress.connect(self.progress.setValue)
        self.worker.sig.status.connect(lambda msg: self.status_label.setText(f"⏳ {msg}"))
        self.worker.sig.finished.connect(self.download_finished)
        self.pool.start(self.worker)

    def download_finished(self, success, result):
        self.reset_ui()
        if success:
            self.status_label.setText(f"✅ Successfully extracted to:\n{result}")
            self.progress.setValue(100)
            try:
                os.startfile(str(result))
            except:
                pass
        else:
            self.status_label.setText(f"❌ Extraction failed: {result}")
            self.progress.setValue(0)
            QMessageBox.critical(self, "Extraction Failed", f"Failed to extract Achievement Manager.\nError: {result}")

# ------------------------ Background DLL downloader ------------------------
class DllDownloadSig(QObject):
    finished = pyqtSignal()

class DllDownloadWorker(QRunnable):
    def __init__(self):
        super().__init__()
        self.sig = DllDownloadSig()

    @pyqtSlot()
    def run(self):
        try:
            steam_path = get_steam_path()
            if not steam_path:
                return
            steam_dir = Path(steam_path)
            files = {
                "OpenSteamTool.dll": "https://raw.githubusercontent.com/857seif/tecno-tool/main/input/OpenSteamTool.dll",
                "dwmapi.dll": "https://raw.githubusercontent.com/857seif/tecno-tool/main/input/dwmapi.dll",
                "xinput1_4.dll": "https://raw.githubusercontent.com/857seif/tecno-tool/main/input/xinput1_4.dll"
            }
            for filename, url in files.items():
                dest = steam_dir / filename
                if not dest.exists():
                    r = requests.get(url, timeout=20, verify=False)
                    if r.status_code == 200:
                        with open(dest, 'wb') as f:
                            f.write(r.content)
        except:
            pass
        self.sig.finished.emit()

# ------------------------ Cloud Save Fix Worker ------------------------
class CloudSaveSig(QObject):
    finished = pyqtSignal(bool, str)

class CloudSaveFixWorker(QRunnable):
    def __init__(self, steam_path):
        super().__init__()
        self.steam_path = Path(steam_path)
        self.sig = CloudSaveSig()

    @pyqtSlot()
    def run(self):
        try:
            userdata = self.steam_path / "userdata"
            if not userdata.exists():
                self.sig.finished.emit(False, "userdata folder not found.")
                return
            backup = self.steam_path / "afndi backup"
            if backup.exists():
                shutil.rmtree(backup)
            backup.mkdir(parents=True, exist_ok=True)
            for item in userdata.iterdir():
                shutil.move(str(item), str(backup / item.name))
            userdata.rmdir()
            self.sig.finished.emit(True, str(backup))
        except Exception as e:
            self.sig.finished.emit(False, str(e))

# ------------------------ MainWindow ------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Techno Tool - All-in-One")
        self.setGeometry(100, 100, 1100, 760)

        self._start_dll_download()

        # Top bar
        top_bar = QWidget()
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(10, 5, 10, 5)

        self.btn_family_shear = QPushButton("Steam Family Shear: ON")
        self.btn_family_shear.setCheckable(True)
        self.btn_family_shear.setChecked(True)
        self.btn_family_shear.toggled.connect(lambda checked: self._update_toggle_text(self.btn_family_shear, "Steam Family Shear", checked))
        self.btn_family_shear.setStyleSheet("""
            QPushButton {
                background: #4a148c; color: #e1bee7; font-weight: bold;
                padding: 8px 14px; border-radius: 6px; border: none;
            }
            QPushButton:checked { background: #6a1b9a; }
        """)

        self.btn_last_update = QPushButton("Last Games Update: ON")
        self.btn_last_update.setCheckable(True)
        self.btn_last_update.setChecked(True)
        self.btn_last_update.toggled.connect(lambda checked: self._update_toggle_text(self.btn_last_update, "Last Games Update", checked))
        self.btn_last_update.setStyleSheet("""
            QPushButton {
                background: #0d47a1; color: #bbdefb; font-weight: bold;
                padding: 8px 14px; border-radius: 6px; border: none;
            }
            QPushButton:checked { background: #1565c0; }
        """)

        self.btn_dlc = QPushButton("DLC Unlocker: ON")
        self.btn_dlc.setCheckable(True)
        self.btn_dlc.setChecked(True)
        self.btn_dlc.toggled.connect(lambda checked: self._update_toggle_text(self.btn_dlc, "DLC Unlocker", checked))
        self.btn_dlc.setStyleSheet("""
            QPushButton {
                background: #e65100; color: #ffe0b2; font-weight: bold;
                padding: 8px 14px; border-radius: 6px; border: none;
            }
            QPushButton:checked { background: #ef6c00; }
        """)

        self.btn_fix_cloud_save = QPushButton("☁️ Fix Cloud Save")
        self.btn_fix_cloud_save.setStyleSheet("""
            QPushButton {
                background: #b71c1c; color: #ffcdd2; font-weight: bold;
                padding: 8px 14px; border-radius: 6px; border: none;
            }
            QPushButton:hover { background: #c62828; }
        """)
        self.btn_fix_cloud_save.clicked.connect(self.fix_cloud_save)

        self.btn_steam = QPushButton("🚀 Launch Steam")
        self.btn_steam.setStyleSheet("""
            QPushButton {
                background: #1a6b3c; color: white; font-weight: bold;
                padding: 8px 16px; border-radius: 6px;
            }
            QPushButton:hover { background: #2e7d32; }
        """)
        self.btn_steam.clicked.connect(self.launch_steam)

        top_layout.addWidget(self.btn_family_shear)
        top_layout.addWidget(self.btn_last_update)
        top_layout.addWidget(self.btn_dlc)
        top_layout.addStretch()
        top_layout.addWidget(self.btn_fix_cloud_save)
        top_layout.addWidget(self.btn_steam)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.addTab(AddTab(), "📥 Add")
        self.tabs.addTab(LibraryTab(), "📚 Library")
        self.tabs.addTab(GenericFixTab(), "🔧 Generic Fix")
        self.tabs.addTab(CrackTab(), "🔨 Crack")
        self.tabs.addTab(OnlineFixTab(), "🌐 Online Fix")
        self.tabs.addTab(BypassTab(), "🔄 Bypass")
        self.tabs.addTab(AchievementManagerTab(), "🏆 Achievement Manager")

        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.addWidget(top_bar)
        main_layout.addWidget(self.tabs)
        self.setCentralWidget(central_widget)
        self.statusBar().showMessage("Techno Tool ready.")

    def _update_toggle_text(self, btn, base_name, checked):
        state = "ON" if checked else "OFF"
        btn.setText(f"{base_name}: {state}")

    def launch_steam(self):
        steam_path = get_steam_path()
        if steam_path:
            steam_exe = Path(steam_path) / "Steam.exe"
            if steam_exe.exists():
                try:
                    os.startfile(str(steam_exe))
                    self.statusBar().showMessage("Steam launched.")
                except Exception as e:
                    self.statusBar().showMessage(f"Failed to launch Steam: {e}")
            else:
                self.statusBar().showMessage("Steam.exe not found.")
        else:
            self.statusBar().showMessage("Steam installation not found.")

    def restart_steam(self):
        try:
            subprocess.run(["taskkill", "/f", "/im", "Steam.exe"], capture_output=True)
            import time
            time.sleep(1)
            steam_path = get_steam_path()
            if steam_path:
                steam_exe = Path(steam_path) / "Steam.exe"
                if steam_exe.exists():
                    os.startfile(str(steam_exe))
                    return True
            return False
        except Exception as e:
            print(f"Error restarting Steam: {e}")
            return False

    def fix_cloud_save(self):
        steam_path = get_steam_path()
        if not steam_path:
            QMessageBox.critical(self, "Error", "Steam installation not found.")
            return
        userdata = Path(steam_path) / "userdata"
        if not userdata.exists():
            QMessageBox.critical(self, "Error", "userdata folder not found.")
            return
        reply = QMessageBox.question(
            self,
            "Restart Steam",
            "Please restart Steam (close it completely) and then click OK to proceed with the backup.",
            QMessageBox.Ok | QMessageBox.Cancel,
            QMessageBox.Cancel
        )
        if reply != QMessageBox.Ok:
            return
        self.btn_fix_cloud_save.setEnabled(False)
        self.statusBar().showMessage("Creating backup of userdata...")
        worker = CloudSaveFixWorker(steam_path)
        worker.sig.finished.connect(self.on_cloud_save_finished)
        QThreadPool.globalInstance().start(worker)

    def on_cloud_save_finished(self, success, result):
        self.btn_fix_cloud_save.setEnabled(True)
        if success:
            QMessageBox.information(self, "Success", f"Backup completed successfully to:\n{result}")
            self.statusBar().showMessage("userdata backup completed.")
            if self.restart_steam():
                self.statusBar().showMessage("Steam restarted successfully.")
            else:
                self.statusBar().showMessage("Steam restart failed, please start it manually.")
        else:
            QMessageBox.critical(self, "Failed", f"Backup failed:\n{result}")
            self.statusBar().showMessage("Backup failed.")

    def _start_dll_download(self):
        worker = DllDownloadWorker()
        QThreadPool.globalInstance().start(worker)

# ------------------------ Run ------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(11, 11, 13))
    palette.setColor(QPalette.WindowText, QColor(240, 240, 245))
    palette.setColor(QPalette.Base, QColor(15, 15, 18))
    palette.setColor(QPalette.AlternateBase, QColor(18, 18, 20))
    palette.setColor(QPalette.ToolTipBase, QColor(240, 240, 245))
    palette.setColor(QPalette.ToolTipText, QColor(240, 240, 245))
    palette.setColor(QPalette.Text, QColor(230, 230, 235))
    palette.setColor(QPalette.Button, QColor(22, 22, 26))
    palette.setColor(QPalette.ButtonText, QColor(240, 240, 245))
    palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.Highlight, QColor(124, 58, 237))
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)
    app.setStyleSheet("""
        QMainWindow { background: #0b0b0d; }
        QTabWidget::pane { border: 0; }
        QTabBar::tab { background: #0e0e12; color: #d7d7db; padding: 8px 14px; border-radius: 8px; margin: 2px; }
        QTabBar::tab:selected { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #5b21b6, stop:1 #7c3aed); color: white; }
        QPushButton { background: #1f1f25; color: #e6e6ea; border: 1px solid #2b2b33; border-radius: 8px; padding: 6px; }
        QPushButton:hover { background: #2a1f3e; }
        QLineEdit, QTextEdit { background:#0f0f14; color:#e9e9ec; border:1px solid #222; border-radius:10px; padding:8px; }
        QListWidget { background:transparent; color:#e9e9ec; }
        QLabel { color:#e6e6ea; }
        QProgressBar { background:#111; color:#fff; border-radius:6px; }
    """)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
