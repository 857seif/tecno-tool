import os
import re
import shutil
from PIL import Image, ImageOps

class FileManager:
    def __init__(self, cache_dir):
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

    def extract_appid(self, fname):
        nums = re.findall(r'\d{2,}', fname)
        return nums[0] if nums else ""

    def process_dropped_files(self, files, target_dir):
        added = 0
        for path in files:
            path_str = path.decode('utf-8') if isinstance(path, bytes) else path
            if os.path.isfile(path_str) and path_str.lower().endswith(".lua"):
                shutil.copy2(path_str, os.path.join(target_dir, os.path.basename(path_str)))
                added += 1
        return added