@echo off
cls
echo Starting PyInstaller build for tecno-tools...

pyinstaller --onefile --windowed --name "tecno-tools" --icon="unnamed.ico" --add-data "unnamed.ico;." tecno-tool.py

echo.
echo ----------------------------------------------------------------------
echo Build attempt complete. Check the "dist" folder for tecno-tool.exe
echo ----------------------------------------------------------------------
pause