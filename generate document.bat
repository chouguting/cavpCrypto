@echo off
:: 檢查是否安裝了 doxygen
where doxygen >nul 2>nul
if %errorlevel% neq 0 (
    echo doxygen not found, installing...
    winget install DimitriVanHeesch.Doxygen
    echo doxygen installed
    echo please run this script again
    pause
    exit
)

:: 執行 doxygen
doxygen .\Doxyfile
pause