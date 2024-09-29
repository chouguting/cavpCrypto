@echo off
:: 檢查是否安裝了 doxygen
where doxygen >nul 2>nul
if %errorlevel% neq 0 (
    echo doxygen 未安裝，正在使用 winget 安裝...
    winget install DimitriVanHeesch.Doxygen
)

:: 執行 doxygen
doxygen .\Doxyfile
pause