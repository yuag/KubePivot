@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ========================================
echo   K8s Commander 启动器
echo ========================================

if not exist "%~dp0commander\app.py" (
    echo [错误] 缺少 commander 文件夹，请完整复制程序目录！
    pause
    exit /b 1
)

if not exist "%~dp0k8s_commander.py" (
    echo [错误] 缺少 k8s_commander.py，请勿使用旧版单文件启动！
    echo 若只有 k8s_commander_monolith.py 说明版本过旧，请重新复制新版。
    pause
    exit /b 1
)

if not exist "%~dp0data" mkdir "%~dp0data"
if not exist "%~dp0data\reports" mkdir "%~dp0data\reports"

echo 启动: k8s_commander.py
echo 数据将保存在: %~dp0data\
echo SOCKS5 代理需: pip install PySocks
echo.

python -c "import socks" 2>nul || echo [提示] 未安装 PySocks，SOCKS5 代理不可用。运行: pip install PySocks
echo.

python "%~dp0k8s_commander.py"
pause
