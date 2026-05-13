@echo off
setlocal EnableDelayedExpansion
::set WORKSPACE=2MW
::set WORKSPACE=HOME
SET WORKSPACE=undefine

::----------------------------------------------------
:: 切換編碼到 UTF-8，讓 dumpcap -D 顯示盡量正常
chcp 65001 >nul

:: =============================================
:: Wireshark dumpcap 抓包批次檔 - 處理中文亂碼版 (已修正 ring buffer)
:: =============================================
echo.
echo =============================================
echo  Wireshark dumpcap 抓包工具 (中文亂碼處理)
echo =============================================
echo.

::----------------------------------------------------
echo 選擇要進行的工作環境...
echo.
echo 1. WORKSPACE=2MW
ECHO 2. WORKSPACE=HOME TEST
echo.
echo 注意：如果上面介面名稱還是亂碼，請忽略名稱，直接看前面的數字編號 (如 1.  2. 等)
echo.

set /p INTERFACE_NUM=請輸入要抓包的介面編號 (例如 1 或 2)： 

if "!INTERFACE_NUM!"=="" (
    echo 錯誤：未輸入編號
    pause
    exit /b
) ELSE IF "!INTERFACE_NUM!"=="1" (
    SET WORKSPACE=2MW

) ELSE IF "!INTERFACE_NUM!"=="2" (
    SET WORKSPACE=HOME

) ELSE (
    echo 錯誤：未輸入正確編號
    pause
    exit /b 1
)

ECHO WORKSPACE=%WORKSPACE%

:: Determine CAPTURE_FILTER based on WORKSPACE selection
IF "!WORKSPACE!"=="2MW" GOTO set_filter_2MW
IF "!WORKSPACE!"=="HOME" GOTO set_filter_HOME

:: Default or error handling if WORKSPACE is not set
echo 錯誤：工作環境未定義或選擇錯誤。
pause
exit /b 1

:set_filter_2MW
    echo.
    echo 選擇抓包濾鏡條件...
    echo 1. 僅限主機 IP (host 192.168.100.150)
    echo 2. 主機 IP 與 TCP 埠 (host 192.168.100.150 and tcp port 33999)
    echo.
    set /p FILTER_CHOICE=請輸入要使用的濾鏡編號 (例如 1 或 2)：

    if "!FILTER_CHOICE!"=="" (
        echo 錯誤：未輸入濾鏡編號
        pause
        exit /b
    ) ELSE IF "!FILTER_CHOICE!"=="1" (
        set CAPTURE_FILTER=host 192.168.100.150
        echo DEBUG: CAPTURE_FILTER set to !CAPTURE_FILTER! for choice 1
    ) ELSE IF "!FILTER_CHOICE!"=="2" (
        set CAPTURE_FILTER=host 192.168.100.150 and tcp port 33999
        echo DEBUG: CAPTURE_FILTER set to !CAPTURE_FILTER! for choice 2
    ) ELSE (
        echo 錯誤：未輸入正確的濾鏡編號
        pause
        exit /b 1
    )
GOTO continue_filter_setup

:set_filter_HOME
    set CAPTURE_FILTER=host 192.168.2.235
    echo DEBUG: CAPTURE_FILTER set to !CAPTURE_FILTER! for HOME workspace
    ::set CAPTURE_FILTER=host 203.69.91.30
    ::set CAPTURE_FILTER=host 203.69.91.26
GOTO continue_filter_setup

:continue_filter_setup
pause

:: 先切換到 Wireshark 安裝目錄（請依你的實際路徑修改）
::cd /d "C:\Program Files\Wireshark"
::if not exist dumpcap.exe (
::    echo 錯誤：找不到 dumpcap.exe，請確認 Wireshark 已安裝在 C:\Program Files\Wireshark
::    pause
::    exit /b
::)
PATH=%PATH%;C:\Program Files\Wireshark;

::================================================================================================
:: 輸出檔案前綴（會自動產生 modbus_capture_00001.pcapng 等）
set OUTPUT_PREFIX=modbusCapture
set OUTPUT_DIR=Capture
::set OUTPUT_FILE=%OUTPUT_DIR%\%OUTPUT_PREFIX%_%date:~0,4%%date:~5,2%%date:~8,2%_%time:~0,2%%time:~3,2%.pcapng
set OUTPUT_FILE=%OUTPUT_DIR%\%OUTPUT_PREFIX%_.pcapng
:: 會自動產生像 modbus_20260216_12 34.pcapng 的檔名（時間有空格會變成底線或直接用）

::================================================================================================
:: 每個檔案大小上限（單位 KB，50MB = 50000）
IF %WORKSPACE%==2MW (
    set FILE_SIZE=50000
) else (
    set FILE_SIZE=100000
)


::================================================================================================
:: 環狀緩衝區檔數（只保留最近 10 個檔，舊的自動覆蓋）
IF %WORKSPACE%==2MW (
    set RING_COUNT=500
) ELSE (
    set RING_COUNT=10
)

::================================================================================================
:: 其他選項（-q 安靜模式，-B 64MB 核心緩衝）
IF %WORKSPACE%==2MW (
    set EXTRA_OPTS=-q -B 64
) ELSE (
    set EXTRA_OPTS=-B 64 -s 256 -C 200000000 -N 200000
)

::================================================================================================
:: 自訂抓包參數（可在此修改）
:: =============================================
:: 抓包濾鏡（BPF 語法），預設抓你的 Modbus 非標準埠 + 特定主機
::set CAPTURE_FILTER=tcp port 60488 or tcp port 23999 or host 192.168.100.157
::---------------------------------------------
:: 2MW
::----------------------------
::  BSU IPC: 192.168.100.150
::  EMS IPC: 192.168.100.29
::  DB IPC: 192.168.100.157


:: ------------------- 不要亂改下面 -------------------


::----------------------------------------------------
:: 切換編碼到 UTF-8，讓 dumpcap -D 顯示盡量正常
chcp 65001 >nul

::----------------------------------------------------
echo 正在列出網路介面...
echo.
dumpcap -D
echo.

echo 注意：如果上面介面名稱還是亂碼，請忽略名稱，直接看前面的數字編號 (如 1.  2. 等)
echo.

set /p INTERFACE_NUM=請輸入要抓包的介面編號 (例如 1 或 2)： 

if "!INTERFACE_NUM!"=="" (
    echo 錯誤：未輸入編號
    pause
    exit /b
)

echo.
echo === Wireshark dumpcap 抓包工具（中文系統亂碼處理版） ===
echo.
echo 開始抓包...
echo.
echo 設定環境   : WORKSPACE=        %WORKSPACE%
echo 追蹤IP     : CAPTURE_FILTER=   !CAPTURE_FILTER!
echo 介面編號   : INTERFACE_NUM=    !INTERFACE_NUM!
echo 輸出檔案   : OUTPUT_FILE=      %OUTPUT_FILE% 
echo 每個檔大小 : FILE_SIZE=        %FILE_SIZE% KB
echo 保留檔數   : RING_COUNT=       %RING_COUNT% 個 (環狀覆蓋)
echo.
echo Ctrl-C to Break...
pause

::----------------------------------------------------
:: 建立輸出目錄（如果不存在）
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"


:: 正確的 ring buffer 語法：-b filesize: + -b files:
echo dumpcap -i !INTERFACE_NUM! -f "!CAPTURE_FILTER!" -b filesize:%FILE_SIZE% -b files:%RING_COUNT% -w "%OUTPUT_FILE%" %EXTRA_OPTS%

pause

echo DEBUG: Final CAPTURE_FILTER before dumpcap: !CAPTURE_FILTER!

dumpcap -i !INTERFACE_NUM! -f "!CAPTURE_FILTER!" -b filesize:%FILE_SIZE% -b files:%RING_COUNT% -w "%OUTPUT_FILE%" %EXTRA_OPTS%

echo.
echo 抓包已結束（或按 Ctrl+C 停止）
pause