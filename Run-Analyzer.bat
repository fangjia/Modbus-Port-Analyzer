@echo off
chcp 65001 >nul
REM =============================================
REM  Modbus Port Analyzer - Interactive Menu Launcher
REM =============================================
echo Starting Modbus Port Analyzer...
echo.

REM ---------------------------------------------------------
REM CONFIGURATION VARIABLES
REM ---------------------------------------------------------
REM 1. Target pcapng or pcap file name
REM Leave blank to use interactive menu selection!
SET PCAP_FILE=

REM 2. Target server IP
SET TARGET_IP="192.168.100.150"

REM 3. Target server Port (Standard Modbus is 502, here 33999)
SET TARGET_PORT=33999

REM 4. Target Modbus Unit ID (Leave blank to prompt interactively!)
SET UNIT_ID=

REM 5. Custom output CSV file name (Leave blank to auto-generate)
SET OUTPUT_FILE=

REM ---------------------------------------------------------
REM EXECUTION LOGIC
REM ---------------------------------------------------------
SET OUTPUT_PARAM=
if not "%OUTPUT_FILE%"=="" (
    SET OUTPUT_PARAM=-OutputFile %OUTPUT_FILE%
)

SET PCAP_PARAM=
if not "%PCAP_FILE%"=="" (
    SET PCAP_PARAM=-PcapFile %PCAP_FILE%
)

SET UNIT_PARAM=
if not "%UNIT_ID%"=="" (
    SET UNIT_PARAM=-UnitId %UNIT_ID%
)

PowerShell -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Analyze-ModbusPorts.ps1" %PCAP_PARAM% -TargetIP "%TARGET_IP:"=%" -TargetPort %TARGET_PORT% %UNIT_PARAM% %OUTPUT_PARAM%

echo.
echo =============================================
echo   Analysis Complete. Press any key to exit.
echo =============================================
pause >nul
