# Modbus TCP 通訊埠狀態分析工具 (Port Analyzer)

本套工具設計用來自動化分析 `.pcap` 與 `.pcapng` 網路封包檔。主要目的為掃描指向特定伺服器的 Modbus/TCP 連線，並分析這些動態建立的 Client Ports 在通訊完成後，是否都有透過標準的 TCP 中斷協定 (`FIN` 或 `RST` 旗標) 正確地將連線釋放。藉此可以快速偵測 Client 端程式是否存有通訊埠洩漏 (Port Leak) 的隱患。

---

## 🛠️ 事前準備 (Prerequisites)

本分析工具的核心底層是呼叫 Wireshark 的指令列引擎進行分析，因此在執行前請確認：
* 您的環境中已正確安裝 **Wireshark**。
* 系統中必須存在 `tshark.exe` (自動尋找 `C:\Program Files\Wireshark\` 目錄，或向系統預設環境變數尋找)。
* 若要使用 **Python 版本**，需安裝 **Python 3.7+**。

---

## 📂 檔案清單與目錄結構

* **`Run-Analyzer.bat`**：使用者的主要啟動入口。支持 PowerShell 和 Python 版本切換。
* **`src/Analyze-ModbusPorts.ps1`**：PowerShell 核心分析腳本。負責啟動 tshark 過濾器、構建終端機互動選單、交叉比對釋放邏輯、產出報告。
* **`src/Analyze-ModbusPorts.py`**：Python 核心分析腳本。具備相同功能，支持命令行參數，更便於自動化整合。
* **`data/`**：操作舞台，存放您的封包檔案與分析報告。
  * 請將側錄好的封包檔 (`.pcap` 或 `.pcapng`) 丟進此資料夾。
  * 分析完成後的 `.csv` 詳細報告、`_Summary.txt` 文字總結報告、`_RST_info.txt` RST 封包資訊，都會整齊地存放在這裡。

---

## 🚀 快速上手教學 (Quick Start)

### 方式一：使用批次檔啟動 (Batch File)

1. 將您側錄好的封包檔丟進 **`data/`** 資料夾下。
2. 對著 **`Run-Analyzer.bat`** 連續點擊滑鼠左鍵兩下執行。
3. 系統將會彈出互動式選單，並列出目錄下的封包檔案。
4. 使用鍵盤的 **[↑] / [↓] 方向鍵** 選擇檔案，接著按下 **[Enter] 鍵**。
5. 稍待數秒鐘，分析報告將自動顯示在畫面上，並輸出相應的 CSV 報表檔。

### 方式二：使用 Python 版本 (命令行)

```bash
# 基本用法
python src\Analyze-ModbusPorts.py --target-ip 192.168.100.150

# 指定封包檔、Unit ID
python src\Analyze-ModbusPorts.py --pcap-file data\capture.pcapng --target-ip 192.168.100.150 --unit-id 0

# 自訂輸出路徑
python src\Analyze-ModbusPorts.py --pcap-file data\capture.pcapng --target-ip 192.168.100.150 --target-port 33999 --output-file output\result.csv
```

### 方式三：使用批次檔切換版本

編輯 `Run-Analyzer.bat`，修改以下變數以選擇版本：

```batch
REM 使用 PowerShell 版本 (預設)
SET USE_PYTHON=0

REM 或使用 Python 版本
SET USE_PYTHON=1
SET PYTHON_EXE=python
```

---

## ⚙️ 進階設定 (Advanced Configurations)

### 批次檔設定變數

編輯 `Run-Analyzer.bat` 的頂部**變數區塊**自由修改：

```batch
:: 1. 欲分析的 pcapng 檔案 (留空代表啟動互動式選單)
SET PCAP_FILE=

:: 2. 伺服器端目標 IP
SET TARGET_IP="192.168.100.150"

:: 3. 伺服器端目標 Port (標準為 502，客製化此處為 33999)
SET TARGET_PORT=33999

:: 4. 欲過濾的 Modbus Unit ID (設備 ID)
SET UNIT_ID=

:: 5. 自訂輸出 CSV 檔名 (留空自動產生)
SET OUTPUT_FILE=

:: 6. 選擇分析器版本 (0=PowerShell, 1=Python)
SET USE_PYTHON=0
SET PYTHON_EXE=python
```

### Python 命令行參數

```
--pcap-file PCAP_FILE          要分析的 pcap/pcapng 檔案路徑
--target-ip TARGET_IP          伺服器端目標 IP (必需)
--target-port TARGET_PORT      伺服器端 Port，預設 33999
--unit-id UNIT_ID              Modbus Unit ID，若未指定則互動式輸入
--output-file OUTPUT_FILE      輸出 CSV 檔案路徑，若未指定則自動產生
--help                         顯示幫助訊息
```

---

## 📊 輸出檔案說明

分析完成後會產出三類報告：

1. **`*_Unit{ID}_port_status.csv`**
   - 詳細的 Port 狀態清單
   - 欄位：`Port`, `Status`, `UnitID`, `QueriedUnitIDs`
   - 未釋放 Port 會列出對應的 Modbus Unit ID 清單

2. **`*_Unit{ID}_port_status_Summary.txt`**
   - 人類可讀的分析總結報告
   - 包含側錄時間、通訊統計、未釋放 Port 表格等

3. **`*_Unit{ID}_port_status_RST_info.txt`**
   - RST 封包完整詳情
   - 包含所有觸發 RST 旗標的封包資訊

---

## 🔬 判定邏輯說明

* **有效連線認定**：腳本會抓取所有發往目標 Port 且封包 Payload 中的 `unit_id` 符合設定的主動查詢連線。
* **已釋放 (`Released`)**：該 Port 與目標伺服器之間曾經發生過帶有 `FIN` 或 `RST` 的封包傳輸，即視為成功中斷並釋放。
* **未釋放 (`Unclosed`)**：有發起查詢紀錄，但直到側錄封包檔結束之前，未曾捕獲到任何關閉連線的訊號，可能成為孤兒連線 (Orphaned connection)。
* **Unit ID 對應**：對每個未釋放 Port，腳本會追蹤其在通訊過程中查詢過的所有 Modbus Unit ID。

---

## 📝 版本差異

| 功能 | PowerShell | Python |
|------|-----------|--------|
| 互動式選單 | ✅ | ✅ (命令行) |
| 自動化無人值守 | ⚠️ (需預設參數) | ✅ (完整命令行支持) |
| 跨平台 | ❌ (Windows Only) | ✅ (可移植) |
| 易於集成 | ⚠️ | ✅ |
| 性能 | 適中 | 略快 |
