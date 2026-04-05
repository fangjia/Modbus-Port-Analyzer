# Modbus TCP 通訊埠狀態分析工具 (Port Analyzer)

本套工具設計用來自動化分析 `.pcap` 與 `.pcapng` 網路封包檔。主要目的為掃描指向特定伺服器的 Modbus/TCP 連線，並分析這些動態建立的 Client Ports 在通訊完成後，是否都有透過標準的 TCP 中斷協定 (`FIN` 或 `RST` 旗標) 正確地將連線釋放。藉此可以快速偵測 Client 端程式是否存有通訊埠洩漏 (Port Leak) 的隱患。

---

## 🛠️ 事前準備 (Prerequisites)

本分析腳本的核心底層是呼叫 Wireshark 的指令列引擎進行分析，因此在執行前請確認：
* 您的環境中已正確安裝 **Wireshark**。
* 系統中必須存在 `tshark.exe` (腳本會自動尋找 `C:\Program Files\Wireshark\` 目錄，或是向系統預設環境變數尋找)。

---

## 📂 檔案清單說明

* **`Run-Analyzer.bat`**：使用者的主要啟動入口。這是一個安全設定過的批次檔，內建避免中文亂碼的 UTF-8 設定，並且能調用最高權限一鍵觸發 PowerShell 腳本。
* **`Analyze-ModbusPorts.ps1`**：核心分析腳本程式。負責啟動 tshark 過濾器、構建終端機互動選單 (UI)、以及交叉比對釋放邏輯、產出報告。
* **`*_port_status.csv`** (腳本自動產生)：分析完成的報告。檔案記錄了每個使用過的 Port 以及它的最終釋放 (Released / Unclosed) 狀態。

---

## 🚀 快速上手教學 (Quick Start)

1. 將您側錄好的封包檔 (`.pcap` 或 `.pcapng`) 統一放在這個指令檔的資料夾下。
2. 對著 **`Run-Analyzer.bat`** 連續點擊滑鼠左鍵兩下執行。
3. 系統將會彈出水藍色的互動式選單，並列出目錄下的封包檔案。
4. 使用鍵盤的 **[↑] / [↓] 方向鍵** 選擇檔案，接著按下 **[Enter] 鍵** 。
5. 稍待數秒鐘，分析報告將自動顯示在畫面上，並輸出相對應的 CSV 報表檔至同目錄下供您利用 Excel 追蹤。

> **💡 智慧提示**：如果您身處於 IDE 或是未掛載標準控制台的環境執行，腳本將自動降級觸發「智慧防呆模式」，並提供您使用「**數字按鍵**」來完成選項的選取，防止系統崩潰。

---

## ⚙️ 進階設定 (Advanced Configurations)

如果您需要分析不同的 IP 目標對象、不同的 Modbus 埠口，您可以透過滑鼠右鍵「編輯」`Run-Analyzer.bat`，並在頂部的**變數區塊**自由修改：

```batch
:: 1. 欲分析的 pcapng 檔案 (留空代表啟動互動式選單)
SET PCAP_FILE=

:: 2. 伺服器端目標 IP
SET TARGET_IP="192.168.100.150"

:: 3. 伺服器端目標 Port (標準為502，因應客製化設定此處為33999)
SET TARGET_PORT=33999

:: 4. 欲過濾的 Modbus Unit ID (設備 ID)
SET UNIT_ID=0
```

*若在 `PCAP_FILE` 欄位指定了檔名（例如 `SET PCAP_FILE="my_capture.pcap"`），啟動時將會跳過選單環節，實現完全自動化的無人值守測試。*

---

## 🔬 判定邏輯說明

* **有效連線認定**：腳本會抓取所有發往目標 Port 且封包 Payload 中的 `unit_id` 符合設定的主動查詢連線。
* **已釋放 (`Released`)**：只要該 Port 與目標伺服器之間曾經發生過帶有 `FIN` 或者 `RST` 的封包傳輸，即視為成功中斷並釋放。
* **未釋放 (`Unclosed`)**：有發起查詢紀錄，但直到側錄封包檔結束之前，未曾捕獲到任何關閉連線的訊號。這可能意味著連線變成了孤兒連線 (Orphaned connection)。
