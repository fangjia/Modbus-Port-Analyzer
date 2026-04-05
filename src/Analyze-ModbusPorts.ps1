<#
.SYNOPSIS
    分析 Pcap/Pcapng 檔案中 Modbus TCP Query 的 Port 釋放狀態。
.DESCRIPTION
    此工具利用 TShark (Wireshark) 讀取封包檔，並分析針對指定目標 IP 與特定 Unit ID 的查詢 (Query) 連線。
    接著比對這些連線的 Port 是曾否送出或收到 FIN 或 RST 中斷交握，產出「已釋放」與「未釋放」的狀態清單。
.PARAMETER PcapFile
    (必要) 指定要分析的 .pcap 或 .pcapng 檔案路徑。
.PARAMETER TargetIP
    (必要) 指定伺服器端 (目標端) 的 IP 地址。
.PARAMETER TargetPort
    (選用) 指定伺服器端的 Port，預設為 33999。
.PARAMETER UnitId
    (選用) 指定要查詢的 Modbus Unit ID，預設為 0。
.PARAMETER OutputFile
    (選用) 匯出的 CSV 檔案路徑。若未指定，則輸出至原始檔案同一個目錄下，檔名自動附加字尾。
.EXAMPLE
    # 在命令提示字元或 PowerShell 下執行:
    .\Analyze-ModbusPorts.ps1 -PcapFile "outport_202604060018.pcapng" -TargetIP "192.168.100.150"
#>
param(
    [Parameter(Mandatory=$false, HelpMessage="請輸入要分析的 pcap/pcapng 檔案路徑")]
    [string]$PcapFile,
    
    [Parameter(Mandatory=$true, HelpMessage="請輸入伺服器端目標 IP (如: 192.168.100.150)")]
    [string]$TargetIP,
    
    [Parameter(Mandatory=$false)]
    [int]$TargetPort = 33999,
    
    [Parameter(Mandatory=$false)]
    [int]$UnitId = 0,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile
)

# 1. 確認 tshark 安裝路徑
$tsharkPaths = @(
    "C:\Program Files\Wireshark\tshark.exe",
    "C:\Program Files (x86)\Wireshark\tshark.exe"
)
$tsharkPath = $null
foreach ($path in $tsharkPaths) {
    if (Test-Path $path) {
        $tsharkPath = $path
        break
    }
}
if (-not $tsharkPath) {
    # 如果預設路徑找不到，嘗試由環境變數尋找
    $tsharkInPath = Get-Command "tshark.exe" -ErrorAction SilentlyContinue
    if ($tsharkInPath) {
        $tsharkPath = $tsharkInPath.Source
    } else {
        Write-Error "找不到 tshark 工具！請確認系統有安裝 Wireshark 並包含 tshark.exe。"
        exit 1
    }
}

# 2. 驗證或選擇來源檔案
if (-not $PcapFile) {
    # 如果未指定，則掃描 ../data 目錄下的封包檔
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $dataDir = Join-Path $scriptDir "..\data"
    if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir -Force | Out-Null }
    
    $files = @(Get-ChildItem -Path $dataDir -File | Where-Object { $_.Extension -match '^\.pcap(?:ng)?$' } | Select-Object -ExpandProperty Name)
    if ($files.Count -eq 0) {
        Write-Error "未提供 -PcapFile 參數，且當前目錄下找不到任何 .pcapng 或 .pcap 檔案！"
        exit 1
    } elseif ($files.Count -eq 1) {
        $PcapFile = Join-Path $dataDir $files[0]
        Write-Host "自動選擇 data 目錄中唯一的封包檔: $($files[0])" -ForegroundColor Yellow
    } else {
        $selectedIndex = 0
        try { [System.Console]::CursorVisible = $false } catch {}
        try {
            while ($true) {
                # 偵測是否為非互動式環境或背景執行
                $isRedirected = $true
                try { $isRedirected = [System.Console]::IsInputRedirected } catch {}
                
                if ($isRedirected) {
                    Write-Host "=================================================" -ForegroundColor Cyan
                    Write-Host " 偵測到終端機不支援方向鍵選單，請手動選擇" -ForegroundColor White
                    Write-Host "=================================================" -ForegroundColor Cyan
                    for ($i = 0; $i -lt $files.Count; $i++) {
                        Write-Host "  [$i] $($files[$i])"
                    }
                    Write-Host ""
                    $sel = Read-Host "請輸入括號內的數字編號"
                    if ($sel -match '^\d+$' -and [int]$sel -lt $files.Count) {
                        $PcapFile = Join-Path $dataDir $files[[int]$sel]
                        break
                    } else {
                        Write-Error "選擇無效或取消。"
                        exit 1
                    }
                }

                Clear-Host
                Write-Host "=================================================" -ForegroundColor Cyan
                Write-Host " 請使用鍵盤方向鍵 [↑] [↓] 選擇要分析的封包檔" 
                Write-Host " 選擇完畢後按下 [Enter] 開始分析，按 [Esc] 退出"
                Write-Host "=================================================" -ForegroundColor Cyan
                for ($i = 0; $i -lt $files.Count; $i++) {
                    if ($i -eq $selectedIndex) {
                        Write-Host "  ▶ $($files[$i]) " -ForegroundColor Black -BackgroundColor Cyan
                    } else {
                        Write-Host "    $($files[$i])"
                    }
                }
                Write-Host ""
                
                $key = $null
                try { $key = [System.Console]::ReadKey($true) } catch { 
                    Write-Error "終端不支援鍵盤擷取，請使用參數 -PcapFile 指定檔案。"
                    exit 1
                }
                
                if ($key.Key -eq 'UpArrow') {
                    $selectedIndex--
                    if ($selectedIndex -lt 0) { $selectedIndex = $files.Count - 1 }
                } elseif ($key.Key -eq 'DownArrow') {
                    $selectedIndex++
                    if ($selectedIndex -ge $files.Count) { $selectedIndex = 0 }
                } elseif ($key.Key -eq 'Enter') {
                    $PcapFile = Join-Path $dataDir $files[$selectedIndex]
                    Clear-Host
                    break
                } elseif ($key.Key -eq 'Escape') {
                    Clear-Host
                    Write-Host "已取消操作。" -ForegroundColor Red
                    exit 0
                }
            }
        } finally {
            try { [System.Console]::CursorVisible = $true } catch {}
        }
        
        # 二次防護，避免 null 導致後方全部崩潰
        if ([string]::IsNullOrWhiteSpace($PcapFile)) {
            Write-Error "檔案選擇不正確或已取消。"
            exit 1
        }
    }
} elseif (-not (Test-Path $PcapFile)) {
    Write-Error "找不到指定的封包檔案: $PcapFile"
    exit 1
}

# 3. 處理預設輸出檔案路徑
if (-not $OutputFile) {
    $parent = [System.IO.Path]::GetDirectoryName($PcapFile)
    if ([string]::IsNullOrEmpty($parent)) { $parent = ".\" }
    $name = [System.IO.Path]::GetFileNameWithoutExtension($PcapFile)
    $OutputFile = Join-Path $parent "${name}_Unit${UnitId}_port_status.csv"
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Modbus TCP 連線埠口狀態分析工具 (Port Analyzer)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "📂 封包檔案: $PcapFile"
Write-Host "🎯 通訊目標: $TargetIP : $TargetPort (Modbus Unit ID: $UnitId)"
Write-Host "🛠️ TShark   : $tsharkPath"
Write-Host "---------------------------------------------"

# 步驟1: 提取送出特定 Unit ID 查詢過的 Ports
Write-Host "[1/3] 正在提取所有對 Unit $UnitId 進行查詢的 Source Ports..." -ForegroundColor Yellow
$filterQuery = "ip.dst == $TargetIP and tcp.dstport == $TargetPort and mbtcp.unit_id == $UnitId"
Write-Host "      指令掃描中... (大型檔案可能需要數十秒)"
$unitPorts = & $tsharkPath -r $PcapFile -Y $filterQuery -T fields -e tcp.srcport | Sort-Object -Unique
$validUnitPorts = $unitPorts | Where-Object { $_ -match '^\d+$' }
Write-Host "      ✔️ 統計: 共使用 $($validUnitPorts.Count) 個獨立的 Source Ports。" -ForegroundColor Green

# 步驟2: 提取通訊階段有過 FIN 或 RST 的 Ports (代表連線被正常關閉或重置)
Write-Host "[2/3] 正在建立並掃描由 FIN 或 RST 終止的已釋放連線池..." -ForegroundColor Yellow
$filterClosed = "ip.addr == $TargetIP and tcp.port == $TargetPort and (tcp.flags.fin == 1 or tcp.flags.reset == 1)"
Write-Host "      指令掃描中..."
$closedPortsSrc = & $tsharkPath -r $PcapFile -Y $filterClosed -T fields -e tcp.srcport | Sort-Object -Unique
$closedPortsDst = & $tsharkPath -r $PcapFile -Y $filterClosed -T fields -e tcp.dstport | Sort-Object -Unique
$closedPorts = ($closedPortsSrc + $closedPortsDst) | Where-Object { $_ -ne $TargetPort.ToString() -and $_ -match '^\d+$' } | Sort-Object -Unique
Write-Host "      ✔️ 掃描完成。" -ForegroundColor Green

# 步驟3: 兩邊資料進行比對，寫入最終狀態
Write-Host "[3/3] 正在進行交叉比對並匯出狀態清單至 CSV..." -ForegroundColor Yellow
$releasedCount = 0
$unclosedCount = 0

"Port,Status,UnitID" | Out-File -FilePath $OutputFile -Encoding UTF8
foreach ($port in $validUnitPorts) {
    if ($closedPorts -contains $port) {
        $status = "已釋放 (Released)"
        $releasedCount++
    } else {
        $status = "未釋放 (Unclosed)"
        $unclosedCount++
    }
    "$port,$status,$UnitId" | Out-File -FilePath $OutputFile -Append -Encoding UTF8
}

$reportFile = $OutputFile -replace '\.csv$', '_Summary.txt'
$reportContent = @"
=============================================
📜 Modbus TCP 分析總結報告
=============================================
🕒 分析時間: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
📂 來源封包: $PcapFile
🎯 通訊目標: $TargetIP : $TargetPort (Unit ID: $UnitId)

📊 分析統計:
---------------------------------------------
📦 參與查詢的總 Port 數 : $($releasedCount + $unclosedCount)
  ✔️ 已正確釋放  (FIN/RST): $releasedCount
  ❌ 未釋放 (無交握中斷記錄): $unclosedCount

"@

if ($unclosedCount -gt 0) {
    $reportContent += "`n⚠️ 警告：發現 $unclosedCount 個未正確關閉可能洩漏的 Ports：`n"
    # 取出未釋放的 ports
    $unclosedPortsList = @()
    foreach ($p in $validUnitPorts) {
        if (-not ($closedPorts -contains $p)) { $unclosedPortsList += $p }
    }
    $reportContent += ($unclosedPortsList -join ', ') + "`n"
} else {
    $reportContent += "`n✅ 恭喜：所有被檢測出的連線埠口皆已被伺服器或客戶端完美釋放！`n"
}

$reportContent | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "--------------------------------------------="
Write-Host "🎉 分析處理完成！" -ForegroundColor Cyan
Write-Host "📦 參與查詢的總 Port 數 : $($releasedCount + $unclosedCount)"
Write-Host "  ✔️ 已正確釋放  (FIN/RST): $releasedCount" -ForegroundColor Green
Write-Host "  ❌ 未釋放 (無交握中斷記錄): $unclosedCount" -ForegroundColor Red
Write-Host ""
Write-Host "📊 詳細資料 CSV 已匯出至: $OutputFile" -ForegroundColor Yellow
Write-Host "📝 整體總結報告 已匯出至: $reportFile" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Cyan
