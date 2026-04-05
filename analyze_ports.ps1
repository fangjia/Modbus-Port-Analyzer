$pcap = "d:\CODE\2MW_EMS_CommunicationError\outport_202604060018.pcapng"
$tshark = "C:\Program Files\Wireshark\tshark.exe"

Write-Host "[1/3] 取得 Unit 0 所使用的 Source Ports..."
$unit0_ports = & $tshark -r $pcap -Y "ip.dst == 192.168.100.150 and tcp.dstport == 33999 and mbtcp.unit_id == 0" -T fields -e tcp.srcport | Sort-Object -Unique

Write-Host "[2/3] 取得所有有 FIN 或 RST 標記的連線 (已釋放的 ports)..."
$closed_ports_src = & $tshark -r $pcap -Y "ip.addr == 192.168.100.150 and tcp.port == 33999 and (tcp.flags.fin == 1 or tcp.flags.reset == 1)" -T fields -e tcp.srcport | Sort-Object -Unique
$closed_ports_dst = & $tshark -r $pcap -Y "ip.addr == 192.168.100.150 and tcp.port == 33999 and (tcp.flags.fin == 1 or tcp.flags.reset == 1)" -T fields -e tcp.dstport | Sort-Object -Unique

$closed_ports = ($closed_ports_src + $closed_ports_dst) | Where-Object { $_ -ne '33999' -and $_ -match '\d+' } | Sort-Object -Unique

Write-Host "[3/3] 分析結果並輸出至 CSV..."
$output_file = "d:\CODE\2MW_EMS_CommunicationError\unit0_ports_status.csv"
"Port,Status" | Out-File $output_file -Encoding utf8

$releasedCount = 0
$unreleasedCount = 0

foreach ($port in $unit0_ports) {
    if (-not ($port -match '\d+')) { continue }
    if ($closed_ports -contains $port) {
        $status = "已釋放 (Released)"
        $releasedCount++
    } else {
        $status = "未釋放 (Unclosed)"
        $unreleasedCount++
    }
    "$port,$status" | Out-File $output_file -Append -Encoding utf8
}

Write-Host "分析完成！"
Write-Host "總計: $($releasedCount + $unreleasedCount) 個 Port"
Write-Host "已釋放: $releasedCount 個"
Write-Host "未釋放: $unreleasedCount 個"
