import argparse
import csv
import os
import subprocess
import sys
from pathlib import Path


def find_tshark() -> tuple[Path, Path | None]:
    candidates = [
        Path("C:/Program Files/Wireshark/tshark.exe"),
        Path("C:/Program Files (x86)/Wireshark/tshark.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            capinfos = candidate.parent / "capinfos.exe"
            return candidate, capinfos if capinfos.exists() else None

    try:
        result = subprocess.run(["tshark", "-v"], capture_output=True, text=True, check=True)
        tshark_path = Path("tshark")
        return tshark_path, None
    except FileNotFoundError:
        raise FileNotFoundError(
            "找不到 tshark 工具！請確認系統已安裝 Wireshark 並且 tshark.exe 可用。"
        )
    except subprocess.CalledProcessError:
        return Path("tshark"), None


def run_command(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(
            f"執行命令失敗: {' '.join(command)}\n{result.stderr.strip()}"
        )
    return result.stdout


def choose_pcap_file(data_dir: Path) -> Path:
    if not data_dir.exists():
        data_dir.mkdir(parents=True, exist_ok=True)

    files = sorted([p for p in data_dir.iterdir() if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng"}])
    if not files:
        raise FileNotFoundError(
            f"未指定 -PcapFile，且資料目錄 {data_dir} 中找不到 .pcap/.pcapng 檔案。"
        )
    if len(files) == 1:
        print(f"自動選擇 data 目錄中唯一的封包檔: {files[0].name}")
        return files[0]

    print("請選擇要分析的封包檔案:")
    for idx, pcap in enumerate(files, start=1):
        print(f"  [{idx}] {pcap.name}")
    while True:
        choice = input("輸入編號並按 Enter 以繼續，或輸入 q 取消: ").strip()
        if choice.lower() == "q":
            raise SystemExit("已取消操作。")
        if choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(files):
                return files[index]
        print("輸入無效，請重新輸入。")


def ask_unit_id(default: str = "0") -> str:
    user = input("請輸入欲分析的 Modbus Unit ID (按 Enter 預設為 0): ").strip()
    if not user:
        return default
    if user.isdigit():
        return user
    raise ValueError("輸入無效！Unit ID 必須為數字。")


def parse_ports(output: str) -> list[str]:
    return sorted({line.strip() for line in output.splitlines() if line.strip().isdigit()}, key=int)


def write_csv(output_file: Path, rows: list[tuple[str, str, str, str]], header: str = "Port,Status,UnitID,QueriedUnitIDs") -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(header.split(","))
        for port, status, unit_id, queried_unit_ids in rows:
            writer.writerow([port, status, unit_id, queried_unit_ids])


def write_text(output_file: Path, content: str) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8", newline="") as f:
        f.write(content)


def get_capinfos_summary(capinfos_path: Path, pcap_file: Path) -> tuple[str, str]:
    try:
        text = run_command([str(capinfos_path), "-u", "-a", "-e", str(pcap_file)])
        duration = "未知/無法取得"
        start = "未知/無法取得"
        end = None
        for line in text.splitlines():
            if line.startswith("Capture duration:"):
                duration = line.split("Capture duration:", 1)[1].strip()
            elif line.startswith("Earliest packet time:"):
                start = line.split("Earliest packet time:", 1)[1].strip()
            elif line.startswith("Latest packet time:"):
                end = line.split("Latest packet time:", 1)[1].strip()
        time_range = f"{start} ~ {end}" if end else start
        return duration, time_range
    except Exception:
        return "未知/無法取得", "未知/無法取得"


def batch_port_uid_mappings(
    tshark_path: Path,
    pcap_file: Path,
    target_ip: str,
    target_port: int,
    unclosed_ports: list[str],
    batch_size: int = 200,
) -> dict[str, set[str]]:
    mappings: dict[str, set[str]] = {}
    for i in range(0, len(unclosed_ports), batch_size):
        batch = unclosed_ports[i : i + batch_size]
        port_filters = [f"tcp.srcport == {port}" for port in batch]
        filter_expr = (
            f"ip.dst == {target_ip} and tcp.dstport == {target_port} and ({' or '.join(port_filters)}) and mbtcp.unit_id"
        )
        output = run_command(
            [
                str(tshark_path),
                "-r",
                str(pcap_file),
                "-Y",
                filter_expr,
                "-T",
                "fields",
                "-e",
                "tcp.srcport",
                "-e",
                "mbtcp.unit_id",
            ]
        )
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            srcport, uid = parts[0].strip(), parts[1].strip()
            if not srcport.isdigit() or not uid.isdigit():
                continue
            mappings.setdefault(srcport, set()).add(uid)
    return mappings


def main() -> int:
    parser = argparse.ArgumentParser(description="Modbus TCP Port Analyzer for pcap/pcapng files.")
    parser.add_argument("--pcap-file", help="要分析的 pcap/pcapng 檔案。")
    parser.add_argument("--target-ip", required=True, help="伺服器端目標 IP。")
    parser.add_argument("--target-port", type=int, default=33999, help="伺服器端 Port，預設 33999。")
    parser.add_argument("--unit-id", help="Modbus Unit ID，若未指定則互動式輸入。")
    parser.add_argument("--output-file", help="輸出 CSV 檔案路徑。若未指定，將自動產生。")
    args = parser.parse_args()

    try:
        unit_id = args.unit_id.strip() if args.unit_id is not None else ""
    except Exception:
        unit_id = ""

    if not unit_id:
        try:
            unit_id = ask_unit_id("0")
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 1

    script_root = Path(__file__).resolve().parent.parent
    data_dir = script_root / "data"

    if args.pcap_file:
        pcap_file = Path(args.pcap_file).expanduser().resolve()
        if not pcap_file.exists():
            print(f"找不到指定的封包檔案: {pcap_file}", file=sys.stderr)
            return 1
    else:
        try:
            pcap_file = choose_pcap_file(data_dir)
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except SystemExit as exc:
            print(exc)
            return 0

    if not args.output_file:
        output_file = pcap_file.with_name(f"{pcap_file.stem}_Unit{unit_id}_port_status.csv")
    else:
        output_file = Path(args.output_file).expanduser().resolve()

    try:
        tshark_path, capinfos_path = find_tshark()
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1

    print("=============================================")
    print("Modbus TCP 連線埠口狀態分析工具 (Port Analyzer)")
    print("=============================================")
    print(f"📂 封包檔案: {pcap_file}")
    print(f"🎯 通訊目標: {args.target_ip} : {args.target_port} (Modbus Unit ID: {unit_id})")
    print(f"🛠️ TShark   : {tshark_path}")
    print("---------------------------------------------")

    filter_query = (
        f"ip.dst == {args.target_ip} and tcp.dstport == {args.target_port} and mbtcp.unit_id == {unit_id}"
    )
    print(f"[1/4] 正在提取所有對 Unit {unit_id} 進行查詢的 Source Ports...")
    # print(f" run_command({tshark_path}, -r {pcap_file}, -Y '{filter_query}', -T fields, -e tcp.srcport  )\n    ")
    output = run_command(
        [
            str(tshark_path),
            "-r",
            str(pcap_file),
            "-Y",
            filter_query,
            "-d tcp.port==33999,mbtcp",
            "-T",
            "fields",
            "-e",
            "tcp.srcport",
        ]
    )
    # print(f" {valid_unit_ports} \n    ")
    valid_unit_ports = parse_ports(output)
    
    
    print(f"      ✔️ 統計: 共使用 {len(valid_unit_ports)} 個獨立的 Source Ports。")

    filter_closed = (
        f"ip.addr == {args.target_ip} and tcp.port == {args.target_port} and (tcp.flags.fin == 1 or tcp.flags.reset == 1)"
    )
    print("[2/4] 正在建立並掃描由 FIN 或 RST 終止的已釋放連線池...")
    closed_src = run_command(
        [
            str(tshark_path),
            "-r",
            str(pcap_file),
            "-Y",
            filter_closed,
            "-T",
            "fields",
            "-e",
            "tcp.srcport",
        ]
    )
    closed_dst = run_command(
        [
            str(tshark_path),
            "-r",
            str(pcap_file),
            "-Y",
            filter_closed,
            "-T",
            "fields",
            "-e",
            "tcp.dstport",
        ]
    )
    closed_ports = set(parse_ports(closed_src) + parse_ports(closed_dst))
    closed_ports.discard(str(args.target_port))
    print("      ✔️ 掃描完成。")

    rows = []
    released_count = 0
    unclosed_count = 0
    unclosed_ports = []
    for port in valid_unit_ports:
        if port in closed_ports:
            status = "已釋放 (Released)"
            released_count += 1
        else:
            status = "未釋放 (Unclosed)"
            unclosed_count += 1
            unclosed_ports.append(port)
        rows.append((port, status, unit_id, ""))

    port_to_uids: dict[str, set[str]] = {}
    if unclosed_ports:
        port_to_uids = batch_port_uid_mappings(
            tshark_path,
            pcap_file,
            args.target_ip,
            args.target_port,
            unclosed_ports,
        )

    rows = [
        (
            port,
            status,
            unit_id,
            ", ".join(sorted(port_to_uids.get(port, []), key=int)) if port in unclosed_ports else "",
        )
        for port, status, unit_id, _ in rows
    ]

    write_csv(output_file, rows)
    print("[3/4] 已匯出 CSV 狀態清單。")

    filter_rst = f"ip.addr == {args.target_ip} and tcp.port == {args.target_port} and tcp.connection.rst"
    print("[4/4] 正在提取 RST (Connection Reset) 封包資訊...")
    rst_raw = run_command(
        [
            str(tshark_path),
            "-r",
            str(pcap_file),
            "-Y",
            filter_rst,
        ]
    )
    rst_lines = [line for line in rst_raw.splitlines() if line.strip()]
    rst_count = len(rst_lines)
    rst_file = output_file.with_name(f"{output_file.stem}_RST_info.txt")
    if rst_count > 0:
        header = [
            " [Idx]  Frame    Time           Source                → Destination           Protocol Length Info",
            "------------------------------------------------------------------------------------------------",
        ]
        write_text(rst_file, "\n".join(header + [f" [{idx+1:>3}] {line}" for idx, line in enumerate(rst_lines)]))
        print(f"      🔍 統計: 找到 {rst_count} 筆 RST 封包，已獨立匯出至文字檔")
    else:
        write_text(rst_file, "未找到符合過濾條件的 RST 封包。\n")
        print("      ❌ 統計: 找不到符合過濾條件的 RST 封包")

    duration_str = "未知/無法取得"
    time_range_str = "未知/無法取得"
    if capinfos_path:
        duration_str, time_range_str = get_capinfos_summary(capinfos_path, pcap_file)

    report_file = output_file.with_name(f"{output_file.stem}_Summary.txt")
    report_lines = [
        "=============================================",
        "📜 Modbus TCP 分析總結報告",
        "=============================================",
        f"⏱️ 側錄時間: {time_range_str}",
        f"⏳ 側錄長度: {duration_str}",
        f"📂 來源封包: {pcap_file}",
        f"🎯 通訊目標: {args.target_ip} : {args.target_port} (Unit ID: {unit_id})",
        "",
        "📊 分析統計:",
        "---------------------------------------------",
        f"📦 參與查詢的總 Port 數 : {released_count + unclosed_count}",
        f"  ✔️ 已正確釋放  (FIN/RST): {released_count}",
        f"  ❌ 未釋放 (無交握中斷記錄): {unclosed_count}",
        f"  🔌 RST 封包總數            : {rst_count} (過濾條件: tcp.connection.rst)",
        "",
    ]

    if unclosed_count > 0:
        report_lines.append(f"⚠️ 警告：發現 {unclosed_count} 個未正確關閉可能洩漏的 Ports：")
        report_lines.append(", ".join(unclosed_ports) if unclosed_ports else "無")
        report_lines.append("")
        report_lines.append("📋 未釋放 Port 的 Unit ID 統計表:")
        report_lines.append("Port      | Queried Unit IDs")
        report_lines.append("----------------------------")
        for port in unclosed_ports:
            uids = sorted(port_to_uids.get(port, []), key=int)
            uid_str = ", ".join(uids) if uids else "無 / 未找到封包"
            report_lines.append(f" {port.ljust(10)}| {uid_str}")
    else:
        report_lines.append("✅ 恭喜：所有被檢測出的連線埠口皆已被伺服器或客戶端完美釋放！")

    if rst_count > 0:
        report_lines.append("")
        report_lines.append(f"🔍 找到 {rst_count} 筆符合條件的 RST 封包，以下為最近的幾筆摘錄 (完整請參考 _RST_info.txt)：")
        report_lines.append("---------------------------------------------")
        preview = rst_lines[:10]
        report_lines.extend([f"  {line}" for line in preview])

    write_text(report_file, "\n".join(report_lines) + "\n")

    print("--------------------------------=============")
    print("🎉 分析處理完成！")
    print(f"📦 參與查詢的總 Port 數 : {released_count + unclosed_count}")
    print(f"  ✔️ 已正確釋放  (FIN/RST): {released_count}")
    print(f"  ❌ 未釋放 (無交握中斷記錄): {unclosed_count}")
    if unclosed_count > 0:
        print(f"⚠️  未釋放 Ports：{', '.join(unclosed_ports)}")
        print("\n📋 未釋放 Port 的 Unit ID 統計表:")
        print("Port      | Queried Unit IDs")
        print("----------------------------")
        for port in unclosed_ports:
            uids = sorted(port_to_uids.get(port, []), key=int)
            uid_str = ", ".join(uids) if uids else "無 / 未找到封包"
            print(f" {port.ljust(10)}| {uid_str}")
    if rst_count > 0:
        print(f"🔍 找到 {rst_count} 筆符合條件的 RST 封包。")
    print(f"📊 詳細資料 CSV 已匯出至: {output_file}")
    print(f"📝 整體總結報告 已匯出至: {report_file}")
    if rst_count > 0:
        print(f"📑 獨立 RST 資訊 已匯出至: {rst_file}")
    print("=============================================")

    return 0


if __name__ == "__main__":
    sys.exit(main())
