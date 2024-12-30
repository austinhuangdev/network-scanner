#!/usr/bin/env python3
# 檔名：network_scanner_optimized.py
# 功能：掃描指定的 IP 或網段內的活躍機器，取得 MAC 位址、開放的埠，並生成詳細的 CSV、HTML、Log 報告。
# 作者：Austin Huang

import sys
import ipaddress
import subprocess
import socket
import re
import csv
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import logging
from rich import print
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    SpinnerColumn,
)
from rich.box import HEAVY_EDGE
from jinja2 import Environment, FileSystemLoader, select_autoescape
import ssl
import os

console = Console()

REPORTS_DIR = "reports"  # 統一將輸出檔案都放在此資料夾底下

#----------------------------------------------------------------------
#  1. 產生各種輸出檔名與資料夾路徑
#----------------------------------------------------------------------
def generate_paths(target_ip_or_network: str):
    """
    - 依照目標 IP/網段與當前時間生成唯一的子資料夾名稱（內含 CSV、HTML、LOG）。
    - 回傳包含三個檔名 (csv_path, html_path, log_path) 與該子資料夾路徑 folder_path。
    """
    # 1) 準備時間戳記與「去掉 /」的 IP (避免不合法字元)
    sanitized_target = target_ip_or_network.replace('/', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 2) 建立子資料夾，例如 reports/192.168.70.1_24_scan_20241230_104537
    folder_name = f"{sanitized_target}_scan_{timestamp}"
    folder_path = os.path.join(REPORTS_DIR, folder_name)
    os.makedirs(folder_path, exist_ok=True)

    # 3) 產生 CSV、HTML、LOG 完整路徑
    csv_path  = os.path.join(folder_path, f"{sanitized_target}_scan_{timestamp}.csv")
    html_path = os.path.join(folder_path, f"{sanitized_target}_scan_{timestamp}.html")
    log_path  = os.path.join(folder_path, f"{sanitized_target}_scan_{timestamp}.log")

    return csv_path, html_path, log_path, folder_path

#----------------------------------------------------------------------
#  2. LOG 基本設定 (稍後會在 main() 動態指定 filename)
#----------------------------------------------------------------------
logging.basicConfig(
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

#----------------------------------------------------------------------
#  3. 服務偵測器 (Detectors)
#----------------------------------------------------------------------
class ServiceDetector:
    def detect(self, ip, port):
        """偵測指定 IP 和埠的服務，返回服務名稱和版本資訊"""
        return None, None

class HTTPDetector(ServiceDetector):
    def detect(self, ip, port):
        try:
            conn = socket.create_connection((ip, port), timeout=2)
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            conn.send(request.encode())
            response = conn.recv(1024).decode(errors='ignore')
            headers = response.split('\r\n')
            for header in headers:
                if header.lower().startswith('server:'):
                    service = header.split(':', 1)[1].strip()
                    return service, None
            return "HTTP（未知 Web 伺服器）", None
        except Exception as e:
            logging.error(f"HTTP 偵測失敗 {ip}:{port} - {e}")
            return "HTTP", None

class HTTPSDetector(ServiceDetector):
    def detect(self, ip, port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    service = "HTTPS（SSL/TLS）"
                    issuer = cert.get('issuer')
                    if issuer:
                        issuer_str = ", ".join(["=".join(item) for sublist in issuer for item in sublist])
                        version_info = f"證書發行者：{issuer_str}"
                        return service, version_info
                    return service, None
        except Exception as e:
            logging.error(f"HTTPS 偵測失敗 {ip}:{port} - {e}")
            return "HTTPS", None

class SSHDetector(ServiceDetector):
    def detect(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=2) as conn:
                banner = conn.recv(1024).decode(errors='ignore').strip()
                return "SSH", banner
        except Exception as e:
            logging.error(f"SSH 偵測失敗 {ip}:{port} - {e}")
            return "SSH", None

class FTPDetector(ServiceDetector):
    def detect(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=2) as conn:
                banner = conn.recv(1024).decode(errors='ignore').strip()
                return "FTP", banner
        except Exception as e:
            logging.error(f"FTP 偵測失敗 {ip}:{port} - {e}")
            return "FTP", None

class TelnetDetector(ServiceDetector):
    def detect(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=2) as conn:
                banner = conn.recv(1024).decode(errors='ignore').strip()
                return "Telnet", banner
        except Exception as e:
            logging.error(f"Telnet 偵測失敗 {ip}:{port} - {e}")
            return "Telnet", None

class MySQLDetector(ServiceDetector):
    def detect(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=2) as conn:
                banner = conn.recv(1024).decode(errors='ignore').strip()
                return "MySQL 資料庫", banner
        except Exception as e:
            logging.error(f"MySQL 偵測失敗 {ip}:{port} - {e}")
            return "MySQL", None

class GenericTCPDetector(ServiceDetector):
    def detect(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=2) as conn:
                conn.sendall(b'\n')
                banner = conn.recv(1024).decode(errors='ignore').strip()
                if banner:
                    return banner, None
                else:
                    return "未知服務", None
        except Exception as e:
            logging.error(f"通用服務偵測失敗 {ip}:{port} - {e}")
            return "未知服務", None

#----------------------------------------------------------------------
#  4. 服務偵測器對應表 (常見埠)
#----------------------------------------------------------------------
DETECTORS = {
    21: FTPDetector(),
    22: SSHDetector(),
    23: TelnetDetector(),
    80: HTTPDetector(),
    443: HTTPSDetector(),
    3306: MySQLDetector(),
    8080: HTTPDetector(),
    8443: HTTPSDetector(),
    # 可持續擴充...
}

#----------------------------------------------------------------------
#  5. 常見埠與服務對應表（台灣繁體中文）
#----------------------------------------------------------------------
SERVICE_MAP = {
    20: {"service": "FTP 資料傳輸", "protocol": "TCP"},
    21: {"service": "FTP 控制", "protocol": "TCP"},
    22: {"service": "SSH（安全外殼協定）", "protocol": "TCP"},
    23: {"service": "Telnet（遠端登入協定）", "protocol": "TCP"},
    25: {"service": "SMTP（簡單郵件傳輸協定）", "protocol": "TCP"},
    53: {"service": "DNS（域名系統）", "protocol": "TCP/UDP"},
    67: {"service": "DHCP 伺服器（動態主機設定協定）", "protocol": "UDP"},
    68: {"service": "DHCP 客戶端（動態主機設定協定）", "protocol": "UDP"},
    69: {"service": "TFTP（簡單檔案傳輸協定）", "protocol": "UDP"},
    80: {"service": "HTTP（超文本傳輸協定）", "protocol": "TCP"},
    110: {"service": "POP3（郵局協議第3版）", "protocol": "TCP"},
    119: {"service": "NNTP（網路新聞傳輸協定）", "protocol": "TCP"},
    123: {"service": "NTP（網路時間協定）", "protocol": "UDP"},
    135: {"service": "Microsoft RPC（遠端程序呼叫）", "protocol": "TCP"},
    137: {"service": "NetBIOS 名稱服務", "protocol": "UDP"},
    138: {"service": "NetBIOS 數據報服務", "protocol": "UDP"},
    139: {"service": "NetBIOS 會話服務", "protocol": "TCP"},
    143: {"service": "IMAP（網際郵件存取協定）", "protocol": "TCP"},
    161: {"service": "SNMP（簡單網路管理協定）", "protocol": "UDP"},
    162: {"service": "SNMP Trap（簡單網路管理協定陷阱）", "protocol": "UDP"},
    194: {"service": "IRC（網際聊天室協定）", "protocol": "TCP"},
    389: {"service": "LDAP（輕量級目錄存取協定）", "protocol": "TCP/UDP"},
    465: {"service": "SMTPS（安全郵件傳輸協定）", "protocol": "TCP"},
    514: {"service": "Syslog（日誌系統）", "protocol": "UDP"},
    636: {"service": "LDAPS（安全輕量級目錄存取協定）", "protocol": "TCP"},
    6379: {"service": "Redis（遠端字典伺服器）", "protocol": "TCP"},
    1025: {"service": "NFS 或 Microsoft RPC 映射器", "protocol": "TCP"},
    1433: {"service": "SQL Server（資料庫服務）", "protocol": "TCP"},
    1521: {"service": "Oracle（資料庫服務）", "protocol": "TCP"},
    1720: {"service": "PPTP（點對點隧道協定）", "protocol": "TCP"},
    1723: {"service": "PPTP VPN（點對點隧道協定虛擬私人網路）", "protocol": "TCP"},
    2049: {"service": "NFS（網路檔案系統）", "protocol": "TCP"},
    2121: {"service": "FTP 替代服務", "protocol": "TCP"},
    2222: {"service": "SSH 替代服務", "protocol": "TCP"},
    2375: {"service": "Docker 容器服務", "protocol": "TCP"},
    3000: {"service": "開發測試用 HTTP 服務",      "protocol": "TCP"},
    3306: {"service": "MySQL 資料庫服務", "protocol": "TCP"},
    3389: {"service": "RDP（遠端桌面協定）", "protocol": "TCP"},
    5000: {"service": "UPnP（通用即插即用）", "protocol": "UDP/TCP"},
    5001: {"service": "Flask 替代服務", "protocol": "TCP"},
    5002: {"service": "Flask 替代服務", "protocol": "TCP"},
    5003: {"service": "Flask 替代服務", "protocol": "TCP"},
    5060: {"service": "SIP（會話發起協定）", "protocol": "UDP/TCP"},
    5140: {"service": "Syslog 替代服務", "protocol": "UDP"},
    5173: {"service": "Vite 開發伺服器（預設埠）", "protocol": "TCP"},
    5500: {"service": "VNC 替代服務", "protocol": "TCP"},
    5501: {"service": "VNC 替代服務", "protocol": "TCP"},
    5502: {"service": "VNC 替代服務", "protocol": "TCP"},
    5900: {"service": "VNC（虛擬網路運算）", "protocol": "TCP"},
    5901: {"service": "VNC 替代服務", "protocol": "TCP"},
    5902: {"service": "VNC 替代服務", "protocol": "TCP"},
    5903: {"service": "VNC 替代服務", "protocol": "TCP"},
    6000: {"service": "X11（X Window 系統）", "protocol": "TCP"},
    6001: {"service": "X11 替代服務", "protocol": "TCP"},
    6002: {"service": "X11 替代服務", "protocol": "TCP"},
    6003: {"service": "X11 替代服務", "protocol": "TCP"},
    8000: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8001: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8002: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8003: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8004: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8080: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8081: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8082: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8083: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8084: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8085: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8443: {"service": "HTTPS 替代服務", "protocol": "TCP"},
    8880: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8881: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8882: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8883: {"service": "HTTP 替代服務", "protocol": "TCP"},
    8888: {"service": "HTTP 替代服務", "protocol": "TCP"},
    9000: {"service": "SonarQube 或其他應用", "protocol": "TCP"},
    9090: {"service": "HTTP 替代服務", "protocol": "TCP"},
    9091: {"service": "HTTP 替代服務", "protocol": "TCP"},
    9092: {"service": "HTTP 替代服務", "protocol": "TCP"},
    9093: {"service": "HTTP 替代服務", "protocol": "TCP"},
    9094: {"service": "HTTP 替代服務", "protocol": "TCP"},
    10000: {"service": "Webmin（系統管理工具）", "protocol": "TCP"},
    10002: {"service": "Webmin 替代服務", "protocol": "TCP"},
    10003: {"service": "Webmin 替代服務", "protocol": "TCP"},
    10004: {"service": "Webmin 替代服務", "protocol": "TCP"},
    10005: {"service": "Webmin 替代服務", "protocol": "TCP"},
    11211: {"service": "Memcached（記憶體快取系統）", "protocol": "TCP"},
    11212: {"service": "Memcached 替代服務", "protocol": "TCP"},
    11213: {"service": "Memcached 替代服務", "protocol": "TCP"},
    11214: {"service": "Memcached 替代服務", "protocol": "TCP"},
    11215: {"service": "Memcached 替代服務", "protocol": "TCP"},
    27017: {"service": "MongoDB（文件型資料庫）", "protocol": "TCP"},
    27018: {"service": "MongoDB 替代服務", "protocol": "TCP"},
    27019: {"service": "MongoDB 替代服務", "protocol": "TCP"},
    27020: {"service": "MongoDB 替代服務", "protocol": "TCP"},
    27021: {"service": "MongoDB 替代服務", "protocol": "TCP"},
}

#----------------------------------------------------------------------
#  6. 印出程式介紹
#----------------------------------------------------------------------
def print_introduction():
    terminal_width = console.size.width

    # 彩色橫幅
    banner = Panel(
        Align.center(Text("✨ 歡迎使用網路掃描器！✨", style="bold bright_green")),
        style="bright_blue",
        expand=False,
        width=terminal_width
    )
    console.print(banner)

    # 功能特色面板
    features = Panel(
        Text(
            "- 支援掃描單一 IP 或整個網段\n"
            "- 自動偵測開放的埠和服務\n"
            "- 生成 CSV、HTML 和 Log 報告\n"
            "- 清晰美觀的資料呈現，適合商業應用",
            style="bright_white"
        ),
        title="[bold bright_yellow]功能特色：[/bold bright_yellow]",
        border_style="bright_green",
        padding=(1, 2),
        width=terminal_width
    )
    console.print(features)

    # 使用方式面板
    usage = Panel(
        Text(
            "1. 掃描單一 IP：\n"
            "   python3 network_scanner_optimized.py 192.168.70.1\n\n"
            "2. 掃描網段：\n"
            "   python3 network_scanner_optimized.py 192.168.70.1/24\n\n"
            "3. 指定特定埠進行掃描：\n"
            "   python3 network_scanner_optimized.py 192.168.70.1/24 -p 22 80 443\n\n"
            "4. 更改輸出檔案名稱：\n"
            "   python3 network_scanner_optimized.py 192.168.70.1/24 -o result.csv --html report.html",
            style="bright_white"
        ),
        title="[bold bright_yellow]使用方式：[/bold bright_yellow]",
        border_style="bright_magenta",
        padding=(1, 2),
        width=terminal_width
    )
    console.print(usage)

    # 開發者資訊面板
    developer_info = Panel(
        Text(
            "開發者：Austin Huang\n"
            "聯絡方式：austinhuangdev@gmail.com\n"
            "GitHub：https://github.com/austinhuangdev\n",
            style="bright_white"
        ),
        title="[bold bright_yellow]開發者資訊：[/bold bright_yellow]",
        border_style="bright_cyan",
        padding=(1, 2),
        width=terminal_width
    )
    console.print(developer_info)

    # 注意事項面板
    warning = Panel(
        Text("⚠️ 注意：請務必在合法且獲得授權的情況下使用此工具！", justify="center", style="bold bright_red"),
        style="bright_red",
        expand=False,
        width=terminal_width
    )
    console.print(warning)

    # 分隔線
    console.print("-" * terminal_width)

#----------------------------------------------------------------------
#  7. 解析命令列參數
#----------------------------------------------------------------------
def parse_arguments():
    """解析命令列參數"""
    parser = argparse.ArgumentParser(
        description="掃描指定的 IP 或網段，取得 MAC 位址和開放的埠。"
    )
    parser.add_argument(
        "target", 
        help="目標 IP 或網段，例如 192.168.70.1 或 192.168.70.1/24"
    )
    parser.add_argument(
        "-o", "--output", 
        help="輸出 CSV 檔案的名稱（若不指定，將自動生成 IP_日期時間.csv）"
    )
    parser.add_argument(
        "-p",
        "--ports",
        nargs='*',
        type=int,
        default=sorted(SERVICE_MAP.keys()),
        help="指定要掃描的埠，預設為常見埠列表。",
    )
    parser.add_argument(
        "--html",
        help="輸出 HTML 報告的名稱（若不指定，將自動生成 IP_日期時間.html）",
    )
    return parser.parse_args()

#----------------------------------------------------------------------
#  8. Ping 探測 IP
#----------------------------------------------------------------------
def ping_ip(ip):
    """Ping 探測 IP 是否活躍"""
    try:
        param = "-n" if sys.platform.startswith("win") else "-c"
        if sys.platform == "darwin":
            command = ["ping", "-c", "1", "-W", "1000", str(ip)]
        else:
            command = ["ping", param, "1", str(ip)]
        result = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            return str(ip)
    except Exception as e:
        logging.error(f"Ping {ip} 失敗: {e}")
    return None

#----------------------------------------------------------------------
#  9. 取得 MAC 位址
#----------------------------------------------------------------------
def get_mac_address(ip):
    """取得 MAC 位址"""
    try:
        if sys.platform.startswith("win"):
            arp_output = subprocess.check_output(["arp", "-a", ip], universal_newlines=True)
        elif sys.platform == "darwin":
            arp_output = subprocess.check_output(["arp", ip], universal_newlines=True)
        else:
            arp_output = subprocess.check_output(["arp", "-n", ip], universal_newlines=True)

        match = re.search(r"(([0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2})", arp_output)
        if match:
            return match.group(1).lower().replace('-', ':')
    except subprocess.CalledProcessError:
        pass
    except Exception as e:
        logging.error(f"取得 {ip} 的 MAC 位址時出錯: {e}")
    return "未知"

#----------------------------------------------------------------------
#  10. 偵測服務
#----------------------------------------------------------------------
def detect_service(ip, port):
    """根據埠和協定偵測服務"""
    detector = DETECTORS.get(port, GenericTCPDetector())
    service, version_info = detector.detect(ip, port)
    return service, version_info

#----------------------------------------------------------------------
#  11. 掃描指定 IP/Port
#----------------------------------------------------------------------
def scan_port(ip, port):
    """掃描指定 IP 的指定埠是否開放，並偵測服務"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                service, version = detect_service(ip, port)
                return (port, service, version)
    except Exception as e:
        logging.error(f"掃描 {ip}:{port} 時出錯: {e}")
    return None

#----------------------------------------------------------------------
#  12. 匯出 CSV
#----------------------------------------------------------------------
def export_to_csv(host_info, filename="scan_results.csv"):
    """將掃描結果輸出為 CSV 檔案"""
    try:
        with open(filename, mode="w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["IP 位址", "MAC 位址", "開放的埠及服務"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for ip in sorted(host_info.keys(), key=lambda x: socket.inet_aton(x)):
                info = host_info[ip]
                port_service_list = []
                for port, service, version in sorted(info.get("open_ports", []), key=lambda x: x[0]):
                    service_str = f"{port}"
                    if service:
                        service_str += f" ({service})"
                    if version:
                        # 限制版本資訊長度，避免過長影響美觀
                        version = (version[:30] + '...') if len(version) > 30 else version
                        service_str += f" [{version}]"
                    port_service_list.append(service_str)
                open_ports_services = ", ".join(port_service_list) if port_service_list else "無"
                writer.writerow(
                    {
                        "IP 位址": ip,
                        "MAC 位址": info.get("mac_address", "未知"),
                        "開放的埠及服務": open_ports_services,
                    }
                )
        console.print(f"[bold green]成功輸出掃描結果至 [underline]{filename}[/underline][/bold green]")
    except Exception as e:
        logging.error(f"輸出 CSV 失敗：{e}")
        console.print(f"[bold red]輸出 CSV 失敗：{e}[/bold red]")

#----------------------------------------------------------------------
#  13. 產生統計數據
#----------------------------------------------------------------------
def generate_statistics(host_info):
    """生成統計數據"""
    service_counts = {}
    total_open_ports = 0
    for info in host_info.values():
        for port, service, version in info.get('open_ports', []):
            total_open_ports += 1
            service_name = service if service else "未知服務"
            service_counts[service_name] = service_counts.get(service_name, 0) + 1
    return service_counts, total_open_ports

#----------------------------------------------------------------------
#  14. 匯出 HTML 報告
#----------------------------------------------------------------------
def export_to_html(host_info, filename="scan_report.html", target=""):
    """將掃描結果輸出為 HTML 報告"""
    try:
        service_counts, total_open_ports = generate_statistics(host_info)
        total_hosts = len(host_info)
        service_types = len(service_counts)
        most_common_service = max(service_counts, key=service_counts.get) if service_counts else "無"
        chart_labels = list(service_counts.keys())
        chart_data = list(service_counts.values())

        # 定義服務到顏色與圖示的映射
        service_styles = {
            "ssh": {"color": "info", "icon": "bi-terminal"},
            "mysql": {"color": "success", "icon": "bi-database"},
            "ftp": {"color": "warning", "icon": "bi-file-earmark-arrow-up"},
            "apache": {"color": "primary", "icon": "bi-server"},
            "nginx": {"color": "primary", "icon": "bi-server"},
            "rdp": {"color": "danger", "icon": "bi-display"},
            "mssql": {"color": "danger", "icon": "bi-display"},
            "http": {"color": "warning", "icon": "bi-globe"},
            "https": {"color": "warning", "icon": "bi-globe2"},
            "microsoft-iis": {"color": "dark", "icon": "bi-server"},
            "mysql 資料庫": {"color": "success", "icon": "bi-database"},
            "http/1.1 400 bad request": {"color": "danger", "icon": "bi-exclamation-triangle"},
            "rfb 003.008": {"color": "secondary", "icon": "bi-display"},
            "unknown": {"color": "secondary", "icon": "bi-question-circle"},
        }

        env = Environment(
            loader=FileSystemLoader('.'),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.from_string("""
        <!DOCTYPE html>
        <html lang="zh-TW">
        <head>
            <meta charset="UTF-8">
            <title>網路掃描報告</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <!-- Bootstrap CSS -->
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <!-- Simple-DataTables CSS -->
            <link href="https://cdn.jsdelivr.net/npm/simple-datatables@latest/dist/style.css" rel="stylesheet">
            <!-- Bootstrap Icons -->
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                body {
                    padding: 20px;
                    background-color: #f8f9fa;
                }
                h1, h2 {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .card-icon {
                    font-size: 1.5rem;
                    margin-right: 10px;
                }
                .summary-card {
                    display: flex;
                    align-items: center;
                }
                table th {
                    white-space: nowrap;
                    text-align: left;
                    font-size: 1rem;
                }
                table td {
                    vertical-align: top;
                    text-align: left;
                    font-size: 0.95rem;
                    background-color: #e9ecef; /* 淺灰色背景 */
                }
                .table-responsive {
                    overflow-x: auto;
                }
                .card-title {
                    font-size: 1.1rem;
                    font-weight: bold;
                }
                .card-text {
                    font-size: 1rem;
                }
                .badge-service {
                    margin-bottom: 5px;
                    padding: 0.3em 0.5em;
                    font-size: 0.85rem;
                    display: flex;
                    align-items: center;
                    width: fit-content;
                }
                .badge-service i {
                    margin-right: 5px;
                }
                .dataTables_wrapper .dataTables_paginate {
                    margin-top: 15px;
                }
                .dataTables_wrapper .dataTables_filter input {
                    width: 100%;
                    max-width: 300px;
                    margin-left: 0.5em;
                }
                .dataTables_wrapper .dataTables_length select {
                    width: auto;
                    display: inline-block;
                    margin-left: 0.5em;
                }
                .dataTables_wrapper .dataTables_paginate .paginate_button {
                    padding: 0.5em 0.75em;
                    margin-left: 0.25em;
                    border: 1px solid #dee2e6;
                    border-radius: 0.25rem;
                    background-color: #ffffff;
                    color: #0d6efd;
                    cursor: pointer;
                }
                .dataTables_wrapper .dataTables_paginate .paginate_button.current {
                    background-color: #0d6efd;
                    color: #ffffff;
                }
                .dataTables_wrapper .dataTables_paginate .paginate_button:hover {
                    background-color: #e9ecef;
                }
                .badge-container {
                    display: flex;
                    flex-direction: column;
                    align-items: flex-start;
                }
                .badge-service.bg-info {
                    background-color: #17a2b8;
                }
                .badge-service.bg-warning {
                    background-color: #ffc107;
                }
                .badge-service.bg-danger {
                    background-color: #dc3545;
                }
                .badge-service.bg-success {
                    background-color: #198754;
                }
                .badge-service.bg-primary {
                    background-color: #0d6efd;
                }
                .badge-service.bg-secondary {
                    background-color: #6c757d;
                }
            </style>
        </head>
        <body>
            <div class="container my-5">
                <h1 class="mb-4"><i class="bi bi-laptop-fill me-2"></i>網路掃描報告</h1>
                <div class="row mb-5">
            <!-- 生成時間 -->
            <div class="col-12 col-lg-6 col-xxl-4 mb-4">
                <div class="card shadow-sm h-100">
                    <div class="card-body d-flex align-items-center">
                        <i class="bi bi-clock-fill fs-3 text-primary me-3"></i>
                        <div class="d-flex justify-content-between align-items-center flex-grow-1">
                            <h5 class="card-title mb-0">生成時間：</h5>
                            <p class="card-text fs-5 fw-bold mb-0 text-primary">{{ scan_time }}</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 掃描目標 -->
            <div class="col-12 col-lg-6 col-xxl-4 mb-4">
                <div class="card shadow-sm h-100">
                    <div class="card-body d-flex align-items-center">
                        <i class="bi bi-router fs-3 text-success me-3"></i>
                        <div class="d-flex justify-content-between align-items-center flex-grow-1">
                            <h5 class="card-title mb-0">掃描目標：</h5>
                            <p class="card-text fs-5 fw-bold mb-0 text-success">{{ target }}</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 活躍機器數量 -->
            <div class="col-12 col-lg-6 col-xxl-4 mb-4">
                <div class="card shadow-sm h-100">
                    <div class="card-body d-flex align-items-center">
                        <i class="bi bi-robot fs-3 text-secondary me-3"></i>
                        <div class="d-flex justify-content-between align-items-center flex-grow-1">
                            <h5 class="card-title mb-0">活躍機器數量：</h5>
                            <p class="card-text fs-5 fw-bold mb-0 text-secondary">{{ active_hosts_count }}</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 總開放埠數 -->
            <div class="col-12 col-lg-6 col-xxl-4 mb-4">
                <div class="card shadow-sm h-100">
                    <div class="card-body d-flex align-items-center">
                        <i class="bi bi-patch-exclamation-fill fs-3 text-danger me-3"></i>
                        <div class="d-flex justify-content-between align-items-center flex-grow-1">
                            <h5 class="card-title mb-0">總開放埠數：</h5>
                            <p class="card-text fs-5 fw-bold mb-0 text-danger">{{ total_open_ports }}</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 服務類型數量 -->
            <div class="col-12 col-lg-6 col-xxl-4 mb-4">
                <div class="card shadow-sm h-100">
                    <div class="card-body d-flex align-items-center">
                        <i class="bi bi-bar-chart-fill fs-3 text-info me-3"></i>
                        <div class="d-flex justify-content-between align-items-center flex-grow-1">
                            <h5 class="card-title mb-0">服務類型數量：</h5>
                            <p class="card-text fs-5 fw-bold mb-0 text-info">{{ service_types }}</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 最常見的服務 -->
            <div class="col-12 col-lg-6 col-xxl-4 mb-4">
                <div class="card shadow-sm h-100">
                    <div class="card-body d-flex align-items-center">
                        <i class="bi bi-tools fs-3 text-warning me-3"></i>
                        <div class="d-flex justify-content-between align-items-center flex-grow-1">
                            <h5 class="card-title mb-0">最常見的服務：</h5>
                            <p class="card-text fs-5 fw-bold mb-0 text-warning">{{ most_common_service }}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
                
        <div class="row mb-5 justify-content-center">
            <div class="col-12">
                <h2 class="mb-4">
                    <i class="bi bi-pie-chart-fill me-2"></i>服務分佈圖
                </h2>
            </div>
            <div class="col-12 col-md-8 col-lg-6">
                <canvas id="servicePieChart"></canvas>
            </div>
        </div>

        <h2 class="mb-4"><i class="bi bi-info-circle-fill me-2"></i>主機詳細資訊</h2>
        <div class="table-responsive mb-5">
            <table id="hostTable" class="table table-striped table-bordered table-hover">
                <thead>
                    <tr>
                        <th><i class="bi bi-wifi card-icon"></i>IP 位址</th>
                        <th><i class="bi bi-hdd-network card-icon"></i>MAC 位址</th>
                        <th><i class="bi bi-cloud card-icon"></i>開放的埠及服務</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ip, info in sorted_host_info %}
                    <tr>
                        <td>{{ ip }}</td>
                        <td>{{ info.mac_address }}</td>
                        <td>
                            {% if info.open_ports %}
                                <div class="badge-container">
                                    {% for port, service, version in info.open_ports %}
                                        {% set service_key = service.lower() if service else "unknown" %}
                                        {% set style = service_styles.get(service_key, service_styles['unknown']) %}
                                        <span class="badge bg-{{ style.color }} badge-service" 
                                              data-bs-toggle="tooltip" 
                                              data-bs-placement="top" 
                                              title="{{ service }}{% if version %} [{{ version }}]{% endif %}">
                                            <i class="{{ style.icon }}"></i> {{ port }} 
                                            {% if service %}
                                                ({{ service }})
                                            {% endif %}
                                            {% if version %}
                                                [{{ version }}]
                                            {% endif %}
                                        </span>
                                    {% endfor %}
                                </div>
                            {% else %}
                                <span class="badge bg-secondary">無</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
                
        <h2 class="mb-4"><i class="bi bi-bar-chart-fill me-2"></i>服務統計</h2>
        <div class="table-responsive mb-5">
            <table id="serviceTable" class="table table-striped table-bordered table-hover">
                <thead>
                    <tr>
                        <th><i class="bi bi-tools card-icon"></i>服務名稱</th>
                        <th><i class="bi bi-graph-up card-icon"></i>開放次數</th>
                    </tr>
                </thead>
                <tbody>
                    {% for service, count in service_counts.items() %}
                    <tr>
                        <td>{{ service }}</td>
                        <td>{{ count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <!-- 在這裡插入 footer，以便在主要內容之後顯示開發者資訊 -->
<footer class="bg-dark text-white py-4">
    <div class="container">
        <div class="d-flex flex-column flex-md-row justify-content-center align-items-center">
            <div class="d-flex align-items-center mb-3 mb-md-0 me-md-4">
                <i class="bi bi-person-fill me-2"></i>
                <span>Developer：Austin Huang</span>
            </div>
            <div class="d-flex align-items-center mb-3 mb-md-0 me-md-4">
                <a href="https://github.com/austinhuangdev" target="_blank" rel="noopener noreferrer" class="text-white text-decoration-none d-flex align-items-center">
                    <i class="bi bi-github me-2"></i>
                    <span>GitHub</span>
                </a>
            </div>
            <div class="d-flex align-items-center">
                <a href="mailto:austinhuangdev@gmail.com" class="text-white text-decoration-none d-flex align-items-center">
                    <i class="bi bi-envelope-fill me-2"></i>
                    <span>austinhuangdev@gmail.com</span>
                </a>
            </div>
        </div>
        <div class="text-center mt-3">
            <small>&copy; 2024 Austin Huang. All rights reserved.</small>
        </div>
    </div>
</footer>


    
    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <!-- Simple-DataTables JS -->
    <script src="https://cdn.jsdelivr.net/npm/simple-datatables@latest"></script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            // 初始化 Simple-DataTables
            const hostTable = document.querySelector('#hostTable');
            if (hostTable) {
                new simpleDatatables.DataTable(hostTable, {
                    searchable: true,
                    fixedHeight: false,
                    perPage: 10,
                    perPageSelect: [10, 25, 50, '全部'],
                    labels: {
                        placeholder: "搜尋...",
                        perPage: "每頁顯示",
                        noRows: "無資料",
                        info: "顯示 {start} 至 {end} 筆，共 {rows} 筆",
                        all: "全部"
                    }
                });
            }
            
            const serviceTable = document.querySelector('#serviceTable');
            if (serviceTable) {
                new simpleDatatables.DataTable(serviceTable, {
                    searchable: true,
                    fixedHeight: false,
                    perPage: 10,
                    perPageSelect: [10, 25, 50, '全部'],
                    labels: {
                        placeholder: "搜尋...",
                        perPage: "每頁顯示",
                        noRows: "無資料",
                        info: "顯示 {start} 至 {end} 筆，共 {rows} 筆",
                        all: "全部"
                    }
                });
            }

            // 初始化 Chart.js (圓餅圖)
            const ctx = document.getElementById('servicePieChart').getContext('2d');
            const servicePieChart = new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: {{ json_chart_labels|tojson }},
                    datasets: [{
                        label: '服務分佈',
                        data: {{ json_chart_data|tojson }},
                        backgroundColor: [
                            'rgba(54, 162, 235, 0.7)',
                            'rgba(255, 99, 132, 0.7)',
                            'rgba(255, 206, 86, 0.7)',
                            'rgba(75, 192, 192, 0.7)',
                            'rgba(153, 102, 255, 0.7)',
                            'rgba(255, 159, 64, 0.7)',
                            'rgba(199, 199, 199, 0.7)',
                            'rgba(83, 102, 255, 0.7)',
                            'rgba(255, 99, 132, 0.7)',
                            'rgba(54, 162, 235, 0.7)',
                            'rgba(255, 206, 86, 0.7)',
                            'rgba(75, 192, 192, 0.7)'
                        ],
                        borderColor: [
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 99, 132, 1)',
                            'rgba(255, 206, 86, 1)',
                            'rgba(75, 192, 192, 1)',
                            'rgba(153, 102, 255, 1)',
                            'rgba(255, 159, 64, 1)',
                            'rgba(199, 199, 199, 1)',
                            'rgba(83, 102, 255, 1)',
                            'rgba(255, 99, 132, 1)',
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 206, 86, 1)',
                            'rgba(75, 192, 192, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = context.chart._metasets[context.datasetIndex].total;
                                    const percentage = ((value / total) * 100).toFixed(2) + '%';
                                    return label + ': ' + value + ' (' + percentage + ')';
                                }
                            }
                        }
                    }
                },
            });

            // 初始化 Bootstrap Tooltips
            const tooltipTriggerList = Array.from(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            const tooltipList = tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
        });
    </script>
</body>
</html>
        """)

        # 序列化資料為 JSON
        json_chart_labels = chart_labels
        json_chart_data = chart_data

        # 排序後再轉成列表
        sorted_host_info = sorted(host_info.items(), key=lambda x: socket.inet_aton(x[0]))

        html_content = template.render(
            scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            target=target,
            active_hosts_count=len(host_info),
            total_open_ports=total_open_ports,
            service_types=service_types,
            most_common_service=most_common_service,
            sorted_host_info=sorted_host_info,
            service_counts=service_counts,
            json_chart_labels=json_chart_labels,
            json_chart_data=json_chart_data,
            service_styles=service_styles
        )

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        console.print(f"[bold green]成功輸出掃描報告至 [underline]{filename}[/underline][/bold green]")
    except Exception as e:
        logging.error(f"輸出 HTML 報告失敗：{e}")
        console.print(f"[bold red]輸出 HTML 報告失敗：{e}[/bold red]")

#----------------------------------------------------------------------
#  15. Ping 掃描 (第一階段)
#----------------------------------------------------------------------
def ping_scan(hosts):
    """Ping 探測活躍機器"""
    active_hosts = []
    console.print("[bold blue]🔍 第一階段：Ping 探測活躍機器[/bold blue]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[{task.completed}/{task.total}]"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]正在 Ping 探測...", total=len(hosts))
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(ping_ip, str(ip)): ip for ip in hosts}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    if result:
                        active_hosts.append(str(ip))
                except Exception as e:
                    logging.error(f"Ping {ip} 時出錯: {e}")
                progress.update(task, advance=1, description=f"[cyan]正在 Ping 探測 IP：{ip}[/cyan]")
    return sorted(active_hosts, key=lambda x: socket.inet_aton(x))

#----------------------------------------------------------------------
#  16. 取得 MAC
#----------------------------------------------------------------------
def retrieve_host_info(active_hosts):
    """取得 MAC 位址"""
    console.print("[bold blue]🔍 第二階段：取得 MAC 位址[/bold blue]")
    host_info = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[{task.completed}/{task.total}]"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]正在取得 MAC 位址...", total=len(active_hosts))
        with ThreadPoolExecutor(max_workers=50) as executor:
            mac_futures = {executor.submit(get_mac_address, ip): ip for ip in active_hosts}

            for future in as_completed(mac_futures):
                ip = mac_futures[future]
                try:
                    mac = future.result()
                except Exception as e:
                    logging.error(f"取得 {ip} 的 MAC 位址時出錯: {e}")
                    mac = "錯誤"
                host_info[ip] = {"mac_address": mac}
                progress.update(task, advance=1, description=f"[cyan]正在取得 MAC 位址：{ip}[/cyan]")
    return host_info

#----------------------------------------------------------------------
#  17. 埠掃描 (第三階段)
#----------------------------------------------------------------------
def port_scan(active_hosts, port_list):
    """掃描開放埠並偵測服務"""
    console.print("\n[bold blue]🔍 第三階段：掃描開放的埠並偵測服務[/bold blue]")
    host_ports = {ip: {"open_ports": []} for ip in active_hosts}
    total_tasks = len(active_hosts) * len(port_list)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[{task.completed}/{task.total}]"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]正在掃描埠...", total=total_tasks)
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {}
            for ip in active_hosts:
                for port in sorted(port_list):
                    futures[executor.submit(scan_port, ip, port)] = (ip, port)
            for future in as_completed(futures):
                ip, port = futures[future]
                try:
                    result = future.result()
                    if result:
                        port_num, service, version = result
                        host_ports[ip]["open_ports"].append((port_num, service, version))
                except Exception as e:
                    logging.error(f"掃描 {ip}:{port} 時出錯: {e}")
                progress.update(task, advance=1, description=f"[cyan]正在掃描 IP：{ip} 埠：{port}[/cyan]")
    return host_ports

#----------------------------------------------------------------------
#  18. 終端輸出報告 (Rich)
#----------------------------------------------------------------------
def generate_report(host_info):
    """生成並顯示最終報告"""
    console.print("\n[bold green]✨ 掃描完成！生成最終報告：[/bold green]\n")
    try:
        result_table = Table(title="網路掃描報告", show_lines=True, box=HEAVY_EDGE)
        result_table.add_column("IP 位址", style="cyan", no_wrap=True)
        result_table.add_column("MAC 位址", style="yellow")
        result_table.add_column("開放的埠及服務", style="green")

        for ip in sorted(host_info.keys(), key=lambda x: socket.inet_aton(x)):
            info = host_info[ip]
            port_service_list = []
            for port, service, version in sorted(info.get("open_ports", []), key=lambda x: x[0]):
                service_str = f"{port}"
                if service:
                    service_str += f" ({service})"
                if version:
                    # 限制版本資訊的長度
                    version = (version[:30] + '...') if len(version) > 30 else version
                    service_str += f" [{version}]"
                port_service_list.append(service_str)
            open_ports_services = ", ".join(port_service_list) if port_service_list else "無"
            mac_address = info.get("mac_address", "未知")
            result_table.add_row(ip, mac_address, open_ports_services)

        console.print(result_table)
    except Exception as e:
        logging.error(f"生成報告時出錯：{e}")
        console.print(f"[bold red]生成報告時出錯：{e}[/bold red]")

#----------------------------------------------------------------------
#  19. 顯示啟動資訊
#----------------------------------------------------------------------
def print_startup_info(target):
    terminal_width = console.size.width

    # 裝飾性橫幅
    banner_text = Text("✨ 網路掃描器啟動！✨", style="bold bright_green")
    banner = Panel(
        Align.center(banner_text),
        style="bright_blue",
        expand=False,
        width=terminal_width
    )
    console.print(banner)

    # 掃描目標與開始時間
    scan_info = Text()
    scan_info.append("掃描目標：", style="bold bright_yellow")
    scan_info.append(f"{target}\n", style="bright_white")
    scan_info.append("開始時間：", style="bold bright_yellow")
    scan_info.append(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}", style="bright_white")

    info_panel = Panel(
        scan_info,
        style="bright_magenta",
        border_style="bright_magenta",
        padding=(1, 2),
        width=terminal_width
    )
    console.print(info_panel)

    # 分隔線
    console.print("-" * terminal_width)

#----------------------------------------------------------------------
#  20. 主程式入口
#----------------------------------------------------------------------
def main():
    # 先印出程式介紹
    print_introduction()
    
    start_time = time.time()
    args = parse_arguments()
    target = args.target
    port_list = args.ports

    # 產生三種檔名及其所在的資料夾路徑
    csv_path, html_path, log_path, folder_path = generate_paths(target)

    # 如果使用者有指定 CSV 或 HTML 檔名，則覆蓋自動命名（但路徑仍在同一子資料夾中）
    if args.output:
        csv_path = os.path.join(folder_path, args.output)
    if args.html:
        html_path = os.path.join(folder_path, args.html)

    # 動態設定 LOG 檔名
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    logging.basicConfig(
        filename=log_path,
        filemode="w",
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    logging.info("程式啟動，開始掃描。")

    # 驗證輸入的目標是否為有效的 IP 或網段
    try:
        try:
            ip_net = ipaddress.ip_network(target, strict=False)
            is_single_ip = ip_net.num_addresses == 1
        except ValueError:
            ipaddress.ip_address(target)
            is_single_ip = True
            ip_net = ipaddress.ip_network(f"{target}/32")
    except ValueError:
        console.print("[red]請輸入有效的 IP 位址或網段，如 192.168.70.1 或 192.168.70.1/24[/red]")
        sys.exit(1)

    print_startup_info(target)
    
    # 取得所有主機清單 (若是單一 IP，就只有一個)
    all_hosts = list(ip_net.hosts())
    
    # 第一階段：Ping 探測
    active_hosts = ping_scan(all_hosts)

    if not active_hosts:
        console.print("[yellow]未發現任何活躍的機器。[/yellow]")
        logging.info("未發現任何活躍機器，程式結束。")
        sys.exit(0)

    console.print(f"[bold green]✅ 發現 {len(active_hosts)} 台活躍的機器。[/bold green]\n")

    # 第二階段：取得 MAC 位址
    host_info = retrieve_host_info(active_hosts)

    # 第三階段：埠掃描 + 服務偵測
    host_ports = port_scan(active_hosts, port_list)

    # 整合 host_info 與 host_ports
    for ip in host_ports:
        if ip in host_info:
            host_info[ip]["open_ports"] = host_ports[ip]["open_ports"]
        else:
            host_info[ip] = {"mac_address": "未知", "open_ports": host_ports[ip]["open_ports"]}

    # 終端輸出最終報告
    generate_report(host_info)

    # 匯出 CSV
    export_to_csv(host_info, filename=csv_path)
    # 匯出 HTML
    export_to_html(host_info, filename=html_path, target=target)

    # 輸出成功訊息（包含 LOG 檔）
    console.print(f"[bold green]成功輸出 Log 檔案至 [underline]{log_path}[/underline][/bold green]")

    end_time = time.time()
    elapsed_time = end_time - start_time
    minutes, seconds = divmod(elapsed_time, 60)
    hours, minutes = divmod(minutes, 60)
    time_str = ""
    if hours > 0:
        time_str += f"{int(hours)} 小時 "
    if minutes > 0:
        time_str += f"{int(minutes)} 分 "
    time_str += f"{seconds:.2f} 秒"

    console.print(f"\n[bold yellow]總共花費時間：[/bold yellow]{time_str}")
    console.print("[bold cyan]======================================[/bold cyan]")
    console.print("[bold green]✨ 網路掃描器結束！✨[/bold green]")
    console.print("[bold cyan]======================================[/bold cyan]")
    logging.info("程式結束。")

if __name__ == "__main__":
    main()
