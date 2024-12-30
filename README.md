# Network Scanner

A powerful and flexible network scanner tool designed to identify active devices, open ports, MAC addresses, and running services on a given IP or subnet. It generates comprehensive reports in CSV and HTML formats with an easy-to-read layout.

## Features

- **Active device discovery**：Quickly detects live hosts in a subnet or specific IP.
- **Port scanning**: Identifies open ports and their associated services.
- **Service detection**：Supports detection for common services such as HTTP, HTTPS, FTP, SSH, and more.
- **MAC address retrieval**：Fetches the MAC address of detected devices.
- **Detailed reporting**：Generates detailed reports in CSV and HTML formats.
- **Customizable port list**：Specify custom ports to scan or use predefined common ports.
- **Cross-platform**：Supports Windows, macOS, and Linux systems.
- **User-friendly interface**：Provides clear, organized, and visually appealing output using `rich`.

## Requirements

- **Python 3.6+**：Ensure Python is installed on your system.
- **Dependencies**：
  - `rich`: For enhanced terminal output.
  - `jinja2`: For generating HTML reports.

  Install dependencies with：
  ```bash
  pip install -r requirements.txt
  ```

## Installation

1. Clone the repository：
   ```bash
   git clone https://github.com/austinhuangdev/network-scanner.git
   cd network-scanner
   ```

2. Install required Python dependencies：
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) Set up a virtual environment：
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

## Usage

Run the script with the following command：

```bash
python3 network_scanner.py [target]
```

### Examples

1. **Scan a single IP**：
   ```bash
   python3 network_scanner.py 192.168.1.100
   ```

2. **Scan a subnet**：
   ```bash
   python3 network_scanner.py 192.168.1.0/24
   ```

3. **Specify ports to scan**：
   ```bash
   python3 network_scanner.py 192.168.1.0/24 -p 22 80 443
   ```

4. **Customize output files**：
   ```bash
   python3 network_scanner.py 192.168.1.0/24 -o results.csv --html report.html
   ```

## Configuration

You can customize the script's behavior by modifying these variables in the script：

- `SERVICE_MAP`：Add or modify service mappings for port detection.
- `DETECTORS`：Extend or customize service detection logic.

### HTML Report
The generated HTML report includes:
- Active devices with MAC addresses and open ports.
- Service statistics with a pie chart for better visualization.
- Fully interactive tables with sorting and searching capabilities.

## Developer Information

- **Developer**：Austin Huang
- **Contact**：[austinhuangdev@gmail.com](mailto:austinhuangdev@gmail.com)
- **GitHub**：[https://github.com/austinhuangdev](https://github.com/austinhuangdev)

## License

This project is licensed under the [MIT License](LICENSE).

---

## Areas for Improvement

### 1. Cross-Platform Compatibility
- Replace system commands with Python-native libraries:
  - Use `ping3` or `scapy` for ping instead of `subprocess`.
  - Use `scapy` for retrieving MAC addresses, avoiding reliance on `arp`.
- Ensure compatibility in containerized environments.

### 2. Service Detection Expansion
- Expand detection to include more detailed service information.
- Focus on supporting additional common protocols and services before considering broader port scanning.
- Plan for full port range scanning but optimize for speed and efficiency.

### 3. Framework Enhancement
- Modularize the codebase for easier extensibility.
- Use asynchronous I/O for better performance during scanning.
- Implement logging and error handling improvements for robust execution.

---

⚠️ **Note**: Please ensure you have proper authorization before scanning any network or device. Unauthorized scanning is illegal and unethical.

