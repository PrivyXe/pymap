<div align="center">

```
██████╗ ██╗   ██╗███╗   ███╗ █████╗ ██████╗ 
██╔══██╗╚██╗ ██╔╝████╗ ████║██╔══██╗██╔══██╗
██████╔╝ ╚████╔╝ ██╔████╔██║███████║██████╔╝
██╔═══╝   ╚██╔╝  ██║╚██╔╝██║██╔══██║██╔═══╝ 
██║        ██║   ██║ ╚═╝ ██║██║  ██║██║     
╚═╝        ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
```

# 🧭 pymap — Advanced Network Scanner & Vulnerability Assessment Tool

An enterprise-grade, automated network reconnaissance and vulnerability assessment engine powered by Python, Nmap, and NIST NVD CVE v2.0 API.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Nmap](https://img.shields.io/badge/Nmap-Engine-orange.svg?style=for-the-badge&logo=nmap&logoColor=white)](https://nmap.org/)
[![NVD API](https://img.shields.io/badge/NIST_NVD-API_v2.0-red.svg?style=for-the-badge)](https://nvd.nist.gov/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/PrivyXe/pymap?style=for-the-badge)](https://github.com/PrivyXe/pymap/stargazers)

[Features](#-key-features) • [Installation](#-installation) • [Usage](#-usage--examples) • [CLI Options](#-command-line-options) • [Architecture](#-architecture) • [Disclaimer](#-disclaimer)

</div>

---

## 📌 Overview

**pymap** bridges the gap between raw port scanning and actionable security auditing. It automatically inspects active hosts, fingerprints running services and daemon versions, queries the **NIST National Vulnerability Database (NVD v2.0 REST API)** in real-time with multi-threaded workers, and compiles executive-level PDF audit reports with CVSS score metrics and color-coded risk classifications.

---

## ✨ Key Features

* 🌐 **Smart Subnet Discovery:** Automatically detects the active local network subnet (`/24`, `/16`, etc.) without manual input using dynamic socket & CIDR calculations.
* 🔍 **Deep Service Fingerprinting:** Integrates with Nmap for high-accuracy service, version, and OS detection.
* 🛡️ **NVD REST API v2.0 Engine:** Queries live CVE records, CVSS v3.1/v3.0 metrics, and vulnerability severity ratings (Critical, High, Medium, Low).
* ⚡ **High-Performance Multi-Threading:** Employs `concurrent.futures.ThreadPoolExecutor` for parallel vulnerability audits and rate-limit backoff.
* 📄 **Executive PDF Reporting:** Generates corporate-grade penetration testing reports using ReportLab Platypus with auto-wrapping tables, summary metrics, and headers/footers.
* 🎨 **Rich Terminal Interface:** High-impact CLI visualizer with ASCII banners, live progress bars, and formatted data tables.

---

## 🛠️ Prerequisites

Before running `pymap`, ensure that **Nmap** is installed on your system and accessible via your PATH.

* **Linux (Debian/Ubuntu):**
  ```bash
  sudo apt update && sudo apt install nmap -y
  ```
* **macOS (Homebrew):**
  ```bash
  brew install nmap
  ```
* **Windows:**
  Download and install from the official [Nmap Windows Installer](https://nmap.org/download.html).

---

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/PrivyXe/pymap.git
   cd pymap
   ```

2. **Create a virtual environment (Recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage & Examples

### 1. Automatic Local Subnet Scan
Scans your current local subnet automatically and creates `pymap_report.pdf`:
```bash
python3 script.py
```

### 2. Scan a Specific Target or CIDR Block
```bash
# Scan a single host
python3 script.py -t 192.168.1.50

# Scan an entire subnet
python3 script.py -t 192.168.1.0/24

# Scan a domain name
python3 script.py -t scanme.nmap.org
```

### 3. Fast Scan (Top 100 Common Ports)
```bash
python3 script.py -t 192.168.1.1 -F
```

### 4. Custom Port Range
```bash
python3 script.py -t 10.0.0.1 -p 22,80,443,8080,3306
```

### 5. High-Speed Scan with NVD API Key
Using an official NIST NVD API key grants 50 requests / 30 seconds (compared to 5 requests without key):
```bash
python3 script.py -t 192.168.1.0/24 --api-key "YOUR_NVD_API_KEY" --threads 10 -o corporate_audit.pdf
```

---

## ⚙️ Command-Line Options

| Option | Short | Description | Default |
| :--- | :---: | :--- | :---: |
| `--target` | `-t` | Target IP address, CIDR subnet, or hostname | *Auto-detected subnet* |
| `--ports` | `-p` | Specific ports (e.g. `80,443`, `1-1000`, `all`) | `--top-ports 1000` |
| `--fast` | `-F` | Fast scan mode (top 100 ports) | `False` |
| `--output` | `-o` | Output filename for the generated PDF report | `pymap_report.pdf` |
| `--api-key` | - | NIST NVD API Key for higher rate limits | `None` |
| `--threads` | - | Number of concurrent threads for CVE lookups | `5` |
| `--no-pdf` | - | Disable PDF generation (CLI table output only) | `False` |
| `--verbose` | `-v` | Enable detailed debug output | `False` |
| `--help` | `-h` | Display help message and exit | - |

---

## 🏗️ Architecture

```
                               ┌───────────────────────────┐
                               │   User Input / Auto-CIDR  │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │     Nmap Port Scanner     │
                               │ (-sV Service Detection)   │
                               └─────────────┬─────────────┘
                                             │ (Active Services & Versions)
                                             ▼
                       ┌───────────────────────────────────────────┐
                       │  ThreadPoolExecutor (Parallel Workers)    │
                       └─────────────┬───────────────┬─────────────┘
                                     │               │
                                     ▼               ▼
                       ┌───────────────────┐   ┌───────────────────┐
                       │ NIST NVD API v2.0 │   │ In-Memory Cache   │
                       │ (CVSS Scores/CVE) │   │ (Fast dedupe)     │
                       └─────────────┬─────┘   └─────────────┬─────┘
                                     └───────────────┬───────┘
                                                     │
                                                     ▼
                                       ┌───────────────────────────┐
                                       │   ReportLab Platypus Engine│
                                       │  (Executive PDF Generator)│
                                       └───────────────────────────┘
```

---

## 📄 Sample Report Features

* 📊 **Risk Summary Matrix:** Metrics on total hosts, active services, and severity breakdown (Critical, High, Medium, Low).
* 📋 **Service Inventory Table:** Full asset inventory including IP, hostname, OS match, port, service name, and product version.
* ⚠️ **Vulnerability Cards:** Detailed findings showing CVE ID, CVSS score badge, affected endpoint, and formatted description.
* 📑 **Standardized Pagination:** Clean "Page X of Y" footers and confidential watermarks.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!
Feel free to check the [issues page](https://github.com/PrivyXe/pymap/issues).

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## ⚖️ Disclaimer

> [!WARNING]
> **pymap** is developed exclusively for authorized security audits, educational purposes, and defensive network administration. Scanning networks without prior explicit authorization from the network owner is illegal in many jurisdictions. The author assumes no liability for any misuse or damage caused by this program.

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

<div align="center">
  <sub>Developed with ❤️ by <a href="https://github.com/PrivyXe">Muhammet</a></sub>
</div>
