# 🧭 pymap — Network Scanning & Vulnerability Detection Tool

> **pymap**: A simple Python script for educational purposes, designed for network scanning and service-based vulnerability detection.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)  [![Nmap](https://img.shields.io/badge/Nmap-required-orange)](https://nmap.org/)  [![License](https://img.shields.io/badge/License-MIT-green)](./LICENSE)

---

## 📌 Project Overview

This project is a Python script that scans a network environment to detect active devices, open ports, running services, and potential security vulnerabilities. It uses Nmap for network scanning, analyzes service version information, queries the NVD/CVE database for relevant vulnerabilities, and generates a PDF report with the results.

---

## ✨ Key Features

* 🔍 **Network Scanning** — Performs in-depth Nmap scans on specified IP addresses, CIDR blocks, or domains.
* 🧾 **Service & Version Detection** — Collects service and version information for detected services.
* ⚠️ **Vulnerability Detection** — Queries collected service/version data against the NVD/CVE database.
* 📄 **PDF Reporting** — Compiles scan results and detected vulnerabilities into a detailed PDF report.
* 🌐 **Automatic Subnet Detection** — Automatically detects the local subnet if no target is specified and performs the scan.
* ⚡ **Parallel Processing (ThreadPoolExecutor)** — Executes vulnerability scans in parallel for improved performance in large networks.

---

## 🛠️ Technologies & Libraries

* **Python** — Core language.
* **Nmap** — Network scanning.
* **Requests** — Fetching CVE data via HTTP.
* **Netifaces** — Detect local network interfaces and subnet information.
* **ReportLab** — Generating PDF reports.
* **Concurrent.Futures** — Parallel processing.

---

## 🚀 Usage

* Scan a Specific IP Address: `python3 script.py -t 192.168.1.1`
* Scan a Subnet: `python3 script.py -t 192.168.1.0/24`
* Automatic Subnet Detection & Scan: `python3 script.py`

---

**⚠️ Note:** Created for educational purposes. Users are responsible for any illegal use.
