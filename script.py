#!/usr/bin/env python3
"""
🧭 pymap — Advanced Network Scanner & Vulnerability Assessment Tool
Author: Muhammet (https://github.com/PrivyXe)
Repository: https://github.com/PrivyXe/pymap
License: MIT
"""

import os
import sys
import time
import socket
import logging
import argparse
import ipaddress
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple

import requests
import nmap

# Rich terminal styling (graceful fallback if not available)
try:
    from rich.console import Console
    from rich.table import Table as RichTable
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich import box
    from rich.text import Text
    console = Console()
    HAS_RICH = True
except ImportError:
    console = None
    HAS_RICH = False

# ReportLab for Enterprise-grade PDF Generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

# Optional psutil for robust subnet detection
try:
    import psutil
except ImportError:
    psutil = None


# ==========================================
# 🎨 CLI & Logging Utilities
# ==========================================

BANNER = r"""
 [bold cyan]██████╗ ██╗   ██╗███╗   ███╗ █████╗ ██████╗ [/bold cyan]
 [bold cyan]██╔══██╗╚██╗ ██╔╝████╗ ████║██╔══██╗██╔══██╗[/bold cyan]
 [bold cyan]██████╔╝ ╚████╔╝ ██╔████╔██║███████║██████╔╝[/bold cyan]
 [bold cyan]██╔═══╝   ╚██╔╝  ██║╚██╔╝██║██╔══██║██╔═══╝ [/bold cyan]
 [bold cyan]██║        ██║   ██║ ╚═╝ ██║██║  ██║██║     [/bold cyan]
 [bold cyan]╚═╝        ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     [/bold cyan]
 [dim]Advanced Network Scanner & Vulnerability Assessment Tool[/dim]
 [dim blue]https://github.com/PrivyXe/pymap[/dim blue]
"""

def print_banner():
    if HAS_RICH:
        console.print(BANNER)
    else:
        print("\n=== pymap — Network Scanner & Vulnerability Assessment Tool ===")
        print("https://github.com/PrivyXe/pymap\n")

def log_info(msg: str):
    if HAS_RICH:
        console.print(f"[bold blue][*][/bold blue] {msg}")
    else:
        logging.info(msg)

def log_success(msg: str):
    if HAS_RICH:
        console.print(f"[bold green][+][/bold green] {msg}")
    else:
        logging.info(f"[SUCCESS] {msg}")

def log_warning(msg: str):
    if HAS_RICH:
        console.print(f"[bold yellow][!][/bold yellow] {msg}")
    else:
        logging.warning(msg)

def log_error(msg: str):
    if HAS_RICH:
        console.print(f"[bold red][-][/bold red] {msg}")
    else:
        logging.error(msg)


# ==========================================
# 🌐 Network & Subnet Detection
# ==========================================

class NetworkManager:
    """Manages subnet discovery and target parsing."""

    @staticmethod
    def detect_local_subnet() -> Optional[str]:
        """Automatically detects active local IPv4 subnet with correct CIDR."""
        # Method 1: psutil network interfaces
        if psutil:
            try:
                for iface, addrs in psutil.net_if_addrs().items():
                    # Check if interface is up
                    stats = psutil.net_if_stats().get(iface)
                    if stats and not stats.isup:
                        continue
                    for addr in addrs:
                        if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                            if addr.netmask:
                                network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                                if not network.is_loopback and not network.is_link_local:
                                    return str(network)
            except Exception as e:
                logging.debug(f"psutil subnet detection failed: {e}")

        # Method 2: Connect socket trick to identify default gateway adapter IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            if local_ip and not local_ip.startswith("127."):
                network = ipaddress.IPv4Network(f"{local_ip}/255.255.255.0", strict=False)
                return str(network)
        except Exception as e:
            logging.debug(f"Socket routing detection failed: {e}")

        # Method 3: Platform specific fallback (ipconfig / ip route)
        try:
            if os.name == "nt":
                output = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
                for line in output.splitlines():
                    if "IPv4" in line and ":" in line:
                        ip = line.split(":")[-1].strip()
                        if ip and not ip.startswith("127."):
                            return f".".join(ip.split(".")[:3]) + ".0/24"
            else:
                output = subprocess.check_output("ip route", shell=True, text=True, errors="ignore")
                for line in output.splitlines():
                    if "proto kernel" in line or "scope link" in line:
                        parts = line.split()
                        if len(parts) > 0 and "/" in parts[0]:
                            return parts[0]
        except Exception as e:
            logging.debug(f"System command detection failed: {e}")

        return None


# ==========================================
# 🔍 Nmap Network Scanner Engine
# ==========================================

class NmapScanner:
    """Executes network scans and formats active services."""

    def __init__(self, target: str, port_spec: Optional[str] = None, fast_mode: bool = False, verbose: bool = False):
        self.target = target
        self.port_spec = port_spec
        self.fast_mode = fast_mode
        self.verbose = verbose

    def scan(self) -> List[Dict[str, Any]]:
        nm = nmap.PortScanner()

        args_list = ["-T4", "-sV", "--version-intensity", "5"]
        if self.fast_mode:
            args_list.append("-F")
        elif self.port_spec:
            if self.port_spec.lower() == "all":
                args_list.extend(["-p-", "--min-rate", "1000"])
            else:
                args_list.append(f"-p {self.port_spec}")
        else:
            args_list.append("--top-ports 1000")

        # Try adding OS detection if root/admin
        is_admin = False
        try:
            is_admin = (os.getuid() == 0) if hasattr(os, "getuid") else True
        except AttributeError:
            is_admin = True
        if is_admin:
            args_list.append("-O")

        nmap_args = " ".join(args_list)
        log_info(f"Initiating Nmap scan against [bold]{self.target}[/bold]...")
        log_info(f"Scan Parameters: [cyan]{nmap_args}[/cyan]")

        try:
            nm.scan(hosts=self.target, arguments=nmap_args)
        except nmap.PortScannerError as e:
            log_error(f"Nmap execution error: {e}")
            log_error("Please make sure Nmap is installed on your system and accessible via PATH.")
            return []
        except Exception as e:
            log_error(f"Unexpected scan error: {e}")
            return []

        hosts_info = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                os_matches = nm[host].get("osmatch", [])
                os_info = os_matches[0].get("name", "Unknown") if os_matches else "Unknown"
                hostname = nm[host].hostname() or "N/A"

                info = {
                    "ip": host,
                    "hostname": hostname,
                    "os": os_info,
                    "status": nm[host].state(),
                    "ports": []
                }

                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        port_data = nm[host][proto][port]
                        state = port_data.get("state", "")
                        if state == "open":
                            info["ports"].append({
                                "port": port,
                                "protocol": proto.upper(),
                                "state": state,
                                "service": port_data.get("name", "unknown"),
                                "product": port_data.get("product", ""),
                                "version": port_data.get("version", ""),
                                "extra_info": port_data.get("extrainfo", "")
                            })
                hosts_info.append(info)

        return hosts_info


# ==========================================
# 🛡️ NVD CVE v2.0 Vulnerability Engine
# ==========================================

class NVDClient:
    """Queries NIST National Vulnerability Database (NVD) REST API v2.0."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache: Dict[str, List[Dict[str, Any]]] = {}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "pymap-Vulnerability-Auditor/2.0 (https://github.com/PrivyXe/pymap)"
        })
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})

    def fetch_cves(self, product: str, version: str) -> List[Dict[str, Any]]:
        """Queries NVD API v2.0 for a given product and version."""
        if not product or product.lower() in ("unknown", "n/a", ""):
            return []

        cache_key = f"{product.strip().lower()} {version.strip().lower()}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        query = f"{product} {version}".strip() if version and version.lower() not in ("unknown", "") else product.strip()
        params = {
            "keywordSearch": query,
            "resultsPerPage": 5
        }

        cves = []
        try:
            # Respect NVD Rate limits (sleep briefly if no API key)
            if not self.api_key:
                time.sleep(0.6)

            response = self.session.get(self.BASE_URL, params=params, timeout=12)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("vulnerabilities", []):
                    cve_obj = item.get("cve", {})
                    cve_id = cve_obj.get("id", "N/A")

                    # Extract English description
                    descriptions = cve_obj.get("descriptions", [])
                    desc = "No description available."
                    for d in descriptions:
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break

                    # Extract CVSS Metrics
                    metrics = cve_obj.get("metrics", {})
                    cvss_data = None
                    severity = "UNKNOWN"
                    score = 0.0

                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                        metric = metrics["cvssMetricV31"][0]
                        cvss_data = metric.get("cvssData", {})
                        severity = metric.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                        score = cvss_data.get("baseScore", 0.0)
                    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                        metric = metrics["cvssMetricV30"][0]
                        cvss_data = metric.get("cvssData", {})
                        severity = metric.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                        score = cvss_data.get("baseScore", 0.0)
                    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                        metric = metrics["cvssMetricV2"][0]
                        cvss_data = metric.get("cvssData", {})
                        severity = metric.get("baseSeverity", "UNKNOWN")
                        score = cvss_data.get("baseScore", 0.0)

                    cves.append({
                        "id": cve_id,
                        "description": desc,
                        "severity": severity.upper(),
                        "score": float(score),
                        "published": cve_obj.get("published", "")[:10]
                    })
            elif response.status_code == 429:
                log_warning(f"NVD API Rate limit hit. Consider providing an API key with --api-key.")
            else:
                logging.debug(f"NVD API request failed ({response.status_code}) for query: {query}")
        except Exception as e:
            logging.debug(f"Error querying NVD for {query}: {e}")

        self.cache[cache_key] = cves
        return cves


def assess_vulnerabilities(hosts_info: List[Dict[str, Any]], nvd_client: NVDClient, max_workers: int = 5) -> List[Dict[str, Any]]:
    """Runs parallel vulnerability checks for all detected services."""
    vulnerabilities = []
    service_tasks = []

    for host in hosts_info:
        for port_info in host["ports"]:
            prod = port_info.get("product")
            ver = port_info.get("version")
            if prod and prod.lower() not in ("unknown", "n/a", ""):
                service_tasks.append((host, port_info, prod, ver))

    if not service_tasks:
        return []

    log_info(f"Auditing [bold]{len(service_tasks)}[/bold] detected services against NVD CVE Database...")

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task_id = progress.add_task("[cyan]Scanning CVEs...", total=len(service_tasks))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_service = {
                    executor.submit(nvd_client.fetch_cves, prod, ver): (host, port_info, prod, ver)
                    for host, port_info, prod, ver in service_tasks
                }
                for future in as_completed(future_to_service):
                    host, port_info, prod, ver = future_to_service[future]
                    try:
                        cves = future.result()
                        for cve in cves:
                            vulnerabilities.append({
                                "ip": host["ip"],
                                "hostname": host["hostname"],
                                "port": port_info["port"],
                                "protocol": port_info["protocol"],
                                "service": port_info["service"],
                                "product": prod,
                                "version": ver,
                                "cve_id": cve["id"],
                                "severity": cve["severity"],
                                "score": cve["score"],
                                "published": cve["published"],
                                "description": cve["description"]
                            })
                    except Exception as e:
                        logging.debug(f"CVE lookup worker error: {e}")
                    progress.advance(task_id)
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_service = {
                executor.submit(nvd_client.fetch_cves, prod, ver): (host, port_info, prod, ver)
                for host, port_info, prod, ver in service_tasks
            }
            for future in as_completed(future_to_service):
                host, port_info, prod, ver = future_to_service[future]
                try:
                    cves = future.result()
                    for cve in cves:
                        vulnerabilities.append({
                            "ip": host["ip"],
                            "hostname": host["hostname"],
                            "port": port_info["port"],
                            "protocol": port_info["protocol"],
                            "service": port_info["service"],
                            "product": prod,
                            "version": ver,
                            "cve_id": cve["id"],
                            "severity": cve["severity"],
                            "score": cve["score"],
                            "published": cve["published"],
                            "description": cve["description"]
                        })
                except Exception as e:
                    logging.debug(f"CVE lookup worker error: {e}")

    # Sort vulnerabilities by CVSS score descending
    vulnerabilities.sort(key=lambda x: x["score"], reverse=True)
    return vulnerabilities


# ==========================================
# 📄 Enterprise PDF Report Generator
# ==========================================

class NumberedCanvas(canvas.Canvas):
    """Adds running headers and 'Page X of Y' footers to all pages."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#718096"))

        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(40, 760, "pymap — Security Assessment & Penetration Test Report")
            self.drawRightString(572, 760, datetime.now().strftime("%Y-%m-%d %H:%M"))
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(40, 752, 572, 752)

        # Footer
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawString(40, 30, "CONFIDENTIAL — GENERATED BY PYMAP")
        self.drawRightString(572, 30, page_text)
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(40, 42, 572, 42)
        self.restoreState()


class PDFReportGenerator:
    """Generates corporate-standard PDF penetration test & vulnerability reports."""

    @staticmethod
    def generate(
        target: str,
        hosts_info: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        output_filename: str = "pymap_report.pdf"
    ):
        doc = SimpleDocTemplate(
            output_filename,
            pagesize=letter,
            leftMargin=40,
            rightMargin=40,
            topMargin=50,
            bottomMargin=50
        )

        styles = getSampleStyleSheet()
        
        # Custom Typography
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#1A202C")
        )
        subtitle_style = ParagraphStyle(
            'DocSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#4A5568")
        )
        h1_style = ParagraphStyle(
            'Heading1_Custom',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#2B6CB0"),
            spaceBefore=14,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            'Body_Custom',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#2D3748")
        )
        body_bold = ParagraphStyle(
            'Body_Bold',
            parent=body_style,
            fontName='Helvetica-Bold'
        )
        desc_style = ParagraphStyle(
            'Desc_Style',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#4A5568")
        )

        elements = []

        # Header Title
        elements.append(Paragraph("🛡️ Penetration Test & Security Audit Report", title_style))
        elements.append(Paragraph(f"Target: <b>{target}</b> | Generated on: {datetime.now().strftime('%B %d, %Y %H:%M:%S')}", subtitle_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#3182CE"), spaceAfter=15))

        # Executive Summary Stats
        total_hosts = len(hosts_info)
        total_services = sum(len(h.get("ports", [])) for h in hosts_info)
        total_vulns = len(vulnerabilities)

        crit_count = sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")
        med_count = sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM")
        low_count = sum(1 for v in vulnerabilities if v.get("severity") == "LOW")

        elements.append(Paragraph("Executive Summary & Risk Metrics", h1_style))
        
        summary_data = [
            [
                Paragraph("<b>Active Hosts:</b>", body_style), Paragraph(str(total_hosts), body_bold),
                Paragraph("<b>Critical CVEs:</b>", body_style), Paragraph(f"<font color='#E53E3E'><b>{crit_count}</b></font>", body_bold)
            ],
            [
                Paragraph("<b>Open Services:</b>", body_style), Paragraph(str(total_services), body_bold),
                Paragraph("<b>High CVEs:</b>", body_style), Paragraph(f"<font color='#DD6B20'><b>{high_count}</b></font>", body_bold)
            ],
            [
                Paragraph("<b>Total Vulnerabilities:</b>", body_style), Paragraph(str(total_vulns), body_bold),
                Paragraph("<b>Medium/Low CVEs:</b>", body_style), Paragraph(f"<font color='#319795'><b>{med_count + low_count}</b></font>", body_bold)
            ]
        ]
        summary_table = Table(summary_data, colWidths=[110, 150, 110, 162])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        # Section 1: Discovered Hosts and Services
        elements.append(Paragraph("1. Discovered Hosts and Active Services", h1_style))
        
        host_table_data = [[
            Paragraph("<b>Target Host</b>", body_bold),
            Paragraph("<b>OS</b>", body_bold),
            Paragraph("<b>Port/Proto</b>", body_bold),
            Paragraph("<b>Service</b>", body_bold),
            Paragraph("<b>Identified Product & Version</b>", body_bold)
        ]]

        for host in hosts_info:
            ip_str = host['ip']
            if host['hostname'] != "N/A":
                ip_str += f"<br/><font size=7 color='#718096'>({host['hostname']})</font>"
            os_str = host['os']

            if not host.get("ports"):
                host_table_data.append([
                    Paragraph(ip_str, body_style),
                    Paragraph(os_str, body_style),
                    Paragraph("N/A", body_style),
                    Paragraph("No open ports", body_style),
                    Paragraph("-", body_style)
                ])
            else:
                for idx, port in enumerate(host["ports"]):
                    port_proto = f"{port['port']}/{port['protocol']}"
                    srv = port['service']
                    prod_ver = f"{port['product']} {port['version']}".strip() or "Unknown"
                    
                    # Group visual appearance
                    host_cell = Paragraph(ip_str, body_style) if idx == 0 else Paragraph("", body_style)
                    os_cell = Paragraph(os_str, body_style) if idx == 0 else Paragraph("", body_style)
                    
                    host_table_data.append([
                        host_cell,
                        os_cell,
                        Paragraph(port_proto, body_style),
                        Paragraph(srv, body_style),
                        Paragraph(prod_ver, body_style)
                    ])

        host_table = Table(host_table_data, colWidths=[120, 100, 65, 80, 167])
        host_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('TOPPADDING', (0, 0), (-1, 0), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFC")]),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(host_table)
        elements.append(Spacer(1, 15))

        # Section 2: Detailed Vulnerability Findings
        elements.append(Paragraph("2. Detailed Vulnerability Findings (CVE / NVD)", h1_style))

        if not vulnerabilities:
            elements.append(Paragraph("<i>No known CVE vulnerabilities detected for running service versions.</i>", body_style))
        else:
            for vuln in vulnerabilities:
                sev = vuln['severity']
                score = vuln['score']

                if sev == "CRITICAL":
                    badge_color = "#E53E3E"
                elif sev == "HIGH":
                    badge_color = "#DD6B20"
                elif sev == "MEDIUM":
                    badge_color = "#D69E2E"
                elif sev == "LOW":
                    badge_color = "#38A169"
                else:
                    badge_color = "#718096"

                vuln_header = [
                    [
                        Paragraph(f"<b>{vuln['cve_id']}</b>", body_bold),
                        Paragraph(f"<b>Target:</b> {vuln['ip']}:{vuln['port']} ({vuln['service']})", body_style),
                        Paragraph(f"<font color='{badge_color}'><b>{sev} ({score})</b></font>", body_bold)
                    ]
                ]
                
                vuln_body = [
                    [
                        Paragraph(f"<b>Product:</b> {vuln['product']} {vuln['version']}", body_style),
                        Paragraph(f"<b>Published:</b> {vuln.get('published', 'N/A')}", body_style)
                    ],
                    [
                        Paragraph(f"<b>Description:</b> {vuln['description']}", desc_style),
                        Paragraph("", desc_style)
                    ]
                ]

                vuln_card_data = vuln_header + vuln_body
                vuln_table = Table(vuln_card_data, colWidths=[180, 232, 120])
                vuln_table.setStyle(TableStyle([
                    ('SPAN', (0, 2), (2, 2)), # Span description across 3 cols
                    ('SPAN', (1, 1), (2, 1)),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                    ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor("#CBD5E0")),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]))

                elements.append(KeepTogether([vuln_table, Spacer(1, 8)]))

        doc.build(elements, canvasmaker=NumberedCanvas)
        log_success(f"Audit report generated successfully: [bold green]{output_filename}[/bold green]")


# ==========================================
# 📊 CLI Results Presentation
# ==========================================

def display_cli_summary(hosts_info: List[Dict[str, Any]], vulnerabilities: List[Dict[str, Any]]):
    """Renders high-impact summaries on the terminal using Rich."""
    if not HAS_RICH:
        print(f"\n[+] Scan Complete: {len(hosts_info)} active hosts found. {len(vulnerabilities)} vulnerabilities detected.")
        return

    # Host Summary Table
    table = RichTable(title="Discovered Network Services", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Host IP", style="bold")
    table.add_column("OS", style="dim")
    table.add_column("Port", justify="center")
    table.add_column("Service", style="green")
    table.add_column("Version", style="yellow")

    for host in hosts_info:
        for p in host.get("ports", []):
            prod_ver = f"{p['product']} {p['version']}".strip() or "Unknown"
            table.add_row(host["ip"], host["os"], f"{p['port']}/{p['protocol']}", p["service"], prod_ver)

    console.print(table)
    console.print()

    # Vulnerability Table
    if vulnerabilities:
        v_table = RichTable(title="Vulnerability Assessment Results", box=box.ROUNDED, header_style="bold magenta")
        v_table.add_column("Severity", justify="center")
        v_table.add_column("CVSS", justify="center")
        v_table.add_column("CVE ID", style="bold")
        v_table.add_column("Target Service")
        v_table.add_column("Summary", max_width=45)

        for v in vulnerabilities[:15]: # Show top 15 in CLI
            sev = v["severity"]
            sev_color = "red" if sev == "CRITICAL" else ("yellow" if sev == "HIGH" else ("cyan" if sev == "MEDIUM" else "green"))
            target_str = f"{v['ip']}:{v['port']} ({v['product']})"
            desc = (v["description"][:100] + "...") if len(v["description"]) > 100 else v["description"]
            
            v_table.add_row(
                f"[{sev_color}]{sev}[/{sev_color}]",
                str(v["score"]),
                v["cve_id"],
                target_str,
                desc
            )
        console.print(v_table)
        if len(vulnerabilities) > 15:
            console.print(f"[dim]...and {len(vulnerabilities) - 15} more findings in the PDF report.[/dim]")
    else:
        console.print(Panel("[bold green]✔ No immediate vulnerabilities detected for detected service versions.[/bold green]", box=box.ROUNDED))


# ==========================================
# 🚀 Main Entrypoint
# ==========================================

def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    print_banner()

    parser = argparse.ArgumentParser(
        description="🧭 pymap — Enterprise Network Scanner & Vulnerability Assessment Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-t", "--target",
        help="Target IP, CIDR subnet, domain or range (e.g., 192.168.1.1, 192.168.1.0/24, scanme.nmap.org)\nIf omitted, local subnet is automatically detected."
    )
    parser.add_argument(
        "-p", "--ports",
        help="Specific ports to scan (e.g., '22,80,443', '1-1000', or 'all' for 1-65535)."
    )
    parser.add_argument(
        "-F", "--fast", action="store_true",
        help="Fast mode: scan top 100 common ports only."
    )
    parser.add_argument(
        "-o", "--output", default="pymap_report.pdf",
        help="Custom output PDF report filename (default: pymap_report.pdf)."
    )
    parser.add_argument(
        "--api-key",
        help="NVD API Key (grants higher rate limits: 50 requests / 30s instead of 5 / 30s)."
    )
    parser.add_argument(
        "--threads", type=int, default=5,
        help="Number of concurrent threads for CVE lookups (default: 5)."
    )
    parser.add_argument(
        "--no-pdf", action="store_true",
        help="Skip PDF report generation and display output in CLI only."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable detailed debug logs."
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Determine Target
    target = args.target
    if not target:
        log_info("No target specified. Detecting local subnet...")
        target = NetworkManager.detect_local_subnet()
        if not target:
            log_error("Could not automatically determine local subnet. Please specify manually via -t / --target.")
            sys.exit(1)
        log_success(f"Discovered local network subnet: [bold cyan]{target}[/bold cyan]")
    else:
        log_info(f"Target selected: [bold cyan]{target}[/bold cyan]")

    # Run Nmap Scan
    scanner = NmapScanner(target=target, port_spec=args.ports, fast_mode=args.fast, verbose=args.verbose)
    hosts_info = scanner.scan()

    if not hosts_info:
        log_warning("No active hosts or open services found.")
        sys.exit(0)

    log_success(f"Scan complete. Found [bold]{len(hosts_info)}[/bold] active host(s).")

    # Run Vulnerability Assessment
    nvd_client = NVDClient(api_key=args.api_key)
    vulnerabilities = assess_vulnerabilities(hosts_info, nvd_client, max_workers=args.threads)

    # CLI Output
    display_cli_summary(hosts_info, vulnerabilities)

    # Generate Enterprise PDF Report
    if not args.no_pdf:
        log_info("Generating PDF audit report...")
        try:
            PDFReportGenerator.generate(
                target=target,
                hosts_info=hosts_info,
                vulnerabilities=vulnerabilities,
                output_filename=args.output
            )
        except Exception as e:
            log_error(f"Failed to generate PDF report: {e}")


if __name__ == "__main__":
    main()
