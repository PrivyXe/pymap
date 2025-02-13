import nmap
import requests
import socket
import subprocess
import os
import logging
import argparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    import netifaces
except ImportError:
    netifaces = None
cve_cache = {}
def get_subnet():
    if netifaces:
        logging.info("Scanning network interfaces with Netifaces...")
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    ip = addr_info.get("addr")
                    netmask = addr_info.get("netmask")
                    if ip and netmask and not ip.startswith("127."):
                        if netmask == "255.255.255.0":
                            subnet = ".".join(ip.split(".")[:3]) + ".0/24"
                            logging.info(f"Found subnet: {subnet}")
                            return subnet
        logging.warning("No suitable subnet found using Netifaces.")
        return None
    else:
        try:
            if os.name == "nt":
                result = subprocess.check_output("ipconfig", shell=True).decode("utf-8")
                for line in result.split("\n"):
                    if "IPv4 Address" in line:
                        ip = line.split(":")[1].strip()
                        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
                        logging.info(f"Found subnet: {subnet}")
                        return subnet
            else:
                result = subprocess.check_output("ifconfig", shell=True).decode("utf-8")
                for line in result.split("\n"):
                    if "inet " in line and "broadcast" in line:
                        ip = line.split()[1]
                        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
                        logging.info(f"Found subnet: {subnet}")
                        return subnet
        except Exception as e:
            logging.error(f"Error occurred while detecting network: {e}")
        return None

def detailed_network_scan(target, nmap_args):
    logging.info(f"Starting Nmap scan on {target}...")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments=nmap_args)
    except Exception as e:
        logging.error(f"Error during Nmap scan: {e}")
        return []
    hosts_info = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            os_info = nm[host].get("osmatch", [{}])[0].get("name", "Unknown")
            info = {
                "ip": host,
                "os": os_info,
                "ports": []
            }
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    port_data = nm[host][proto][port]
                    info["ports"].append({
                        "port": port,
                        "service": port_data.get("name", "Unknown"),
                        "version": port_data.get("version", "Unknown"),
                        "product": port_data.get("product", "Unknown")
                    })
            hosts_info.append(info)
    logging.info(f"Nmap scan completed. {len(hosts_info)} active hosts found.")
    return hosts_info

def fetch_cve_data(product, version):
    cache_key = f"{product}-{version}"
    if cache_key in cve_cache:
        logging.info(f"Fetching CVE information from cache: {cache_key}")
        return cve_cache[cache_key]
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {
        "keyword": f"{product} {version}",
        "resultsPerPage": 5
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            cves = []
            for item in data.get("result", {}).get("CVE_Items", []):
                cve_id = item["cve"]["CVE_data_meta"]["ID"]
                description = item["cve"]["description"]["description_data"][0]["value"]
                cves.append({"id": cve_id, "description": description})
            cve_cache[cache_key] = cves
            logging.info(f"{len(cves)} CVEs found for {cache_key}.")
            return cves
        else:
            logging.error(f"CVE API error: {response.status_code}")
    except Exception as e:
        logging.error(f"Error occurred while fetching CVE data: {e}")
    cve_cache[cache_key] = []
    return []
def detect_vulnerabilities_with_cve(network_details):
    logging.info("Vulnerability detection starting...")
    vulnerabilities = []
    tasks = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for host in network_details:
            for port_info in host["ports"]:
                product = port_info["product"]
                version = port_info["version"]
                if product and version and product != "Unknown" and version != "Unknown":
                    future = executor.submit(fetch_cve_data, product, version)
                    tasks.append((future, host, port_info, product, version))
        for future, host, port_info, prod, ver in tasks:
            cves = future.result()
            for cve in cves:
                vulnerabilities.append({
                    "ip": host["ip"],
                    "port": port_info["port"],
                    "service": port_info["service"],
                    "product": prod,
                    "version": ver,
                    "cve_id": cve["id"],
                    "description": cve["description"]
                })
    logging.info(f"Total {len(vulnerabilities)} vulnerabilities found.")
    return vulnerabilities
def generate_report(network_details, vulnerabilities, filename="report.pdf"):
    logging.info("Generating PDF report...")
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Penetration Test Report")
    y = height - 80
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Network Scan Results:")
    y -= 20
    c.setFont("Helvetica", 12)
    for host in network_details:
        c.drawString(50, y, f"IP: {host['ip']}")
        y -= 15
        c.drawString(50, y, f"Operating System: {host['os']}")
        y -= 15
        if host.get("ports"):
            c.drawString(50, y, "Open Ports and Services:")
            y -= 15
            for port in host["ports"]:
                port_line = (f"Port: {port['port']} - Service: {port['service']} - "
                             f"Version: {port['version']} - Product: {port['product']}")
                c.drawString(60, y, port_line)
                y -= 15
                if y < 50:
                    c.showPage()
                    y = height - 50
        else:
            c.drawString(50, y, "No open ports found.")
            y -= 15
        y -= 10  
        if y < 50:
            c.showPage()
            y = height - 50

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Vulnerability Detection Results:")
    y -= 20
    c.setFont("Helvetica", 12)
    if vulnerabilities:
        for vuln in vulnerabilities:
            c.drawString(50, y, f"IP: {vuln['ip']} - Port: {vuln['port']} - Service: {vuln['service']}")
            y -= 15
            c.drawString(50, y, f"Product: {vuln['product']} - Version: {vuln['version']}")
            y -= 15
            c.drawString(50, y, f"CVE ID: {vuln['cve_id']}")
            y -= 15
            c.drawString(50, y, f"Description: {vuln['description']}")
            y -= 25
            if y < 50:
                c.showPage()
                y = height - 50
    else:
        c.drawString(50, y, "No vulnerabilities found.")
        y -= 15
    c.save()
    logging.info(f"Report generated: {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Network scanning and vulnerability reporting tool. "
                    "Target can be specified as IP, CIDR, domain, or IP range."
    )
    parser.add_argument(
        "-t", "--target",
        help="Target to scan (e.g., 192.168.1.1, 192.168.1.0/24, scanme.nmap.org, 192.168.1.1-254)"
    )
    args = parser.parse_args()
    if args.target:
        target = args.target
        logging.info(f"Target provided by user: {target}")
    else:
        target = get_subnet()
        if not target:
            logging.error("Network could not be detected. Please enter the target manually.")
            exit(1)
        logging.info(f"Automatically detected target: {target}")

    nmap_args = "-T4 -A -p- -sV -O -v"

    network_details = detailed_network_scan(target, nmap_args)
    if not network_details:
        logging.error("No hosts found during network scan.")
        exit(1)

    vulnerabilities = detect_vulnerabilities_with_cve(network_details)

    generate_report(network_details, vulnerabilities)
