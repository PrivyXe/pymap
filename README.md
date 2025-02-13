# pymap Network Scanning and Vulnerability Detection Tool

This project is a Python script designed to scan a network environment to detect active devices, open ports, running services, and potential security vulnerabilities. The script performs network scanning using Nmap, analyzes service version information, and retrieves relevant security vulnerabilities from the CVE (Common Vulnerabilities and Exposures) database. Finally, it generates a detailed PDF report containing the scan results and detected vulnerabilities.

# Key Features
# Network Scanning
The script performs an in-depth network scan using Nmap on a specified IP address, CIDR block, or domain.
It collects information such as operating systems, open ports, running services, and their versions.
# Vulnerability Detection
The gathered service and version data are queried against the NVD (National Vulnerability Database) for CVE vulnerabilities.
Relevant security vulnerabilities (CVE IDs and descriptions) are retrieved and recorded for each detected service.
# PDF Reporting
The scan results and detected vulnerabilities are compiled into a readable PDF report.
The report includes detailed information such as each device’s IP address, open ports, running services, operating system details, and detected vulnerabilities.
# Automatic Subnet Detection
If no target is specified, the script automatically detects the subnet of the local network and performs a scan on that subnet.
# Parallel Processing
The vulnerability detection process is executed in parallel using ThreadPoolExecutor, improving performance, especially in large network environments.

# Technologies & Libraries Used
 Python: The script is written in Python.
 Nmap: Used for network scanning.
 Requests: Used to fetch data from the CVE database via HTTP requests.
 Netifaces: Used to detect local network interfaces and retrieve subnet information.
 ReportLab: Used to generate PDF reports containing scan results and vulnerabilities.
 Concurrent.Futures: Used for parallel processing.

Scanning on a Specific IP Address: python3 script.py -t 192.168.1.1

Scanning on a Subnet: python3 script.py -t 192.168.1.0/24

Automatic Subnet Detection and Scanning: python3 script.py

Notice: It was created for educational purposes. The user is responsible for illegal use.
