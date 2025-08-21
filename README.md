# Network Vulnerability Scanner and Report Generator

## Overview

This project is a comprehensive bash script that automates network security scanning. It takes a target IP address or hostname, performs an advanced `nmap` scan to discover open ports and services, analyzes the results for known vulnerabilities, and enriches the findings with live data from the NIST National Vulnerability Database (NVD). The script then generates a clean, readable security report with actionable recommendations.

---

## Features

- **Target Input**: Accepts a single IP address or hostname as a command-line argument.
- **Advanced Scanning**: Utilizes `nmap` for service version (`-sV`), OS detection (`-O`), and vulnerability scanning with the Nmap Scripting Engine (`--script vuln`).
- **Multi-layered Vulnerability Analysis**:
    1.  Identifies high-confidence vulnerabilities directly from NSE scripts.
    2.  Performs local checks for specific, known-vulnerable software versions (e.g., vsftpd 2.3.4, ProFTPD 1.3.5).
    3.  Queries the live NIST NVD API via `curl` and `jq` to fetch the latest CVE information for discovered services.
- **Dynamic Recommendations**: Generates a list of specific, actionable remediation steps based on the vulnerabilities that were actually discovered.
- **Robust Error Handling**: Validates user input, checks for required tools (`nmap`, `curl`, `jq`), and gracefully handles failed scans.
- **Professional Report Generation**: Creates a well-formatted `.txt` report with clear headings for each section.

---

## How to Use

1.  **Prerequisites**: Ensure you have `nmap`, `curl`, and `jq` installed on your system.
    ```bash
    # On Debian/Ubuntu
    sudo apt update && sudo apt install nmap curl jq -y
    ```

2.  **Make the script executable**:
    ```bash
    chmod +x final_scanner.sh
    ```

3.  **Run the scan**: Provide a target IP address or hostname as an argument.
    ```bash
    ./final_scanner.sh <target_ip_or_hostname>
    ```
    **Example:**
    ```bash
    ./final_scanner.sh scanme.nmap.org
    ```

4.  **View the Report**: The script will generate a file named `vulnerability_report.txt` in the same directory.

---

## Vulnerability Detection Methodology

This script employs a three-pronged approach to identify vulnerabilities:

1.  **Nmap Scripting Engine (NSE)**: The `--script vuln` command runs a large collection of scripts that actively check for known vulnerabilities. The script flags any output containing the word "VULNERABLE" as a high-confidence finding.

2.  **Local Version Checks**: The script contains a hardcoded list of specific software versions that are known to be critically insecure (e.g., vsftpd 2.3.4, which contains a backdoor). This provides a fast, offline check for common, high-impact vulnerabilities.

3.  **NIST NVD API Correlation**: For each service discovered by `nmap`, the script extracts the product name and version number. It then makes a live API call to the NIST National Vulnerability Database to retrieve the latest CVEs associated with that software. This ensures the report is enriched with up-to-date, authoritative vulnerability data.

---

## **Ethical Considerations**

**This tool is for educational purposes and for use by security professionals on authorized systems only.**

- **Permission is Mandatory**: Never run this script against a target that you do not have explicit, written permission to scan. Unauthorized network scanning is illegal and unethical.
- **Scope**: All testing and development for this project must be conducted strictly within an authorized scope, such as on `localhost` (127.0.0.1), personal virtual machines, or public, designated test targets like `scanme.nmap.org`.
- **No Exploitation**: This script is a passive analysis tool. It is designed to find and report on potential vulnerabilities, **not** to exploit them. It does not contain any exploit code and should not be modified to do so. The role of this tool is that of a security analyst, not an attacker.
