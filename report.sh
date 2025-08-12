#!/bin/bash

# This script generates a security report by running an advanced nmap scan
# to find open ports and known vulnerabilities.

#
# --- Function Definitions ---
#

# Function: write_header
# Description: Prints the main header for the report.
# Arguments: $1 - The target IP address or hostname.
write_header() {
  local target="$1"
  cat << EOF
=====================================================
      Network Security Scan Report
=====================================================

Scan Date: $(date)
Target IP Address/Hostname: $target

EOF
}

# Function: write_ports_section
# Description: Parses scan results and prints the open ports.
# Arguments: $1 - The full nmap scan results.
write_ports_section() {
  local scan_results="$1"
  # Print the static section header
  echo "-----------------------------------------------------"
  echo "### 1. Open Ports and Detected Services ###"
  echo "-----------------------------------------------------"
  # Filter the results for lines containing "open"
  echo "$scan_results" | grep "open"
  echo "" # Add a blank line for spacing
}

# Function: write_vulns_section
# Description: Analyzes scan results for potential vulnerabilities.
# Arguments: $1 - The full nmap scan results.
write_vulns_section() {
  local scan_results="$1"
  echo "-----------------------------------------------------"
  echo "### 2. Potential Vulnerabilities Identified ###"
  echo "-----------------------------------------------------"

  # Strategy A: Grep for high-confidence results from NSE
  echo "--- High-Confidence Findings from Nmap Scripts ---"
  echo "$scan_results" | grep "VULNERABLE" || echo "No high-confidence vulnerabilities found by NSE."
  echo ""

  # Strategy B: Use conditional logic for specific version checks
  echo "--- Analysis of Specific Service Versions ---"
  # Process the full scan results line by line
  local found_version_vuln=false
  while read -r line; do
    # Use a case statement to check for specific vulnerable versions
    case "$line" in
      *"vsftpd 2.3.4"*)
        echo "[!!] VULNERABILITY DETECTED: vsftpd 2.3.4 is running, which contains a known critical backdoor."
        found_version_vuln=true
        ;;
      *"Apache httpd 2.4.49"*)
        echo "[!!] VULNERABILITY DETECTED: Apache 2.4.49 is running, which is vulnerable to path traversal (CVE-2021-41773)."
        found_version_vuln=true
        ;;
      *"ProFTPD 1.3.5"*)
        echo "[!!] VULNERABILITY DETECTED: ProFTPD 1.3.5 is running, which is vulnerable to remote command execution (CVE-2015-3306)."
        found_version_vuln=true
        ;;
      *"OpenSSH 7.7"*)
        echo "[!!] VULNERABILITY DETECTED: OpenSSH 7.7 is running, which is vulnerable to username enumeration (CVE-2018-15473)."
        found_version_vuln=true
        ;;
    esac
  done <<< "$scan_results" # Feed the scan results into the loop

  if [ "$found_version_vuln" = false ]; then
    echo "No specific vulnerable software versions found based on current checks."
  fi
  echo ""
}

# Function: write_recs_section
# Description: Prints the placeholder section for recommendations.
write_recs_section() {
  cat << EOF
-----------------------------------------------------
### 3. Recommendations for Remediation ###
-----------------------------------------------------

- Review and patch all identified vulnerabilities immediately.
- Update all software to the latest stable versions.
- Implement a firewall and configure rules to restrict access.

EOF
}

# Function: write_footer
# Description: Prints the footer for the report.
write_footer() {
  cat << EOF
-----------------------------------------------------
                  End of Report
-----------------------------------------------------
EOF
}

# Function: main
# Description: The main controller of the script.
main() {
  # --- Input Validation ---
  if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_ip_or_hostname>" >&2
    exit 1
  fi

  # --- Script Execution ---
  local target="$1"
  local report_file="vulnerability_report.txt"

  echo "Starting advanced network scan against $target..."
  echo "This may take several minutes. Please wait."

  # Run the enhanced nmap scan once and store the output in a variable
  local scan_results
  scan_results=$(nmap -sV --script vuln "$target")

  echo "Scan complete. Generating report..."

  # Call the functions in order to build the report.
  write_header "$target" > "$report_file"
  write_ports_section "$scan_results" >> "$report_file"
  write_vulns_section "$scan_results" >> "$report_file"
  write_recs_section >> "$report_file"
  write_footer >> "$report_file"

  echo "Report for $target successfully generated: $report_file"
}

# --- Script Entry Point ---
main "$@"

