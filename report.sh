#!/bin/bash

# This script generates a security report by running a live nmap scan
# against a target IP/hostname.

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
# Description: Runs an nmap scan and prints the open ports.
# Arguments: $1 - The target IP address or hostname.
write_ports_section() {
  local target="$1"
  # Print the static section header
  echo "-----------------------------------------------------"
  echo "### 1. Open Ports and Detected Services ###"
  echo "-----------------------------------------------------"
  echo "Scanning... please wait."
  echo "" # Add a blank line for spacing

  # Execute the nmap scan and filter for open ports.
  # The output of this command pipeline is written to the report.
  nmap -sV "$target" | grep "open"
  echo "" # Add a blank line for spacing
}

# Function: write_vulns_section
# Description: Prints the placeholder section for identified vulnerabilities.
write_vulns_section() {
  cat << EOF
-----------------------------------------------------
### 2. Potential Vulnerabilities Identified ###
-----------------------------------------------------

CVE-2023-XXXX - Outdated Web Server: The service on port 443 appears to be running an outdated version.
Default Credentials - FTP Server: The FTP service may be using default, insecure credentials.

EOF
}

# Function: write_recs_section
# Description: Prints the placeholder section for recommendations.
write_recs_section() {
  cat << EOF
-----------------------------------------------------
### 3. Recommendations for Remediation ###
-----------------------------------------------------

- Update all software to the latest versions to patch known exploits.
- Change default credentials immediately on all services.
- Implement a firewall and configure rules to restrict access to necessary ports only.

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
# Description: The main controller of the script. It validates input
#              and calls the other functions to generate the report.
main() {
  # --- Input Validation ---
  if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_ip_or_hostname>" >&2
    exit 1
  fi

  # --- Script Execution ---
  local target="$1"
  local report_file="vulnerability_report.txt"

  echo "Starting network scan against $target..."

  # Call the functions in order to build the report.
  write_header "$target" > "$report_file"
  # Pass the target to the ports section function
  write_ports_section "$target" >> "$report_file"
  write_vulns_section >> "$report_file"
  write_recs_section >> "$report_file"
  write_footer >> "$report_file"

  echo " Report for $target successfully generated: $report_file"
}

# --- Script Entry Point ---
main "$@"

