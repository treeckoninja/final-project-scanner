#!/bin/bash

# Assignment 4.2 

#
# --- Function Definitions ---
#

# Function: write_header
# Description: Prints the main header for the report.
# Arguments: $1 - The target IP address or hostname.
write_header() {
  local target="$1" # Assign the first argument to a local variable for clarity
  cat << EOF
=====================================================
      Network Security Scan Report
=====================================================

Scan Date: $(date)
Target IP Address/Hostname: $target

EOF
}

# Function: write_ports_section
# Description: Prints the placeholder section for open ports.
write_ports_section() {
  cat << EOF
-----------------------------------------------------
### 1. Open Ports and Detected Services ###
-----------------------------------------------------

Port 80/tcp   - http
Port 443/tcp  - https
Port 22/tcp   - ssh

EOF
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
  # Check if exactly one argument was provided.
  if [ "$#" -ne 1 ]; then
    # If not, print a usage message to standard error and exit.
    echo "Usage: $0 <target_ip_or_hostname>" >&2
    exit 1
  fi

  # --- Script Execution ---
  local target="$1"
  local report_file="vulnerability_report.txt"

  # Call the functions in order to build the report.
  # Use > for the first call to create/overwrite the file.
  write_header "$target" > "$report_file"

  # Use >> for all subsequent calls to append to the file.
  write_ports_section >> "$report_file"
  write_vulns_section >> "$report_file"
  write_recs_section >> "$report_file"
  write_footer >> "$report_file"

  # Print a confirmation message to the console.
  echo " Report for $target successfully generated: $report_file"
}

# --- Script Entry Point ---
# This line calls the main function and passes all command-line arguments to it.
# This is the only command that runs in the global scope.
main "$@"

