#!/bin/bash

# This script generates a security report by running an advanced nmap scan
# and enriching the findings with data from the NIST NVD API.

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
  echo "-----------------------------------------------------"
  echo "### 1. Open Ports and Detected Services ###"
  echo "-----------------------------------------------------"
  echo "$scan_results" | grep "open"
  echo ""
}

# Function: query_nvd
# Description: Queries the NVD API for CVEs related to a product and version.
# Arguments: $1 - Product name, $2 - Product version
query_nvd() {
    local product="$1"
    local version="$2"
    local results_limit=3
    
    echo # Add a newline for formatting
    echo "Querying NVD for vulnerabilities in: $product $version..."

    # The API needs a URL-encoded string.
    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"

    local vulnerabilities_json
    vulnerabilities_json=$(curl -s "$nvd_api_url")

    # --- Defensive Programming: Check for Errors ---
    if [[ -z "$vulnerabilities_json" ]]; then
        echo "  [!] Error: Failed to fetch data from NVD. The API might be down or unreachable."
        return
    fi
    if echo "$vulnerabilities_json" | jq -e '.message' > /dev/null; then
        echo "  [!] NVD API Error: $(echo "$vulnerabilities_json" | jq -r '.message')"
        return
    fi
    if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null; then
        echo "  [+] No vulnerabilities found in NVD for this keyword search."
        return
    fi
    # --- End Error Checks ---

    # This jq command filters and formats the JSON for our report.
    echo "$vulnerabilities_json" | jq -r \
        '.vulnerabilities[] |
        "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].baseSeverity // "N/A")\n---"'
}

# Function: write_nvd_analysis
# Description: Parses services and calls the NVD query function.
# Arguments: $1 - The full nmap scan results.
write_nvd_analysis() {
    local scan_results="$1"
    echo "-----------------------------------------------------"
    echo "### 2. Live Vulnerability Analysis (NVD) ###"
    echo "-----------------------------------------------------"

    # Process only the open port lines from the scan results
    while read -r line; do
        # Skip lines that don't contain service version info
        if [[ ! "$line" =~ (OpenSSH|Apache|httpd) ]]; then
            continue
        fi

        local product=""
        local version=""

        # Use a case statement to reliably parse different service lines
        case "$line" in
            *OpenSSH*)
                product="OpenSSH"
                # Use awk to grab the version, which is the 4th field after the service name
                version=$(echo "$line" | awk '{print $4}')
                ;;
            *Apache*|*httpd*)
                product="Apache httpd"
                # Use awk to find the version number, which often follows "Apache httpd"
                version=$(echo "$line" | awk -F'Apache httpd ' '{print $2}' | awk '{print $1}')
                ;;
        esac

        # If we successfully extracted a product and version, query the NVD
        if [[ -n "$product" && -n "$version" ]]; then
            query_nvd "$product" "$version"
        fi

    done <<< "$(echo "$scan_results" | grep "open")"
    echo ""
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
  if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_ip_or_hostname>" >&2
    exit 1
  fi

  local target="$1"
  local report_file="vulnerability_report.txt"

  echo "Starting advanced network scan against $target..."
  echo "This may take several minutes. Please wait."

  local scan_results
  # Using -sV for version detection is crucial for the API query
  scan_results=$(nmap -sV "$target")

  echo "Scan complete. Generating report..."

  # Build the report section by section
  write_header "$target" > "$report_file"
  write_ports_section "$scan_results" >> "$report_file"
  # Add the new NVD analysis section
  write_nvd_analysis "$scan_results" >> "$report_file"
  write_footer >> "$report_file"

  echo "Report for $target successfully generated: $report_file"
}

# --- Script Entry Point ---
main "$@"

