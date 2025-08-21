#!/usr/bin/env bash

# This script generates a security report by running an advanced nmap scan
# and enriching the findings with data from the NIST NVD API.

# --- Script Best Practices ---
# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipelines return the exit status of the last command to exit with a non-zero status.
set -o pipefail

# --- Color Definitions for Enhanced Readability ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Disable color codes if the output is not a terminal (e.g., redirecting to a file)
if ! [ -t 1 ]; then
    RED=''
    YELLOW=''
    GREEN=''
    BLUE=''
    NC=''
fi

# --- Global Variables ---
# Create a temporary file for nmap's raw output that will be cleaned up on exit.
TEMP_SCAN_RESULTS=$(mktemp /tmp/nmap_scan_results.XXXXXX)

# --- Function Definitions ---

# Function: cleanup
# Description: Removes temporary files when the script exits.
cleanup() {
  rm -f "$TEMP_SCAN_RESULTS"
}
# Register the cleanup function to be called on script exit.
trap cleanup EXIT

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
  # Use awk for more reliable parsing to only match lines starting with a port number.
  echo "$scan_results" | awk '/^[0-9]+\/(tcp|udp)/'
  echo ""
}

# Function: query_nvd
# Description: Queries the NVD API for CVEs related to a product and version.
# Arguments: $1 - Product name, $2 - Product version
# Output: Prints CVE details and a recommendation string if vulnerabilities are found.
query_nvd() {
    local product="$1"
    local version="$2"
    local results_limit=2
    
    echo
    echo -e "${BLUE}Querying NVD for vulnerabilities in: $product $version...${NC}"

    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"

    local vulnerabilities_json
    vulnerabilities_json=$(curl --connect-timeout 10 -s "$nvd_api_url")

    if [[ -z "$vulnerabilities_json" ]] || ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null; then
        echo -e "  ${GREEN}[+] No vulnerabilities found in NVD for this keyword search.${NC}"
        return
    fi
    
    # Echo a recommendation string that can be captured by the calling function.
    echo "RECOMMENDATION: Review and patch the CVEs found for $product $version."

    echo "$vulnerabilities_json" | jq -r \
        '.vulnerabilities[] |
        "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].baseSeverity // "N/A")\n---"'
}

# Function: write_vulnerability_analysis
# Description: Analyzes scan results for potential vulnerabilities.
# Arguments: $1 - Full nmap scan results. $2 - A reference to an array for recommendations.
write_vulnerability_analysis() {
    local scan_results="$1"
    declare -n recommendations_ref=$2 # Use a nameref for the array

    echo "-----------------------------------------------------"
    echo "### 2. Vulnerability Analysis ###"
    echo "-----------------------------------------------------"

    # Use grep with context to get more useful NSE output
    local nse_vulns
    nse_vulns=$(echo "$scan_results" | grep -A 5 "VULNERABLE:" || true)
    if [[ -n "$nse_vulns" ]]; then
        echo -e "${RED}--- High-Confidence Findings from Nmap Scripts (NSE) ---${NC}"
        echo "$nse_vulns"
        recommendations_ref+=("Address all high-confidence NSE findings immediately by following the CVE remediation steps.")
    fi

    echo -e "${YELLOW}--- Analysis of Specific Service Versions (Local Checks & NVD) ---${NC}"
    while read -r line; do
        local product=""
        local version=""
        
        case "$line" in
            *OpenSSH*)
                product="OpenSSH"
                # More robust version parsing to capture the full version string (e.g., 6.6.1p1)
                version=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="OpenSSH") print $(i+1)}')
                if [[ "$version" == "7.7"* ]]; then
                    echo -e "  ${RED}[!!] VULNERABILITY: OpenSSH 7.7 is vulnerable to username enumeration (CVE-2018-15473).${NC}"
                    recommendations_ref+=("Upgrade OpenSSH to version 7.8 or later to mitigate username enumeration.")
                fi
                ;;
            *vsftpd\ 2.3.4*)
                product="vsftpd"
                version="2.3.4"
                echo -e "  ${RED}[!!] CRITICAL VULNERABILITY: vsftpd 2.3.4 contains a known critical backdoor.${NC}"
                recommendations_ref+=("Immediately upgrade or replace vsftpd 2.3.4. This version is critically compromised.")
                ;;
            *ProFTPD\ 1.3.5*)
                product="ProFTPD"
                version="1.3.5"
                echo -e "  ${RED}[!!] VULNERABILITY: ProFTPD 1.3.5 is vulnerable to remote command execution (CVE-2015-3306).${NC}"
                recommendations_ref+=("Upgrade ProFTPD to version 1.3.6 or later to patch remote command execution vulnerability.")
                ;;
            *Apache*httpd*)
                product="Apache httpd"
                version=$(echo "$line" | awk -F'Apache httpd ' '{print $2}' | awk '{print $1}')
                if [[ "$version" == "2.4.49" ]]; then
                    echo -e "  ${RED}[!!] VULNERABILITY: Apache 2.4.49 is vulnerable to path traversal (CVE-2021-41773).${NC}"
                    recommendations_ref+=("Upgrade Apache to 2.4.51 or later to fix the path traversal vulnerability.")
                fi
                ;;
            *Samba\ smbd\ 3.*|*Samba\ smbd\ 4.*)
                product="Samba"
                version=$(echo "$line" | grep -oP 'Samba smbd \K[0-9]+\.[0-9]+\.[0-9]+')
                echo -e "  ${RED}[!!] CRITICAL VULNERABILITY: Older Samba versions are vulnerable to SambaCry (CVE-2017-7494).${NC}"
                recommendations_ref+=("Upgrade Samba to version 4.6.4 or later to mitigate the SambaCry remote code execution vulnerability.")
                ;;
            *MySQL*|*MariaDB*)
                product="MySQL"
                version=$(echo "$line" | grep -oP '(MySQL|MariaDB) \K[0-9]+\.[0-9]+\.[0-9]+')
                echo -e "  ${YELLOW}[!] INFO: Detected MySQL/MariaDB. Versions prior to MySQL 5.7 are unsupported and may have numerous vulnerabilities.${NC}"
                recommendations_ref+=("Verify MySQL/MariaDB version. If unsupported, upgrade to a modern, patched version.")
                ;;
            *Apache\ Tomcat*)
                product="Apache Tomcat"
                version=$(echo "$line" | grep -oP 'Apache Tomcat \K[0-9]+\.[0-9]+\.[0-9]+')
                if [[ "$version" == "9.0.30" ]]; then
                     echo -e "  ${RED}[!!] VULNERABILITY: Apache Tomcat 9.0.30 is vulnerable to Ghostcat (CVE-2020-1938).${NC}"
                     recommendations_ref+=("Upgrade Apache Tomcat to 9.0.31 or later to mitigate the Ghostcat vulnerability.")
                fi
                ;;
            *PHP/5.*)
                product="PHP"
                version=$(echo "$line" | grep -oP 'PHP/\K[0-9]+\.[0-9]+\.[0-9]+')
                echo -e "  ${RED}[!!] VULNERABILITY: PHP 5.x is end-of-life and unsupported. It contains numerous known vulnerabilities.${NC}"
                recommendations_ref+=("Upgrade from PHP 5.x to a modern, supported version (e.g., PHP 8.x) immediately.")
                ;;
            *ISC\ BIND*)
                product="ISC BIND"
                version=$(echo "$line" | grep -oP 'ISC BIND \K[\d\.\-a-zA-Z]+')
                echo -e "  ${YELLOW}[!] INFO: Detected ISC BIND. Versions prior to 9.11.3 are known to have multiple DoS vulnerabilities.${NC}"
                recommendations_ref+=("Verify the version of ISC BIND. If older than 9.11.3, upgrade to the latest stable release to prevent Denial of Service attacks.")
                ;;
        esac

        if [[ -n "$product" && -n "$version" ]]; then
            local nvd_output
            nvd_output=$(query_nvd "$product" "$version")
            
            local new_rec
            new_rec=$(echo "$nvd_output" | grep "RECOMMENDATION:" | sed 's/RECOMMENDATION: //' || true)
            if [[ -n "$new_rec" ]]; then
                recommendations_ref+=("$new_rec")
            fi
            
            echo "$nvd_output" | grep -v "RECOMMENDATION:"
        fi

    done <<< "$(echo "$scan_results" | awk '/^[0-9]+\/(tcp|udp)/')"
    echo ""
}

# Function: write_recommendations
# Description: Prints remediation advice based on findings.
# Arguments: An array of recommendation strings.
write_recommendations() {
    echo "-----------------------------------------------------"
    echo "### 3. Recommendations for Remediation ###"
    echo "-----------------------------------------------------"
    
    if [ ${#@} -eq 0 ]; then
        echo -e "${GREEN}No specific vulnerabilities requiring action were found based on the current checks.${NC}"
    else
        local count=1
        for rec in "$@"; do
            echo "- (${count}) $rec"
            ((count++))
        done
    fi
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
    echo -e "${RED}Usage: $0 <target_ip_or_hostname>${NC}" >&2
    exit 1
  fi

  for tool in nmap curl jq; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${RED}Error: Required tool '$tool' is not installed. Please install it to continue.${NC}" >&2
        exit 1
    fi
  done

  local target="$1"
  local report_file="vulnerability_report.txt"
  local recommendations=()

  echo -e "${BLUE}Starting advanced network scan against $target...${NC}"
  echo "This may take several minutes. Please wait."

  if ! nmap -sV -O --script vuln "$target" -oN "$TEMP_SCAN_RESULTS"; then
      echo -e "${RED}[!!] Error: nmap scan failed. Please check the target and your network connection.${NC}" >&2
      exit 1
  fi
  
  local scan_results
  scan_results=$(cat "$TEMP_SCAN_RESULTS")

  echo -e "${GREEN}Scan complete. Generating report...${NC}"

  # Build the report section by section and capture the full output
  local full_report
  full_report=$(
    write_header "$target"
    write_ports_section "$scan_results"
    write_vulnerability_analysis "$scan_results" recommendations
    write_recommendations "${recommendations[@]}"
    write_footer
  )
  
  # Write the plain text version to the file
  echo -e "$full_report" | sed 's/\\033\[[0-9;]*m//g' > "$report_file"

  # Print the colorized version to the console
  echo -e "$full_report"

  echo -e "${GREEN} Report for $target successfully generated: $report_file${NC}"
}

# --- Script Entry Point ---
main "$@"
