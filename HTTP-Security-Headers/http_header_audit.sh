#!/bin/bash

# HTTP Security Headers CLI Auditor
# Author: Tiga06

set -euo pipefail

# Colors for CLI output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Security headers to check
SECURITY_HEADERS=(
    "Content-Security-Policy"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Strict-Transport-Security"
    "Permissions-Policy"
    "Referrer-Policy"
    "X-XSS-Protection"
)

# Server info headers
SERVER_HEADERS=(
    "Server"
    "X-Powered-By"
    "Via"
    "X-AspNet-Version"
    "X-Generator"
)

usage() {
    echo "Usage: $0 [OPTIONS] <URL>"
    echo "       $0 -f <targets_file>"
    echo ""
    echo "Options:"
    echo "  -f FILE    Read targets from file (one URL per line)"
    echo "  -j         JSON output only (no CLI summary)"
    echo "  -p         Pretty-print JSON output"
    echo "  -r         Don't follow redirects (analyze original URL only)"
    echo "  -h         Show this help"
    exit 1
}

fetch_headers() {
    local url="$1"
    local follow_redirects="$2"
    
    if [[ "$follow_redirects" == "true" ]]; then
        curl -s -I -L --max-time 10 --connect-timeout 5 "$url" 2>/dev/null || echo ""
    else
        curl -s -I --max-time 10 --connect-timeout 5 "$url" 2>/dev/null || echo ""
    fi
}

get_redirect_info() {
    local url="$1"
    local redirect_output
    redirect_output=$(curl -s -I -L -w "FINAL_URL:%{url_effective}\nREDIRECT_COUNT:%{num_redirects}\n" "$url" 2>/dev/null)
    
    local final_url
    local redirect_count
    final_url=$(echo "$redirect_output" | grep "FINAL_URL:" | cut -d: -f2-)
    redirect_count=$(echo "$redirect_output" | grep "REDIRECT_COUNT:" | cut -d: -f2)
    
    echo "$final_url|$redirect_count"
}

analyze_csp() {
    local csp="$1"
    local risk="Low"
    local issues=()
    
    if [[ "$csp" == *"unsafe-inline"* ]]; then
        risk="High"
        issues+=("unsafe-inline detected")
    fi
    
    if [[ "$csp" == *"unsafe-eval"* ]]; then
        risk="High"
        issues+=("unsafe-eval detected")
    fi
    
    if [[ "$csp" == *"*"* ]]; then
        risk="Medium"
        issues+=("wildcard (*) source detected")
    fi
    
    echo "$risk|${issues[*]}"
}

get_header_value() {
    local headers="$1"
    local header_name="$2"
    echo "$headers" | grep -i "^$header_name:" | cut -d' ' -f2- | tr -d '\r\n' || echo ""
}

audit_url() {
    local url="$1"
    local follow_redirects="$2"
    local headers
    local json_output=""
    local redirect_info=""
    
    # Get redirect information
    if [[ "$follow_redirects" == "true" ]]; then
        redirect_info=$(get_redirect_info "$url")
    fi
    
    headers=$(fetch_headers "$url" "$follow_redirects")
    
    if [[ -z "$headers" ]]; then
        echo "{\"url\":\"$url\",\"error\":\"Failed to fetch headers\"}"
        return
    fi
    
    json_output="{\"url\":\"$url\""
    
    # Add redirect information if following redirects
    if [[ "$follow_redirects" == "true" && -n "$redirect_info" ]]; then
        local final_url
        local redirect_count
        final_url=$(echo "$redirect_info" | cut -d'|' -f1)
        redirect_count=$(echo "$redirect_info" | cut -d'|' -f2)
        
        json_output+=",\"redirect_info\":{\"final_url\":\"$final_url\",\"redirect_count\":$redirect_count}"
        
        if [[ "$redirect_count" -gt 0 ]]; then
            high_risk_issues+=("$redirect_count redirect(s) detected - potential security risk")
        fi
    fi
    
    json_output+=",\"headers\":{"
    
    # Check security headers
    local header_results=()
    local missing_headers=()
    local high_risk_issues=()
    
    for header in "${SECURITY_HEADERS[@]}"; do
        local value
        value=$(get_header_value "$headers" "$header")
        
        if [[ -n "$value" ]]; then
            local risk="Low"
            local analysis=""
            
            case "$header" in
                "Content-Security-Policy")
                    local csp_analysis
                    csp_analysis=$(analyze_csp "$value")
                    risk=$(echo "$csp_analysis" | cut -d'|' -f1)
                    analysis=$(echo "$csp_analysis" | cut -d'|' -f2)
                    ;;
                "X-Frame-Options")
                    if [[ "$value" != *"DENY"* && "$value" != *"SAMEORIGIN"* ]]; then
                        risk="Medium"
                        analysis="Weak X-Frame-Options value"
                    fi
                    ;;
            esac
            
            header_results+=("\"$header\":{\"status\":\"present\",\"value\":\"$value\",\"risk\":\"$risk\"}")
            
            if [[ "$risk" == "High" ]]; then
                high_risk_issues+=("$header: $analysis")
            fi
        else
            header_results+=("\"$header\":{\"status\":\"missing\",\"risk\":\"High\"}")
            missing_headers+=("$header")
            high_risk_issues+=("$header missing")
        fi
    done
    
    json_output+=$(IFS=','; echo "${header_results[*]}")
    json_output+="},\"server_info\":{"
    
    # Extract server info
    local server_results=()
    for header in "${SERVER_HEADERS[@]}"; do
        local value
        value=$(get_header_value "$headers" "$header")
        if [[ -n "$value" ]]; then
            server_results+=("\"$header\":\"$value\"")
        fi
    done
    
    json_output+=$(IFS=','; echo "${server_results[*]}")
    json_output+="},\"summary\":{"
    json_output+="\"missing_headers\":[$(printf '"%s",' "${missing_headers[@]}" | sed 's/,$//')],"
    json_output+="\"high_risk_issues\":[$(printf '"%s",' "${high_risk_issues[@]}" | sed 's/,$//')]"
    json_output+="}}"
    
    echo "$json_output"
}

print_cli_summary() {
    local json="$1"
    local url
    local missing_count
    local risk_count
    
    url=$(echo "$json" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
    
    # Count missing headers by extracting the array and counting elements
    local missing_array
    missing_array=$(echo "$json" | sed -n 's/.*"missing_headers":\[\([^]]*\)\].*/\1/p')
    if [[ -n "$missing_array" && "$missing_array" != "" ]]; then
        missing_count=$(echo "$missing_array" | grep -o '"[^"]*"' | wc -l)
    else
        missing_count=0
    fi
    
    # Count high risk issues
    local risk_array
    risk_array=$(echo "$json" | sed -n 's/.*"high_risk_issues":\[\([^]]*\)\].*/\1/p')
    if [[ -n "$risk_array" && "$risk_array" != "" ]]; then
        risk_count=$(echo "$risk_array" | grep -o '"[^"]*"' | wc -l)
    else
        risk_count=0
    fi
    
    echo -e "\n${YELLOW}=== $url ===${NC}"
    
    if [[ $risk_count -gt 0 ]]; then
        echo -e "${RED}⚠ High Risk Issues: $risk_count${NC}"
    else
        echo -e "${GREEN}✓ No high risk issues detected${NC}"
    fi
    
    if [[ $missing_count -gt 0 ]]; then
        echo -e "${RED}✗ Missing Headers: $missing_count${NC}"
    else
        echo -e "${GREEN}✓ All security headers present${NC}"
    fi
}

pretty_print_json() {
    local json="$1"
    if command -v jq >/dev/null 2>&1; then
        echo "$json" | jq .
    else
        echo "$json" | python3 -m json.tool 2>/dev/null || echo "$json"
    fi
}

main() {
    local json_only=false
    local pretty_print=false
    local follow_redirects=true
    local targets_file=""
    local target_url=""
    
    while getopts "f:jphr" opt; do
        case $opt in
            f) targets_file="$OPTARG" ;;
            j) json_only=true ;;
            p) pretty_print=true ;;
            r) follow_redirects=false ;;
            h) usage ;;
            *) usage ;;
        esac
    done
    shift $((OPTIND-1))
    
    if [[ -n "$targets_file" ]]; then
        if [[ ! -f "$targets_file" ]]; then
            echo "Error: File $targets_file not found" >&2
            exit 1
        fi
        
        echo "["
        local first=true
        while IFS= read -r url; do
            [[ -z "$url" || "$url" =~ ^# ]] && continue
            
            if [[ "$first" == true ]]; then
                first=false
            else
                echo ","
            fi
            
            local result
            result=$(audit_url "$url" "$follow_redirects")
            
            if [[ "$pretty_print" == true ]]; then
                pretty_print_json "$result"
            else
                echo -n "$result"
            fi
            
            if [[ "$json_only" == false ]]; then
                print_cli_summary "$result" >&2
            fi
        done < "$targets_file"
        echo "]"
    elif [[ $# -eq 1 ]]; then
        target_url="$1"
        local result
        result=$(audit_url "$target_url" "$follow_redirects")
        
        if [[ "$pretty_print" == true ]]; then
            pretty_print_json "$result"
        else
            echo "$result"
        fi
        
        if [[ "$json_only" == false ]]; then
            print_cli_summary "$result" >&2
        fi
    else
        usage
    fi
}

main "$@"