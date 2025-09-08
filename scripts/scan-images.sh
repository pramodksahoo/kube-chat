#!/bin/bash

# KubeChat Container Image Security Scanning Integration
# Security vulnerability scanning and compliance checking
# Usage: ./scripts/scan-images.sh [options]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="${PROJECT_ROOT}/logs"
LOG_FILE="${LOG_DIR}/security-scan_$(date +%Y%m%d_%H%M%S).log"

# Scanner configuration
SCANNER="trivy"  # trivy, grype, snyk
SEVERITY_THRESHOLD="HIGH"  # LOW, MEDIUM, HIGH, CRITICAL
OUTPUT_FORMAT="table"  # table, json, sarif
SCAN_TYPE="all"  # all, kubechat, specific
FAIL_ON_HIGH=true
GENERATE_REPORT=true

# Services to scan
KUBECHAT_SERVICES=("kubechat/api-gateway" "kubechat/operator" "kubechat/audit-service" "kubechat/web")

# Colors and logging
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$1] ${*:2}" | tee -a "$LOG_FILE"; }
log_info() { log "INFO" "$@"; }
log_success() { log "SUCCESS" "${GREEN}$*${NC}"; }
log_error() { log "ERROR" "${RED}$*${NC}"; }

check_scanner() {
    case $SCANNER in
        trivy)
            if ! command -v trivy >/dev/null; then
                log_error "Trivy not installed. Install: https://aquasecurity.github.io/trivy/"
                exit 1
            fi ;;
        grype)
            if ! command -v grype >/dev/null; then
                log_error "Grype not installed. Install: https://github.com/anchore/grype"
                exit 1
            fi ;;
        *) log_error "Unsupported scanner: $SCANNER"; exit 1 ;;
    esac
    log_success "Scanner available: $SCANNER"
}

scan_image() {
    local image="$1"
    local report_file="${LOG_DIR}/scan-$(basename "$image" | sed 's/:/-/g').json"
    
    log_info "Scanning image: $image"
    
    case $SCANNER in
        trivy)
            trivy image --format json --severity "$SEVERITY_THRESHOLD" --output "$report_file" "$image" || true
            trivy image --format table --severity "$SEVERITY_THRESHOLD" "$image"
            ;;
        grype)
            grype "$image" -o json --file "$report_file" || true
            grype "$image" -o table
            ;;
    esac
}

scan_all_images() {
    local failed_scans=0
    
    for service in "${KUBECHAT_SERVICES[@]}"; do
        # Find latest local image
        local latest_image
        latest_image=$(docker images "$service" --format "{{.Repository}}:{{.Tag}}" | head -1)
        
        if [[ -n "$latest_image" ]]; then
            scan_image "$latest_image" || ((failed_scans++))
        else
            log_error "No local image found for: $service"
            ((failed_scans++))
        fi
    done
    
    if [[ $failed_scans -gt 0 ]]; then
        log_error "$failed_scans scans failed"
        return 1
    fi
    
    log_success "All security scans completed"
}

generate_security_report() {
    local report_file="${LOG_DIR}/security-report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" <<EOF
# KubeChat Security Scan Report

**Generated:** $(date)
**Scanner:** $SCANNER
**Severity Threshold:** $SEVERITY_THRESHOLD

## Scan Results Summary

$(find "$LOG_DIR" -name "scan-*.json" -type f | while read -r scan_file; do
    echo "- $(basename "$scan_file")"
done)

## Recommendations

1. Update base images to latest secure versions
2. Apply security patches for identified vulnerabilities
3. Consider using distroless or minimal base images
4. Implement regular security scanning in CI/CD pipeline

EOF
    
    log_success "Security report generated: $report_file"
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --scanner) SCANNER="$2"; shift 2 ;;
            --severity) SEVERITY_THRESHOLD="$2"; shift 2 ;;
            --image) SPECIFIC_IMAGE="$2"; SCAN_TYPE="specific"; shift 2 ;;
            --help)
                echo "Usage: $0 [--scanner trivy|grype] [--severity LOW|MEDIUM|HIGH|CRITICAL] [--image IMAGE]"
                exit 0 ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    mkdir -p "$LOG_DIR"
    check_scanner
    
    case $SCAN_TYPE in
        specific) scan_image "$SPECIFIC_IMAGE" ;;
        *) scan_all_images ;;
    esac
    
    if [[ "$GENERATE_REPORT" == "true" ]]; then
        generate_security_report
    fi
}

main "$@"