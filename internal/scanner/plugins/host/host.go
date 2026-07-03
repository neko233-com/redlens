package host

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/redlens/redlens/internal/scanner"
)

type HostScanner struct{}

func New() *HostScanner {
	return &HostScanner{}
}

func (h *HostScanner) Name() string { return "host" }
func (h *HostScanner) Description() string {
	return "Host configuration scanner - checks OS security settings"
}

func (h *HostScanner) Scan(ctx context.Context, target *scanner.Target) (*scanner.Result, error) {
	result := &scanner.Result{
		ScanTime: time.Now(),
	}

	if vuln := h.checkDNS(ctx, target.Host); vuln != nil {
		result.Vulns = append(result.Vulns, *vuln)
	}

	if vulns := h.checkMisconfigs(ctx, target); len(vulns) > 0 {
		result.Vulns = append(result.Vulns, vulns...)
	}

	result.Evidence = append(result.Evidence, scanner.Evidence{
		Type:    scanner.EvidenceLog,
		Content: fmt.Sprintf("OS: %s, Arch: %s", runtime.GOOS, runtime.GOARCH),
	})

	return result, nil
}

func (h *HostScanner) checkDNS(ctx context.Context, host string) *scanner.Vulnerability {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return &scanner.Vulnerability{
			ID:          "HOST-001",
			Severity:    scanner.SeverityLow,
			Title:       "DNS Resolution Issue",
			Description: fmt.Sprintf("Could not resolve hostname: %s", host),
			Evidence: []scanner.Evidence{{
				Type:    scanner.EvidenceLog,
				Content: fmt.Sprintf("DNS lookup failed: %v", err),
			}},
			Remediation: "Verify DNS configuration and hostname",
			CVSS:        2.0,
		}
	}
	return nil
}

func (h *HostScanner) checkMisconfigs(ctx context.Context, target *scanner.Target) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	if h.isPortOpen(target.Host, 23) {
		vulns = append(vulns, scanner.Vulnerability{
			ID:          "HOST-002",
			Severity:    scanner.SeverityHigh,
			Title:       "Telnet Service Enabled",
			Description: "Telnet transmits data in plaintext including credentials",
			Evidence: []scanner.Evidence{{
				Type:    scanner.EvidenceLog,
				Content: "Port 23 (telnet) is open",
			}},
			Remediation: "Disable Telnet and use SSH instead",
			CVSS:        7.5,
		})
	}

	if h.isPortOpen(target.Host, 21) {
		vulns = append(vulns, scanner.Vulnerability{
			ID:          "HOST-003",
			Severity:    scanner.SeverityMedium,
			Title:       "FTP Service Enabled",
			Description: "FTP transmits data including credentials in plaintext",
			Evidence: []scanner.Evidence{{
				Type:    scanner.EvidenceLog,
				Content: "Port 21 (FTP) is open",
			}},
			Remediation: "Use SFTP or FTPS instead of plain FTP",
			CVSS:        5.3,
		})
	}

	if isLocalhost(target.Host) && os.Getuid() == 0 {
		vulns = append(vulns, scanner.Vulnerability{
			ID:          "HOST-004",
			Severity:    scanner.SeverityHigh,
			Title:       "Running as Root/Administrator",
			Description: "Scanner is running with elevated privileges",
			Evidence: []scanner.Evidence{{
				Type:    scanner.EvidenceLog,
				Content: "Process running as root",
			}},
			Remediation: "Run services with least privilege principle",
			CVSS:        7.0,
		})
	}

	return vulns
}

func (h *HostScanner) isPortOpen(host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func isLocalhost(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "10.")
}
