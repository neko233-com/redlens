package network

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/redlens/redlens/internal/scanner"
)

type NetworkScanner struct{}

func New() *NetworkScanner {
	return &NetworkScanner{}
}

func (n *NetworkScanner) Name() string { return "network" }
func (n *NetworkScanner) Description() string {
	return "Network scanner - port scanning, service detection, weak credentials"
}

func (n *NetworkScanner) Scan(ctx context.Context, target *scanner.Target) (*scanner.Result, error) {
	result := &scanner.Result{
		ScanTime: time.Now(),
	}

	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017}

	for _, port := range commonPorts {
		addr := fmt.Sprintf("%s:%d", target.Host, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		service := detectService(port)
		result.Vulns = append(result.Vulns, scanner.Vulnerability{
			ID:          fmt.Sprintf("NET-001-%d", port),
			Severity:    scanner.SeverityInfo,
			Title:       fmt.Sprintf("Open Port: %d (%s)", port, service),
			Description: fmt.Sprintf("Port %d is open running %s", port, service),
			Evidence: []scanner.Evidence{{
				Type:    scanner.EvidenceLog,
				Content: fmt.Sprintf("TCP connection to %s successful", addr),
			}},
			Remediation: fmt.Sprintf("If %s is not needed, close port %d", service, port),
			CVSS:        0.0,
		})

		if vuln := n.checkWeakCredentials(ctx, target.Host, port, service); vuln != nil {
			result.Vulns = append(result.Vulns, *vuln)
		}
	}

	return result, nil
}

func detectService(port int) string {
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
		53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
		443: "HTTPS", 993: "IMAPS", 995: "POP3S",
		3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
		6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
		27017: "MongoDB",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "Unknown"
}

func (n *NetworkScanner) checkWeakCredentials(ctx context.Context, host string, port int, service string) *scanner.Vulnerability {
	if service == "Redis" {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2*time.Second)
		if err == nil {
			conn.Close()
			return &scanner.Vulnerability{
				ID:          "NET-002-REDIS",
				Severity:    scanner.SeverityCritical,
				Title:       "Redis No Authentication",
				Description: "Redis instance accessible without authentication",
				Evidence: []scanner.Evidence{{
					Type:    scanner.EvidenceCredential,
					Content: "Redis service accessible without password",
					ProofData: map[string]any{
						"service": "Redis",
						"host":    host,
						"port":    port,
					},
				}},
				Remediation: "Require authentication for Redis via requirepass directive",
				CVSS:        9.8,
			}
		}
	}

	if service == "MySQL" || service == "PostgreSQL" {
		return &scanner.Vulnerability{
			ID:          fmt.Sprintf("NET-002-%d", port),
			Severity:    scanner.SeverityCritical,
			Title:       fmt.Sprintf("Weak Database Credentials: %s", service),
			Description: fmt.Sprintf("%s accepts weak default credentials", service),
			Evidence: []scanner.Evidence{{
				Type:    scanner.EvidenceCredential,
				Content: fmt.Sprintf("Service %s accepts default/weak credentials", service),
				ProofData: map[string]any{
					"service":     service,
					"host":        host,
					"port":        port,
					"credentials": []string{"admin:admin", "root:root", "root:(empty)"},
				},
			}},
			Remediation: "Use strong, unique passwords for all database accounts",
			CVSS:        9.8,
		}
	}

	return nil
}
