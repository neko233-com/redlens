package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redlens/redlens/internal/scanner"
)

type WebScanner struct{}

func New() *WebScanner {
	return &WebScanner{}
}

func (w *WebScanner) Name() string { return "web" }
func (w *WebScanner) Description() string {
	return "Web vulnerability scanner - checks for common web vulnerabilities"
}

func (w *WebScanner) Scan(ctx context.Context, target *scanner.Target) (*scanner.Result, error) {
	result := &scanner.Result{
		ScanTime: time.Now(),
	}

	baseURL := fmt.Sprintf("%s://%s:%d", target.Scheme, target.Host, target.Port)

	if vuln := w.checkAdminPanels(ctx, baseURL); vuln != nil {
		result.Vulns = append(result.Vulns, *vuln)
	}

	if vuln := w.checkDirectoryListing(ctx, baseURL); vuln != nil {
		result.Vulns = append(result.Vulns, *vuln)
	}

	if vulns := w.checkSecurityHeaders(ctx, baseURL); len(vulns) > 0 {
		result.Vulns = append(result.Vulns, vulns...)
	}

	return result, nil
}

func (w *WebScanner) checkAdminPanels(ctx context.Context, baseURL string) *scanner.Vulnerability {
	adminPaths := []string{"/admin", "/admin/login", "/wp-admin", "/phpmyadmin", "/console"}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range adminPaths {
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			return &scanner.Vulnerability{
				ID:          fmt.Sprintf("WEB-001"),
				Severity:    scanner.SeverityMedium,
				Title:       "Admin Panel Exposed",
				Description: fmt.Sprintf("Admin panel found at %s", path),
				Evidence: []scanner.Evidence{{
					Type:    scanner.EvidenceLog,
					Content: fmt.Sprintf("GET %s returned %d", path, resp.StatusCode),
				}},
				Remediation: "Restrict access to admin panels via IP whitelist or VPN",
				CVSS:        5.3,
			}
		}
	}
	return nil
}

func (w *WebScanner) checkDirectoryListing(ctx context.Context, baseURL string) *scanner.Vulnerability {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if strings.Contains(body, "Index of /") {
		return &scanner.Vulnerability{
			ID:          "WEB-002",
			Severity:    scanner.SeverityLow,
			Title:       "Directory Listing Enabled",
			Description: "Web server has directory listing enabled",
			Evidence: []scanner.Evidence{{
				Type:    scanner.EvidenceLog,
				Content: "Response contains 'Index of /' - directory listing detected",
			}},
			Remediation: "Disable directory listing in web server configuration",
			CVSS:        3.1,
		}
	}
	return nil
}

func (w *WebScanner) checkSecurityHeaders(ctx context.Context, baseURL string) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability
	requiredHeaders := map[string]string{
		"X-Frame-Options":           "Protects against clickjacking",
		"X-Content-Type-Options":    "Prevents MIME type sniffing",
		"Strict-Transport-Security": "Enforces HTTPS",
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	for header, desc := range requiredHeaders {
		if resp.Header.Get(header) == "" {
			vulns = append(vulns, scanner.Vulnerability{
				ID:          fmt.Sprintf("WEB-003-%s", header),
				Severity:    scanner.SeverityLow,
				Title:       fmt.Sprintf("Missing Security Header: %s", header),
				Description: desc,
				Evidence: []scanner.Evidence{{
					Type:    scanner.EvidenceLog,
					Content: fmt.Sprintf("Header %s not present in response", header),
				}},
				Remediation: fmt.Sprintf("Add '%s' header to HTTP responses", header),
				CVSS:        2.0,
			})
		}
	}
	return vulns
}
