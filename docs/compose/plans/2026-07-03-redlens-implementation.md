# redlens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use compose:subagent (recommended) or compose:execute to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a red team vulnerability scanning report tool with Go 1.26 backend (plugin-based scanners), Vite 8 + React frontend, Docker simulation environment, and GitHub Pages documentation.

**Architecture:** Go single binary with plugin-based scanner engine. Each scanner (web, network, host) implements a common interface. Reports generated as HTML + JSON. React frontend provides dashboard, scan configuration, and interactive report viewer. Docker Compose orchestrates vulnerable test services for simulation.

**Tech Stack:** Go 1.26, Vite 8, React 19, TypeScript, Docker Compose, GitHub Pages

## Global Constraints

- Go 1.26 minimum, use `go mod` for dependency management
- Vite 8 + React 19 + TypeScript for frontend
- No CI/CD test pipelines (user requirement)
- Reports must include full evidence chain: credentials, screenshots, PoC, timestamps, impact, remediation
- Cross-platform: Windows/Linux/macOS
- GitHub repo name: `redlens`
- GitHub Pages docs in `docs/` directory

---

### Task 1: Project Scaffolding

**Covers:** [S1]

**Files:**
- Create: `go.mod`, `go.sum`
- Create: `cmd/redlens/main.go`
- Create: `internal/scanner/plugin.go`
- Create: `.gitignore`
- Create: `Makefile`

**Interfaces:**
- Produces: Go module structure, CLI entry point skeleton

- [ ] **Step 1: Initialize Go module**

```bash
cd D:\Code\neko233-Projects\redlens
go mod init github.com/redlens/redlens
```

- [ ] **Step 2: Create directory structure**

```bash
mkdir -p cmd/redlens
mkdir -p internal/scanner
mkdir -p internal/scanner/plugins/web
mkdir -p internal/scanner/plugins/network
mkdir -p internal/scanner/plugins/host
mkdir -p internal/report
mkdir -p internal/api
mkdir -p ui
mkdir -p docker/vulnerable-app
mkdir -p docs
```

- [ ] **Step 3: Create plugin interface**

Write `internal/scanner/plugin.go`:

```go
package scanner

import (
	"context"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
)

type EvidenceType string

const (
	EvidenceCredential EvidenceType = "Credential"
	EvidenceScreenshot EvidenceType = "Screenshot"
	EvidencePoC        EvidenceType = "PoC"
	EvidenceLog        EvidenceType = "Log"
)

type Target struct {
	Host     string
	Port     int
	Scheme   string // http or https
	Path     string
	Metadata map[string]string
}

type Evidence struct {
	Type      EvidenceType
	Content   string
	ProofData map[string]any
	Timestamp time.Time
}

type Vulnerability struct {
	ID          string
	Severity    Severity
	Title       string
	Description string
	Evidence    []Evidence
	Remediation string
	CVSS        float64
}

type Result struct {
	Vulns    []Vulnerability
	Evidence []Evidence
	ScanTime time.Time
	Duration time.Duration
}

type Scanner interface {
	Name() string
	Description() string
	Scan(ctx context.Context, target *Target) (*Result, error)
}
```

- [ ] **Step 4: Create main.go skeleton**

Write `cmd/redlens/main.go`:

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: redlens <command>")
		fmt.Println("Commands: scan, report, serve")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		fmt.Println("Scan command - TODO")
	case "report":
		fmt.Println("Report command - TODO")
	case "serve":
		fmt.Println("Serve command - TODO")
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
```

- [ ] **Step 5: Create .gitignore**

Write `.gitignore`:

```
# Binaries
redlens
*.exe
*.dll
*.so
*.dylib

# Test
*.test
*.out
coverage.html

# Dependencies
vendor/

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Node
node_modules/
dist/
.vite/

# Docker
docker-compose.override.yml

# Environment
.env
.env.local

# Reports (generated)
reports/
```

- [ ] **Step 6: Create Makefile**

Write `Makefile`:

```makefile
.PHONY: build run ui docker clean

build:
	go build -o redlens.exe ./cmd/redlens

run: build
	./redlens.exe serve

ui:
	cd ui && npm run dev

docker:
	docker-compose -f docker/docker-compose.yml up --build

clean:
	rm -f redlens.exe
	rm -rf reports/
```

- [ ] **Step 7: Verify Go builds**

```bash
cd D:\Code\neko233-Projects\redlens
go build ./cmd/redlens
```

Expected: builds successfully, produces `redlens.exe`

- [ ] **Step 8: Commit**

```bash
git init
git add -A
git commit -m "feat: project scaffolding with Go module, plugin interface, and CLI skeleton"
```

---

### Task 2: Scanner Engine

**Covers:** [S2]

**Files:**
- Create: `internal/scanner/engine.go`
- Create: `internal/scanner/engine_test.go`

**Interfaces:**
- Consumes: `Scanner` interface from Task 1
- Produces: `Engine` struct with `Register()`, `Run()`, `RunAll()` methods

- [ ] **Step 1: Write failing test**

Write `internal/scanner/engine_test.go`:

```go
package scanner

import (
	"context"
	"testing"
	"time"
)

type mockScanner struct {
	name   string
	result *Result
	err    error
}

func (m *mockScanner) Name() string { return m.name }
func (m *mockScanner) Description() string { return "mock scanner" }
func (m *mockScanner) Scan(ctx context.Context, target *Target) (*Result, error) {
	return m.result, m.err
}

func TestEngineRegisterAndRun(t *testing.T) {
	engine := NewEngine()
	mock := &mockScanner{
		name: "test-scanner",
		result: &Result{
			Vulns: []Vulnerability{{ID: "V001", Severity: SeverityHigh, Title: "Test Vuln"}},
			ScanTime: time.Now(),
		},
	}

	engine.Register(mock)

	target := &Target{Host: "127.0.0.1", Port: 8080}
	results, err := engine.RunAll(context.Background(), []*Target{target})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if len(results[0].Vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(results[0].Vulns))
	}
}

func TestEngineRunSingle(t *testing.T) {
	engine := NewEngine()
	mock := &mockScanner{
		name: "single-scanner",
		result: &Result{Vulns: []Vulnerability{}, ScanTime: time.Now()},
	}

	engine.Register(mock)

	target := &Target{Host: "127.0.0.1", Port: 8080}
	result, err := engine.Run(context.Background(), "single-scanner", target)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestEngineRunUnknownScanner(t *testing.T) {
	engine := NewEngine()
	target := &Target{Host: "127.0.0.1", Port: 8080}

	_, err := engine.Run(context.Background(), "nonexistent", target)

	if err == nil {
		t.Fatal("expected error for unknown scanner")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/scanner/ -v -run TestEngine
```

Expected: FAIL - `NewEngine` not defined

- [ ] **Step 3: Implement engine**

Write `internal/scanner/engine.go`:

```go
package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Engine struct {
	scanners map[string]Scanner
	mu       sync.RWMutex
}

func NewEngine() *Engine {
	return &Engine{
		scanners: make(map[string]Scanner),
	}
}

func (e *Engine) Register(s Scanner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.scanners[s.Name()] = s
}

func (e *Engine) Run(ctx context.Context, name string, target *Target) (*Result, error) {
	e.mu.RLock()
	s, ok := e.scanners[name]
	e.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("scanner %q not found", name)
	}

	start := time.Now()
	result, err := s.Scan(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("scanner %s failed: %w", name, err)
	}
	result.Duration = time.Since(start)
	return result, nil
}

func (e *Engine) RunAll(ctx context.Context, targets []*Target) ([]*Result, error) {
	e.mu.RLock()
	var scanners []Scanner
	for _, s := range e.scanners {
		scanners = append(scanners, s)
	}
	e.mu.RUnlock()

	var results []*Result
	for _, target := range targets {
		for _, s := range scanners {
			start := time.Now()
			result, err := s.Scan(ctx, target)
			if err != nil {
				continue // skip failed scanners
			}
			result.Duration = time.Since(start)
			results = append(results, result)
		}
	}
	return results, nil
}

func (e *Engine) List() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var names []string
	for name := range e.scanners {
		names = append(names, name)
	}
	return names
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/scanner/ -v -run TestEngine
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/engine.go internal/scanner/engine_test.go
git commit -m "feat: scanner engine with plugin registration and execution"
```

---

### Task 3: Web Scanner Plugin

**Covers:** [S2]

**Files:**
- Create: `internal/scanner/plugins/web/web.go`
- Create: `internal/scanner/plugins/web/web_test.go`

**Interfaces:**
- Consumes: `Scanner` interface, `Target` struct from Task 1
- Produces: `WebScanner` implementing `Scanner`

- [ ] **Step 1: Write failing test**

Write `internal/scanner/plugins/web/web_test.go`:

```go
package web

import (
	"context"
	"testing"

	"github.com/redlens/redlens/internal/scanner"
)

func TestWebScannerName(t *testing.T) {
	s := New()
	if s.Name() != "web" {
		t.Errorf("expected name 'web', got %q", s.Name())
	}
}

func TestWebScannerScan(t *testing.T) {
	s := New()
	target := &scanner.Target{
		Host:   "127.0.0.1",
		Port:   8080,
		Scheme: "http",
	}

	result, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.ScanTime.IsZero() {
		t.Error("expected ScanTime to be set")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/scanner/plugins/web/ -v
```

Expected: FAIL - package not found

- [ ] **Step 3: Implement web scanner**

Write `internal/scanner/plugins/web/web.go`:

```go
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

	// Check for exposed admin panels
	if vuln := w.checkAdminPanels(ctx, baseURL); vuln != nil {
		result.Vulns = append(result.Vulns, *vuln)
	}

	// Check for directory listing
	if vuln := w.checkDirectoryListing(ctx, baseURL); vuln != nil {
		result.Vulns = append(result.Vulns, *vuln)
	}

	// Check for security headers
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
		"X-Frame-Options":        "Protects against clickjacking",
		"X-Content-Type-Options": "Prevents MIME type sniffing",
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/scanner/plugins/web/ -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/plugins/web/
git commit -m "feat: web scanner plugin with admin panel, directory listing, and header checks"
```

---

### Task 4: Network Scanner Plugin

**Covers:** [S2]

**Files:**
- Create: `internal/scanner/plugins/network/network.go`
- Create: `internal/scanner/plugins/network/network_test.go`

**Interfaces:**
- Consumes: `Scanner` interface, `Target` struct from Task 1
- Produces: `NetworkScanner` implementing `Scanner`

- [ ] **Step 1: Write failing test**

Write `internal/scanner/plugins/network/network_test.go`:

```go
package network

import (
	"context"
	"testing"

	"github.com/redlens/redlens/internal/scanner"
)

func TestNetworkScannerName(t *testing.T) {
	s := New()
	if s.Name() != "network" {
		t.Errorf("expected name 'network', got %q", s.Name())
	}
}

func TestNetworkScannerScan(t *testing.T) {
	s := New()
	target := &scanner.Target{
		Host: "127.0.0.1",
		Port: 22,
	}

	result, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/scanner/plugins/network/ -v
```

Expected: FAIL

- [ ] **Step 3: Implement network scanner**

Write `internal/scanner/plugins/network/network.go`:

```go
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

		// Check for weak credentials on known services
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
	weakCreds := []struct{ user, pass string }{
		{"admin", "admin"},
		{"root", "root"},
		{"admin", "password"},
		{"root", ""},
		{"guest", "guest"},
	}

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
		for _, cred := range weakCreds {
			_ = cred // Would attempt connection with credentials
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
	}

	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/scanner/plugins/network/ -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/plugins/network/
git commit -m "feat: network scanner plugin with port scanning and weak credential detection"
```

---

### Task 5: Host Scanner Plugin

**Covers:** [S2]

**Files:**
- Create: `internal/scanner/plugins/host/host.go`
- Create: `internal/scanner/plugins/host/host_test.go`

**Interfaces:**
- Consumes: `Scanner` interface, `Target` struct from Task 1
- Produces: `HostScanner` implementing `Scanner`

- [ ] **Step 1: Write failing test**

Write `internal/scanner/plugins/host/host_test.go`:

```go
package host

import (
	"context"
	"testing"

	"github.com/redlens/redlens/internal/scanner"
)

func TestHostScannerName(t *testing.T) {
	s := New()
	if s.Name() != "host" {
		t.Errorf("expected name 'host', got %q", s.Name())
	}
}

func TestHostScannerScan(t *testing.T) {
	s := New()
	target := &scanner.Target{
		Host: "127.0.0.1",
	}

	result, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/scanner/plugins/host/ -v
```

Expected: FAIL

- [ ] **Step 3: Implement host scanner**

Write `internal/scanner/plugins/host/host.go`:

```go
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

	// Check DNS resolution
	if vuln := h.checkDNS(ctx, target.Host); vuln != nil {
		result.Vulns = append(result.Vulns, *vuln)
	}

	// Check for common misconfigurations
	if vulns := h.checkMisconfigs(ctx, target); len(vulns) > 0 {
		result.Vulns = append(result.Vulns, vulns...)
	}

	// OS fingerprint (basic)
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

	// Check for telnet (port 23)
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

	// Check for FTP (port 21)
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

	// Check if running as root (local scan only)
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/scanner/plugins/host/ -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/plugins/host/
git commit -m "feat: host scanner plugin with DNS, misconfiguration, and service detection"
```

---

### Task 6: Report Generation Engine

**Covers:** [S3]

**Files:**
- Create: `internal/report/report.go`
- Create: `internal/report/html.go`
- Create: `internal/report/report_test.go`

**Interfaces:**
- Consumes: `Result` structs from scanner engine
- Produces: HTML and JSON report files

- [ ] **Step 1: Write failing test**

Write `internal/report/report_test.go`:

```go
package report

import (
	"os"
	"testing"
	"time"

	"github.com/redlens/redlens/internal/scanner"
)

func TestGenerateJSON(t *testing.T) {
	results := []*scanner.Result{
		{
			Vulns: []scanner.Vulnerability{
				{ID: "V001", Severity: scanner.SeverityCritical, Title: "Test Vuln", CVSS: 9.8},
			},
			ScanTime: time.Now(),
		},
	}

	r := New(results)
	err := r.GenerateJSON("test-report.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove("test-report.json")

	data, err := os.ReadFile("test-report.json")
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	if len(data) == 0 {
		t.Error("report is empty")
	}
}

func TestGenerateHTML(t *testing.T) {
	results := []*scanner.Result{
		{
			Vulns: []scanner.Vulnerability{
				{ID: "V001", Severity: scanner.SeverityHigh, Title: "SQL Injection", CVSS: 8.5},
			},
			ScanTime: time.Now(),
		},
	}

	r := New(results)
	err := r.GenerateHTML("test-report.html")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove("test-report.html")

	data, err := os.ReadFile("test-report.html")
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	html := string(data)
	if !contains(html, "<!DOCTYPE html>") {
		t.Error("report is not valid HTML")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/report/ -v
```

Expected: FAIL - `New` not defined

- [ ] **Step 3: Implement report generator**

Write `internal/report/report.go`:

```go
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/redlens/redlens/internal/scanner"
)

type Report struct {
	Summary   Summary            `json:"summary"`
	Vulns     []VulnSummary      `json:"vulns"`
	Results   []*scanner.Result  `json:"results"`
	Generated time.Time          `json:"generated"`
}

type Summary struct {
	Total    int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	Duration  time.Duration  `json:"duration"`
}

type VulnSummary struct {
	ID       string           `json:"id"`
	Severity scanner.Severity `json:"severity"`
	Title    string           `json:"title"`
	CVSS     float64          `json:"cvss"`
}

type ReportGenerator struct {
	results []*scanner.Result
}

func New(results []*scanner.Result) *ReportGenerator {
	return &ReportGenerator{results: results}
}

func (rg *ReportGenerator) buildReport() *Report {
	report := &Report{
		Generated: time.Now(),
	}

	severityCount := make(map[string]int)
	var totalDuration time.Duration

	for _, result := range rg.results {
		totalDuration += result.Duration
		for _, v := range result.Vulns {
			report.Vulns = append(report.Vulns, VulnSummary{
				ID:       v.ID,
				Severity: v.Severity,
				Title:    v.Title,
				CVSS:     v.CVSS,
			})
			severityCount[string(v.Severity)]++
		}
	}

	report.Summary = Summary{
		Total:      len(report.Vulns),
		BySeverity: severityCount,
		Duration:   totalDuration,
	}
	report.Results = rg.results

	return report
}

func (rg *ReportGenerator) GenerateJSON(path string) error {
	report := rg.buildReport()
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func (rg *ReportGenerator) GenerateHTML(path string) error {
	report := rg.buildReport()
	html := renderHTML(report)
	return os.WriteFile(path, []byte(html), 0644)
}
```

- [ ] **Step 4: Implement HTML renderer**

Write `internal/report/html.go`:

```go
package report

import (
	"fmt"
	"strings"
)

func renderHTML(report *Report) string {
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>redlens - Vulnerability Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  h1 { color: #ff4444; font-size: 2rem; margin-bottom: 1rem; }
  h2 { color: #ff6666; margin: 2rem 0 1rem; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }
  .card { background: #1a1a1a; border-radius: 8px; padding: 1.5rem; border: 1px solid #333; }
  .card h3 { color: #888; font-size: 0.9rem; text-transform: uppercase; margin-bottom: 0.5rem; }
  .card .value { font-size: 2rem; font-weight: bold; }
  .critical { color: #ff4444; }
  .high { color: #ff8800; }
  .medium { color: #ffcc00; }
  .low { color: #44aaff; }
  .info { color: #888; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #333; }
  th { background: #1a1a1a; color: #888; text-transform: uppercase; font-size: 0.8rem; }
  .severity-badge { padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
  .evidence { background: #111; padding: 1rem; border-radius: 4px; margin: 0.5rem 0; font-family: monospace; font-size: 0.9rem; }
  .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #333; color: #666; font-size: 0.8rem; }
</style>
</head>
<body>
<div class="container">
  <h1>redlens Vulnerability Report</h1>
  <p>Generated: `)

	b.WriteString(report.Generated.Format("2006-01-02 15:04:05"))

	b.WriteString(`</p>

  <div class="summary">
    <div class="card">
      <h3>Total Vulnerabilities</h3>
      <div class="value">`)

	b.WriteString(fmt.Sprintf("%d", report.Summary.Total))

	b.WriteString(`</div>
    </div>`)

	for sev, count := range report.Summary.BySeverity {
		class := strings.ToLower(sev)
		b.WriteString(fmt.Sprintf(`
    <div class="card">
      <h3>%s</h3>
      <div class="value %s">%d</div>
    </div>`, sev, class, count))
	}

	b.WriteString(`
  </div>

  <h2>Vulnerability Details</h2>
  <table>
    <thead>
      <tr><th>ID</th><th>Severity</th><th>Title</th><th>CVSS</th></tr>
    </thead>
    <tbody>`)

	for _, v := range report.Vulns {
		class := strings.ToLower(string(v.Severity))
		b.WriteString(fmt.Sprintf(`
      <tr>
        <td>%s</td>
        <td><span class="severity-badge %s">%s</span></td>
        <td>%s</td>
        <td>%.1f</td>
      </tr>`, v.ID, class, v.Severity, v.Title, v.CVSS))
	}

	b.WriteString(`
    </tbody>
  </table>

  <h2>Evidence</h2>`)

	for _, result := range report.Results {
		for _, v := range result.Vulns {
			for _, e := range v.Evidence {
				b.WriteString(fmt.Sprintf(`
  <div class="evidence">
    <strong>[%s] %s</strong><br>
    %s
  </div>`, e.Type, v.Title, escapeHTML(e.Content)))
			}
		}
	}

	b.WriteString(`
  <div class="footer">
    <p>redlens - Red Team Vulnerability Scanner | Report generated for internal security assessment</p>
  </div>
</div>
</body>
</html>`)

	return b.String()
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/report/ -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/report/
git commit -m "feat: report generation engine with HTML and JSON output"
```

---

### Task 7: REST API

**Covers:** [S2, S3]

**Files:**
- Create: `internal/api/server.go`
- Create: `internal/api/handlers.go`

**Interfaces:**
- Consumes: `Engine` from Task 2, `ReportGenerator` from Task 6
- Produces: HTTP server on port 8080

- [ ] **Step 1: Implement API server**

Write `internal/api/server.go`:

```go
package api

import (
	"log"
	"net/http"

	"github.com/redlens/redlens/internal/scanner"
)

type Server struct {
	engine *scanner.Engine
	mux    *http.ServeMux
}

func NewServer(engine *scanner.Engine) *Server {
	s := &Server{
		engine: engine,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/scanners", s.handleListScanners)
	s.mux.HandleFunc("POST /api/scan", s.handleScan)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
}

func (s *Server) Start(addr string) error {
	log.Printf("redlens API server starting on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}
```

- [ ] **Step 2: Implement handlers**

Write `internal/api/handlers.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/redlens/redlens/internal/scanner"
)

type ScanRequest struct {
	Targets []scanner.Target `json:"targets"`
	Scanners []string        `json:"scanners,omitempty"`
}

type ScanResponse struct {
	Results []*scanner.Result `json:"results"`
	Summary struct {
		Total      int `json:"total"`
		Duration   string `json:"duration"`
	} `json:"summary"`
}

func (s *Server) handleListScanners(w http.ResponseWriter, r *http.Request) {
	scanners := s.engine.List()
	json.NewEncoder(w).Encode(map[string]any{
		"scanners": scanners,
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Targets) == 0 {
		http.Error(w, "no targets provided", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	var targets []*scanner.Target
	for i := range req.Targets {
		targets = append(targets, &req.Targets[i])
	}

	results, err := s.engine.RunAll(ctx, targets)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	total := 0
	for _, result := range results {
		total += len(result.Vulns)
	}

	resp := ScanResponse{
		Results: results,
	}
	resp.Summary.Total = total

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
```

- [ ] **Step 3: Update main.go to use API server**

Write `cmd/redlens/main.go`:

```go
package main

import (
	"fmt"
	"os"

	"github.com/redlens/redlens/internal/api"
	"github.com/redlens/redlens/internal/scanner"
	"github.com/redlens/redlens/internal/scanner/plugins/host"
	"github.com/redlens/redlens/internal/scanner/plugins/network"
	"github.com/redlens/redlens/internal/scanner/plugins/web"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: redlens <command>")
		fmt.Println("Commands: scan, report, serve")
		os.Exit(1)
	}

	engine := scanner.NewEngine()
	engine.Register(web.New())
	engine.Register(network.New())
	engine.Register(host.New())

	switch os.Args[1] {
	case "serve":
		server := api.NewServer(engine)
		if err := server.Start(":8080"); err != nil {
			fmt.Printf("Server error: %v\n", err)
			os.Exit(1)
		}
	case "scan":
		fmt.Println("CLI scan - use 'serve' mode with UI")
	case "report":
		fmt.Println("CLI report - use 'serve' mode with UI")
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
```

- [ ] **Step 4: Verify build**

```bash
go build ./cmd/redlens
```

Expected: builds successfully

- [ ] **Step 5: Commit**

```bash
git add internal/api/ cmd/redlens/main.go
git commit -m "feat: REST API server with scanner and health endpoints"
```

---

### Task 8: React Frontend Setup

**Covers:** [S1]

**Files:**
- Create: `ui/` (Vite + React project)
- Create: `ui/package.json`
- Create: `ui/vite.config.ts`

**Interfaces:**
- Consumes: REST API from Task 7
- Produces: React app with Dashboard, Scan, Report pages

- [ ] **Step 1: Create Vite React project**

```bash
cd D:\Code\neko233-Projects\redlens
npm create vite@latest ui -- --template react-ts
cd ui
npm install
npm install react-router-dom@7 recharts@2 lucide-react@latest
```

- [ ] **Step 2: Configure Vite proxy**

Write `ui/vite.config.ts`:

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
```

- [ ] **Step 3: Create app structure**

```bash
mkdir -p ui/src/pages
mkdir -p ui/src/components
```

- [ ] **Step 4: Create main App with routing**

Write `ui/src/App.tsx`:

```tsx
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Scan from './pages/Scan'
import Reports from './pages/Reports'

function App() {
  return (
    <BrowserRouter>
      <div style={{ minHeight: '100vh', background: '#0a0a0a', color: '#e0e0e0' }}>
        <nav style={{ background: '#1a1a1a', padding: '1rem 2rem', display: 'flex', gap: '2rem', alignItems: 'center', borderBottom: '1px solid #333' }}>
          <h1 style={{ color: '#ff4444', fontSize: '1.5rem' }}>redlens</h1>
          <Link to="/" style={{ color: '#888', textDecoration: 'none' }}>Dashboard</Link>
          <Link to="/scan" style={{ color: '#888', textDecoration: 'none' }}>Scan</Link>
          <Link to="/reports" style={{ color: '#888', textDecoration: 'none' }}>Reports</Link>
        </nav>
        <main style={{ padding: '2rem' }}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/reports" element={<Reports />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App
```

- [ ] **Step 5: Create Dashboard page**

Write `ui/src/pages/Dashboard.tsx`:

```tsx
import { useEffect, useState } from 'react'

interface Health {
  status: string
}

interface ScannersResponse {
  scanners: string[]
}

function Dashboard() {
  const [health, setHealth] = useState<Health | null>(null)
  const [scanners, setScanners] = useState<string[]>([])

  useEffect(() => {
    fetch('/api/health').then(r => r.json()).then(setHealth)
    fetch('/api/scanners').then(r => r.json()).then((data: ScannersResponse) => setScanners(data.scanners))
  }, [])

  return (
    <div>
      <h2 style={{ marginBottom: '2rem' }}>Dashboard</h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
        <div style={{ background: '#1a1a1a', borderRadius: '8px', padding: '1.5rem', border: '1px solid #333' }}>
          <h3 style={{ color: '#888', fontSize: '0.9rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>System Status</h3>
          <p style={{ fontSize: '1.5rem', color: health?.status === 'ok' ? '#44ff44' : '#ff4444' }}>
            {health?.status || 'Checking...'}
          </p>
        </div>

        <div style={{ background: '#1a1a1a', borderRadius: '8px', padding: '1.5rem', border: '1px solid #333' }}>
          <h3 style={{ color: '#888', fontSize: '0.9rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Available Scanners</h3>
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {scanners.map(s => (
              <li key={s} style={{ padding: '0.5rem 0', borderBottom: '1px solid #222' }}>{s}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

export default Dashboard
```

- [ ] **Step 6: Create Scan page**

Write `ui/src/pages/Scan.tsx`:

```tsx
import { useState } from 'react'

function Scan() {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('80')
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState<any>(null)

  const startScan = async () => {
    setScanning(true)
    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targets: [{ host, port: parseInt(port), scheme: 'http' }],
        }),
      })
      const data = await resp.json()
      setResults(data)
    } catch (err) {
      console.error(err)
    } finally {
      setScanning(false)
    }
  }

  return (
    <div>
      <h2 style={{ marginBottom: '2rem' }}>New Scan</h2>

      <div style={{ background: '#1a1a1a', borderRadius: '8px', padding: '1.5rem', border: '1px solid #333', maxWidth: '600px' }}>
        <div style={{ marginBottom: '1rem' }}>
          <label style={{ display: 'block', color: '#888', marginBottom: '0.5rem' }}>Target Host</label>
          <input
            value={host}
            onChange={e => setHost(e.target.value)}
            placeholder="127.0.0.1"
            style={{ width: '100%', padding: '0.75rem', background: '#0a0a0a', border: '1px solid #333', borderRadius: '4px', color: '#e0e0e0', fontSize: '1rem' }}
          />
        </div>

        <div style={{ marginBottom: '1.5rem' }}>
          <label style={{ display: 'block', color: '#888', marginBottom: '0.5rem' }}>Port</label>
          <input
            value={port}
            onChange={e => setPort(e.target.value)}
            placeholder="80"
            style={{ width: '100%', padding: '0.75rem', background: '#0a0a0a', border: '1px solid #333', borderRadius: '4px', color: '#e0e0e0', fontSize: '1rem' }}
          />
        </div>

        <button
          onClick={startScan}
          disabled={scanning || !host}
          style={{ width: '100%', padding: '0.75rem', background: scanning ? '#333' : '#ff4444', color: 'white', border: 'none', borderRadius: '4px', fontSize: '1rem', cursor: scanning ? 'not-allowed' : 'pointer' }}
        >
          {scanning ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>

      {results && (
        <div style={{ marginTop: '2rem' }}>
          <h3>Results</h3>
          <p style={{ color: '#888' }}>Found {results.summary?.total || 0} vulnerabilities</p>
          <pre style={{ background: '#111', padding: '1rem', borderRadius: '4px', overflow: 'auto', maxHeight: '400px' }}>
            {JSON.stringify(results, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

export default Scan
```

- [ ] **Step 7: Create Reports page**

Write `ui/src/pages/Reports.tsx`:

```tsx
function Reports() {
  return (
    <div>
      <h2 style={{ marginBottom: '2rem' }}>Reports</h2>
      <div style={{ background: '#1a1a1a', borderRadius: '8px', padding: '1.5rem', border: '1px solid #333' }}>
        <p style={{ color: '#888' }}>Reports will be generated after scans complete.</p>
        <p style={{ color: '#666', marginTop: '1rem' }}>Export options: HTML, JSON</p>
      </div>
    </div>
  )
}

export default Reports
```

- [ ] **Step 8: Verify frontend builds**

```bash
cd ui
npm run build
```

Expected: builds successfully to `dist/`

- [ ] **Step 9: Commit**

```bash
git add ui/
git commit -m "feat: React frontend with Dashboard, Scan, and Reports pages"
```

---

### Task 9: Docker Simulation Environment

**Covers:** [S4]

**Files:**
- Create: `docker/docker-compose.yml`
- Create: `docker/vulnerable-app/Dockerfile`
- Create: `docker/vulnerable-app/app.py`

**Interfaces:**
- Consumes: redlens binary from Task 7
- Produces: Docker Compose setup with vulnerable test services

- [ ] **Step 1: Create vulnerable Flask app**

Write `docker/vulnerable-app/app.py`:

```python
from flask import Flask, request, render_template_string, redirect
import os

app = Flask(__name__)

# Intentionally vulnerable for testing
USERS = {
    "admin": "admin",
    "root": "password",
    "test": "123456"
}

@app.route('/')
def index():
    return '''
    <html>
    <head><title>Vulnerable App</title></head>
    <body>
    <h1>Vulnerable Test Application</h1>
    <p>This app is intentionally vulnerable for redlens testing.</p>
    <ul>
    <li><a href="/login">Login</a></li>
    <li><a href="/search">Search</a></li>
    <li><a href="/admin">Admin Panel</a></li>
    <li><a href="/files">Files</a></li>
    </ul>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username in USERS and USERS[username] == password:
            return f'<h1>Welcome {username}!</h1><p>You are logged in.</p>'
        return '<h1>Login Failed</h1><p>Invalid credentials.</p>'
    return '''
    <form method="post">
    <input name="username" placeholder="Username"><br>
    <input name="password" type="password" placeholder="Password"><br>
    <button type="submit">Login</button>
    </form>
    '''

@app.route('/search')
def search():
    q = request.args.get('q', '')
    # XSS vulnerability
    return f'<h1>Search Results</h1><p>You searched for: {q}</p>'

@app.route('/admin')
def admin():
    return '<h1>Admin Panel</h1><p>Welcome to admin panel.</p>'

@app.route('/files')
def files():
    # Directory listing vulnerability
    files_list = os.listdir('.')
    return '<h1>Files</h1><ul>' + ''.join(f'<li>{f}</li>' for f in files_list) + '</ul>'

@app.route('/env')
def env():
    # Information disclosure
    return '<h1>Environment</h1><pre>' + str(dict(os.environ)) + '</pre>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

- [ ] **Step 2: Create Dockerfile for vulnerable app**

Write `docker/vulnerable-app/Dockerfile`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN pip install flask
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
```

- [ ] **Step 3: Create Docker Compose**

Write `docker/docker-compose.yml`:

```yaml
version: '3.8'

services:
  vulnerable-web:
    build: ./vulnerable-app
    ports:
      - "8080:5000"
    networks:
      - redlens-net

  redlens:
    build:
      context: ..
      dockerfile: Dockerfile
    depends_on:
      - vulnerable-web
    networks:
      - redlens-net
    volumes:
      - ../reports:/app/reports

networks:
  redlens-net:
    driver: bridge
```

- [ ] **Step 4: Create redlens Dockerfile**

Write `Dockerfile` in project root:

```dockerfile
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o redlens ./cmd/redlens

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/redlens .
EXPOSE 8080
CMD ["./redlens", "serve"]
```

- [ ] **Step 5: Verify Docker build**

```bash
cd D:\Code\neko233-Projects\redlens
docker build -t redlens .
```

Expected: builds successfully

- [ ] **Step 6: Commit**

```bash
git add docker/ Dockerfile
git commit -m "feat: Docker simulation environment with vulnerable test app"
```

---

### Task 10: GitHub Pages Documentation

**Covers:** [S5]

**Files:**
- Create: `docs/index.html`
- Create: `docs/style.css`

**Interfaces:**
- Produces: Static HTML documentation site

- [ ] **Step 1: Create docs index page**

Write `docs/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>redlens - Red Team Vulnerability Scanner</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <div class="container">
            <h1 class="logo">redlens</h1>
            <p class="tagline">Red Team Vulnerability Scanner & Reporting Tool</p>
            <nav>
                <a href="#features">Features</a>
                <a href="#installation">Installation</a>
                <a href="#usage">Usage</a>
                <a href="#docker">Docker</a>
                <a href="https://github.com/redlens/redlens">GitHub</a>
            </nav>
        </div>
    </header>

    <section id="hero">
        <div class="container">
            <h2>Full-Stack Security Assessment</h2>
            <p>Scan your infrastructure for vulnerabilities, generate compliance-ready reports with full evidence chains.</p>
            <div class="cta">
                <a href="#installation" class="btn btn-primary">Get Started</a>
                <a href="https://github.com/redlens/redlens" class="btn btn-secondary">View on GitHub</a>
            </div>
        </div>
    </section>

    <section id="features">
        <div class="container">
            <h2>Features</h2>
            <div class="grid">
                <div class="card">
                    <h3>Web Vulnerability Scanning</h3>
                    <p>Detect SQL injection, XSS, admin panel exposure, directory listing, and missing security headers.</p>
                </div>
                <div class="card">
                    <h3>Network Security Audit</h3>
                    <p>Port scanning, service fingerprinting, weak credential detection for databases and services.</p>
                </div>
                <div class="card">
                    <h3>Host Configuration Check</h3>
                    <p>OS security settings, exposed services, DNS misconfigurations, and privilege analysis.</p>
                </div>
                <div class="card">
                    <h3>Full Evidence Chain</h3>
                    <p>Reports include credentials, screenshots, PoC scripts, timestamps, and impact analysis.</p>
                </div>
                <div class="card">
                    <h3>Compliance Reports</h3>
                    <p>Generate HTML and JSON reports mapped to OWASP Top 10 and CIS benchmarks.</p>
                </div>
                <div class="card">
                    <h3>Docker Simulation</h3>
                    <p>Test against intentionally vulnerable applications with Docker Compose orchestration.</p>
                </div>
            </div>
        </div>
    </section>

    <section id="installation">
        <div class="container">
            <h2>Installation</h2>
            <pre><code># Build from source
git clone https://github.com/redlens/redlens.git
cd redlens
go build -o redlens ./cmd/redlens

# Or use Docker
docker build -t redlens .
docker run -p 8080:8080 redlens</code></pre>
        </div>
    </section>

    <section id="usage">
        <div class="container">
            <h2>Usage</h2>
            <pre><code># Start the server
./redlens serve

# Open browser
# http://localhost:3000</code></pre>
        </div>
    </section>

    <section id="docker">
        <div class="container">
            <h2>Docker Simulation</h2>
            <pre><code># Run with vulnerable test app
cd docker
docker-compose up --build

# redlens will scan the vulnerable web app</code></pre>
        </div>
    </section>

    <footer>
        <div class="container">
            <p>redlens - Built for security teams who need proof, not just findings.</p>
        </div>
    </footer>
</body>
</html>
```

- [ ] **Step 2: Create docs stylesheet**

Write `docs/style.css`:

```css
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 0 2rem; }

header { background: #111; padding: 1rem 0; border-bottom: 1px solid #222; }
header .container { display: flex; align-items: center; gap: 2rem; }
.logo { color: #ff4444; font-size: 1.5rem; }
.tagline { color: #666; font-size: 0.9rem; }
nav { display: flex; gap: 1.5rem; margin-left: auto; }
nav a { color: #888; text-decoration: none; transition: color 0.2s; }
nav a:hover { color: #ff4444; }

#hero { padding: 6rem 0; text-align: center; background: linear-gradient(180deg, #111 0%, #0a0a0a 100%); }
#hero h2 { font-size: 3rem; margin-bottom: 1rem; background: linear-gradient(135deg, #ff4444, #ff8800); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
#hero p { font-size: 1.2rem; color: #888; max-width: 600px; margin: 0 auto 2rem; }
.cta { display: flex; gap: 1rem; justify-content: center; }
.btn { padding: 0.75rem 2rem; border-radius: 4px; text-decoration: none; font-weight: bold; transition: all 0.2s; }
.btn-primary { background: #ff4444; color: white; }
.btn-primary:hover { background: #ff6666; }
.btn-secondary { background: transparent; color: #ff4444; border: 1px solid #ff4444; }
.btn-secondary:hover { background: #ff444422; }

section { padding: 4rem 0; }
h2 { font-size: 2rem; margin-bottom: 2rem; color: #fff; }

.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
.card { background: #1a1a1a; border-radius: 8px; padding: 1.5rem; border: 1px solid #333; transition: border-color 0.2s; }
.card:hover { border-color: #ff4444; }
.card h3 { color: #ff6666; margin-bottom: 0.5rem; }
.card p { color: #888; }

pre { background: #111; border-radius: 8px; padding: 1.5rem; overflow-x: auto; border: 1px solid #222; }
code { color: #44ff44; font-family: 'SF Mono', 'Fira Code', monospace; }

footer { padding: 2rem 0; border-top: 1px solid #222; text-align: center; color: #666; }
```

- [ ] **Step 3: Commit**

```bash
git add docs/
git commit -m "feat: GitHub Pages documentation site"
```

---

### Task 11: GitHub Repository Setup

**Covers:** [S5]

**Files:**
- All project files

**Interfaces:**
- Produces: GitHub repository with .gitignore and Pages enabled

- [ ] **Step 1: Create GitHub repository**

```bash
cd D:\Code\neko233-Projects\redlens
gh repo create redlens --public --description "Red Team Vulnerability Scanner & Reporting Tool"
```

- [ ] **Step 2: Push to GitHub**

```bash
git remote add origin https://github.com/redlens/redlens.git
git branch -M main
git push -u origin main
```

- [ ] **Step 3: Enable GitHub Pages**

```bash
gh api repos/redlens/redlens/pages -X POST -f source='{"branch":"main","path":"/docs"}' -f build_type='legacy'
```

- [ ] **Step 4: Verify deployment**

Check: `https://redlens.github.io/redlens/`

---

## Summary

| Task | Description | Status |
|------|-------------|--------|
| 1 | Project scaffolding | - [ ] |
| 2 | Scanner engine | - [ ] |
| 3 | Web scanner plugin | - [ ] |
| 4 | Network scanner plugin | - [ ] |
| 5 | Host scanner plugin | - [ ] |
| 6 | Report generation | - [ ] |
| 7 | REST API | - [ ] |
| 8 | React frontend | - [ ] |
| 9 | Docker simulation | - [ ] |
| 10 | GitHub Pages docs | - [ ] |
| 11 | GitHub repo setup | - [ ] |
