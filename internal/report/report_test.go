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
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
