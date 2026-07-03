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
