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
