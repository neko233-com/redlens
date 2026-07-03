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
