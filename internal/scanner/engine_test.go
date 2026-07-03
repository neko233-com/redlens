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

func (m *mockScanner) Name() string         { return m.name }
func (m *mockScanner) Description() string  { return "mock scanner" }
func (m *mockScanner) Scan(ctx context.Context, target *Target) (*Result, error) {
	return m.result, m.err
}

func TestEngineRegisterAndRun(t *testing.T) {
	engine := NewEngine()
	mock := &mockScanner{
		name: "test-scanner",
		result: &Result{
			Vulns:    []Vulnerability{{ID: "V001", Severity: SeverityHigh, Title: "Test Vuln"}},
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
		name:   "single-scanner",
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
