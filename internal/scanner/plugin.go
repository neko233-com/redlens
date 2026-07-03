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
	Scheme   string
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