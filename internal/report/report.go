package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/redlens/redlens/internal/scanner"
)

type Report struct {
	Summary   Summary           `json:"summary"`
	Vulns     []VulnSummary     `json:"vulns"`
	Results   []*scanner.Result `json:"results"`
	Generated time.Time         `json:"generated"`
}

type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	Duration   time.Duration  `json:"duration"`
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
