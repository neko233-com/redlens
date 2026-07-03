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
