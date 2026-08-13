package services

import (
	"black-hat/models"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type Reporter struct{}

func NewReporter() *Reporter {
	return &Reporter{}
}

func (r *Reporter) GenerateJSON(result *models.AnalysisResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

func (r *Reporter) GenerateHTML(result *models.AnalysisResult, lang string) string {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html>\n<html lang=\"" + lang + "\">\n<head>\n")
	sb.WriteString("<meta charset=\"UTF-8\">\n")
	sb.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	sb.WriteString("<title>KernelSpy - Analysis Report</title>\n")
	sb.WriteString("<style>\n")
	sb.WriteString("body { background: #000; color: #fff; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 40px; }\n")
	sb.WriteString("h1 { font-size: 2.5rem; margin-bottom: 10px; }\n")
	sb.WriteString("h2 { font-size: 1.8rem; margin-top: 40px; border-bottom: 1px solid #1a1a1a; padding-bottom: 10px; }\n")
	sb.WriteString("h3 { font-size: 1.3rem; margin-top: 30px; }\n")
	sb.WriteString("table { width: 100%; border-collapse: collapse; margin: 20px 0; }\n")
	sb.WriteString("th { background: #0a0a0a; padding: 12px; text-align: left; border-bottom: 1px solid #1a1a1a; }\n")
	sb.WriteString("td { padding: 12px; border-bottom: 1px solid #111; }\n")
	sb.WriteString("tr:hover { background: #0a0a0a; }\n")
	sb.WriteString(".badge { padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; }\n")
	sb.WriteString(".badge-critical { background: #ff0000; color: #fff; }\n")
	sb.WriteString(".badge-high { background: #ff6600; color: #fff; }\n")
	sb.WriteString(".badge-medium { background: #ffcc00; color: #000; }\n")
	sb.WriteString(".badge-low { background: #0066ff; color: #fff; }\n")
	sb.WriteString(".badge-info { background: #666666; color: #fff; }\n")
	sb.WriteString(".stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }\n")
	sb.WriteString(".stat { background: #0a0a0a; border: 1px solid #1a1a1a; padding: 20px; border-radius: 8px; }\n")
	sb.WriteString(".stat-value { font-size: 2rem; font-weight: 800; }\n")
	sb.WriteString(".stat-label { color: #a0a0a0; margin-top: 5px; }\n")
	sb.WriteString(".metric { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #111; }\n")
	sb.WriteString("</style>\n</head>\n<body>\n")

	sb.WriteString("<h1>KernelSpy - Analysis Report</h1>\n")
	sb.WriteString("<p style=\"color: #a0a0a0;\">Generated on " + time.Now().Format("January 2, 2006 15:04") + "</p>\n")

	sb.WriteString("<div class=\"stats\">\n")
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value\">%d</div><div class=\"stat-label\">Files Scanned</div></div>\n", result.FilesScanned))
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value\">%d</div><div class=\"stat-label\">Security Findings</div></div>\n", len(result.SecurityFindings)))
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value\">%d</div><div class=\"stat-label\">Quality Issues</div></div>\n", len(result.QualityFindings)))
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value\">%d</div><div class=\"stat-label\">Dependency Vulnerabilities</div></div>\n", len(result.DependencyVulns)))
	sb.WriteString("</div>\n")

	// Fail-safe banner: when scanners could not run, say so loudly instead of
	// presenting a clean report.
	if degraded := degradedScanners(result.ToolStatuses); len(degraded) > 0 {
		sb.WriteString("<div style=\"background:#3a1a00;border:1px solid #ff6600;color:#ffcc99;padding:16px 20px;border-radius:8px;margin:20px 0;\">")
		sb.WriteString("<strong>⚠ Incomplete scan:</strong> " + escapeHTML(strings.Join(degraded, ", ")) + " could not run. Results may be missing findings.</div>\n")
	}

	if len(result.SecurityFindings) > 0 {
		sb.WriteString("<h2>Security Findings</h2>\n")
		sb.WriteString("<table><thead><tr><th>Rule</th><th>File</th><th>Line</th><th>Severity</th><th>Description</th><th>Vulnerable Code</th></tr></thead><tbody>\n")
		for _, f := range result.SecurityFindings {
			sb.WriteString("<tr>")
			sb.WriteString("<td>" + escapeHTML(f.Rule) + "</td>")
			sb.WriteString("<td>" + escapeHTML(f.FilePath) + "</td>")
			sb.WriteString("<td>" + fmt.Sprintf("%d", f.LineNumber) + "</td>")
			sb.WriteString("<td><span class=\"badge badge-" + f.Severity + "\">" + strings.Title(f.Severity) + "</span></td>")
			sb.WriteString("<td>" + escapeHTML(f.Description) + "</td>")
			sb.WriteString("<td><code style=\"color:#9ecb6c;font-family:ui-monospace,monospace;display:block;white-space:pre-wrap;word-break:break-all;\">" + escapeHTML(f.CodeSnippet) + "</code></td>")
			sb.WriteString("</tr>\n")
		}
		sb.WriteString("</tbody></table>\n")
	}

	if len(result.QualityFindings) > 0 {
		sb.WriteString("<h2>Code Quality</h2>\n")
		sb.WriteString("<table><thead><tr><th>Category</th><th>File</th><th>Line</th><th>Severity</th><th>Description</th></tr></thead><tbody>\n")
		for _, f := range result.QualityFindings {
			sb.WriteString("<tr>")
			sb.WriteString("<td>" + escapeHTML(f.Category) + "</td>")
			sb.WriteString("<td>" + escapeHTML(f.FilePath) + "</td>")
			sb.WriteString("<td>" + fmt.Sprintf("%d", f.LineNumber) + "</td>")
			sb.WriteString("<td><span class=\"badge badge-" + f.Severity + "\">" + strings.Title(f.Severity) + "</span></td>")
			sb.WriteString("<td>" + escapeHTML(f.Description) + "</td>")
			sb.WriteString("</tr>\n")
		}
		sb.WriteString("</tbody></table>\n")

		sb.WriteString("<h3>Quality Metrics</h3>\n")
		sb.WriteString("<div class=\"metric\"><span>Duplicated Code</span><span>" + fmt.Sprintf("%d", result.QualityMetrics.DuplicatedCode) + "</span></div>\n")
		sb.WriteString("<div class=\"metric\"><span>Unused Imports</span><span>" + fmt.Sprintf("%d", result.QualityMetrics.UnusedImports) + "</span></div>\n")
		sb.WriteString("<div class=\"metric\"><span>Unused Variables</span><span>" + fmt.Sprintf("%d", result.QualityMetrics.UnusedVars) + "</span></div>\n")
		sb.WriteString("<div class=\"metric\"><span>Dead Code</span><span>" + fmt.Sprintf("%d", result.QualityMetrics.DeadCode) + "</span></div>\n")
		sb.WriteString("<div class=\"metric\"><span>Long Functions</span><span>" + fmt.Sprintf("%d", result.QualityMetrics.LongFunctions) + "</span></div>\n")
		sb.WriteString("<div class=\"metric\"><span>Large Files</span><span>" + fmt.Sprintf("%d", result.QualityMetrics.LargeFiles) + "</span></div>\n")
		sb.WriteString("<div class=\"metric\"><span>Complex Functions</span><span>" + fmt.Sprintf("%d", result.QualityMetrics.ComplexFunctions) + "</span></div>\n")
		sb.WriteString("<div class=\"metric\"><span>Style Issues</span><span>" + fmt.Sprintf("%d", result.QualityMetrics.StyleIssues) + "</span></div>\n")
	}

	if len(result.DependencyVulns) > 0 {
		sb.WriteString("<h2>Dependency Vulnerabilities</h2>\n")
		sb.WriteString("<table><thead><tr><th>Package</th><th>Installed</th><th>Patched</th><th>Severity</th><th>Reference</th></tr></thead><tbody>\n")
		for _, v := range result.DependencyVulns {
			sb.WriteString("<tr>")
			sb.WriteString("<td>" + escapeHTML(v.PackageName) + "</td>")
			sb.WriteString("<td>" + escapeHTML(v.InstalledVersion) + "</td>")
			sb.WriteString("<td>" + escapeHTML(v.PatchedVersion) + "</td>")
			sb.WriteString("<td><span class=\"badge badge-" + v.Severity + "\">" + strings.Title(v.Severity) + "</span></td>")
			sb.WriteString("<td>" + escapeHTML(v.ReferenceURL) + "</td>")
			sb.WriteString("</tr>\n")
		}
		sb.WriteString("</tbody></table>\n")
	}

	if len(result.ToolStatuses) > 0 {
		sb.WriteString("<h2>Scanner Status</h2>\n")
		sb.WriteString("<table><thead><tr><th>Tool</th><th>Status</th><th>Findings</th><th>Duration</th><th>Error</th></tr></thead><tbody>\n")
		for _, st := range result.ToolStatuses {
			sb.WriteString("<tr>")
			sb.WriteString("<td>" + escapeHTML(st.Tool) + "</td>")
			sb.WriteString("<td><span class=\"badge badge-" + st.Status + "\">" + strings.Title(st.Status) + "</span></td>")
			sb.WriteString("<td>" + fmt.Sprintf("%d", st.Findings) + "</td>")
			sb.WriteString("<td>" + fmt.Sprintf("%.1fs", st.DurationSeconds) + "</td>")
			sb.WriteString("<td>" + escapeHTML(st.Error) + "</td>")
			sb.WriteString("</tr>\n")
		}
		sb.WriteString("</tbody></table>\n")
	}

	sb.WriteString("<h2>Project Information</h2>\n")
	sb.WriteString("<div class=\"metric\"><span>Total Files</span><span>" + fmt.Sprintf("%d", result.ProjectInfo.TotalFiles) + "</span></div>\n")
	sb.WriteString("<div class=\"metric\"><span>Total Lines</span><span>" + fmt.Sprintf("%d", result.ProjectInfo.TotalLines) + "</span></div>\n")
	sb.WriteString("<div class=\"metric\"><span>Languages</span><span>" + strings.Join(result.LanguagesDetected, ", ") + "</span></div>\n")
	sb.WriteString("<div class=\"metric\"><span>Frameworks</span><span>" + strings.Join(result.FrameworksDetected, ", ") + "</span></div>\n")
	sb.WriteString("<div class=\"metric\"><span>Config Files</span><span>" + fmt.Sprintf("%d", len(result.ProjectInfo.ConfigFiles)) + "</span></div>\n")

	sb.WriteString("<div style=\"text-align: center; margin-top: 60px; padding: 30px; border-top: 1px solid #1a1a1a; color: #666;\">\n")
	sb.WriteString("<p>Generated by KernelSpy - Code Analysis Platform</p>\n")
	sb.WriteString("<p>Developed by The L house</p>\n")
	sb.WriteString("</div>\n")

	sb.WriteString("</body>\n</html>")
	return sb.String()
}

func (r *Reporter) GeneratePDFHTML(result *models.AnalysisResult, lang string) string {
	return r.GenerateHTML(result, lang)
}

func (r *Reporter) SaveReport(reportDir, format string, content []byte) (string, error) {
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return "", err
	}

	filename := fmt.Sprintf("report_%s.%s", time.Now().Format("20060102_150405"), format)
	filePath := reportDir + "/" + filename

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return "", err
	}

	return filePath, nil
}

// degradedScanners returns the names of scanners that did not complete
// successfully (missing, timed out, crashed) so the report can warn that the
// result may be incomplete. Intentionally-disabled scanners are excluded.
func degradedScanners(statuses []models.ToolStatus) []string {
	var degraded []string
	for _, st := range statuses {
		if st.Status == "success" || st.Status == "skipped" {
			continue
		}
		degraded = append(degraded, st.Tool+" ("+st.Status+")")
	}
	return degraded
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
