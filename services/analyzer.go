package services

import (
	"black-hat/models"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Analyzer orchestrates the concurrent Static Application Security Testing
// (SAST) pipeline. It detects the project languages, then runs every
// applicable industry-standard CLI tool in parallel goroutines and aggregates
// their JSON outputs into the single unified report schema the frontend
// expects. No AI is used anywhere — findings come strictly from the tools.
//
// Fail-safe: every scanner reports a ToolStatus through the shared collector,
// so a scanner that cannot run (not installed, timed out, crashed) is surfaced
// in the report as missing/timeout/error instead of silently producing a
// "clean" result. The summary explicitly warns when the scan was incomplete.
type Analyzer struct {
	detector *Detector
	semgrep  *SemgrepRunner
	gosec    *GosecRunner
	njsscan  *NjsScanRunner
	bandit   *BanditRunner
	eslint   *ESLintRunner
	trivy    *TrivyRunner
	gitleaks *GitleaksRunner
	golangci *GolangCIRunner
	clippy   *ClippyRunner
	pmd      *PMDRunner
	phpstan  *PHPStanRunner
	codeql   *CodeQLRunner
	depcheck *DependencyCheckRunner
	builtin  *BuiltinRunner
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		detector: NewDetector(),
		semgrep:  NewSemgrepRunner(),
		gosec:    NewGosecRunner(),
		njsscan:  NewNjsScanRunner(),
		bandit:   NewBanditRunner(),
		eslint:   NewESLintRunner(),
		trivy:    NewTrivyRunner(),
		gitleaks: NewGitleaksRunner(),
		golangci: NewGolangCIRunner(),
		clippy:   NewClippyRunner(),
		pmd:      NewPMDRunner(),
		phpstan:  NewPHPStanRunner(),
		codeql:   NewCodeQLRunner(),
		depcheck: NewDependencyCheckRunner(),
		builtin:  NewBuiltinRunner(),
	}
}

// AnalyzeProject scans the extracted project directory and returns a full
// analysis result. Every scanner runs concurrently; results are aggregated
// with a mutex and the pipeline always completes within the configured tool
// timeouts. The per-tool outcomes are collected so failed or missing scanners
// are visible in the report instead of masquerading as a clean scan.
func (a *Analyzer) AnalyzeProject(projectPath string) (*models.AnalysisResult, error) {
	languages := a.detector.DetectLanguages(projectPath)
	frameworks := a.detector.DetectFrameworks(projectPath)
	configFiles := a.detector.DetectConfigFiles(projectPath)

	fileCount, lineCount := countFilesAndLines(projectPath)
	largestFiles := findLargestFiles(projectPath, 10)

	projectInfo := models.ProjectInfo{
		Structure:    getProjectStructure(projectPath),
		Languages:    countByLanguage(projectPath),
		Frameworks:   frameworks,
		ConfigFiles:  configFiles,
		TotalFiles:   fileCount,
		TotalLines:   lineCount,
		LargestFiles: largestFiles,
	}

	statuses := &ToolStatusCollector{}

	var mu sync.Mutex
	securityFindings := []models.SecurityFinding{}
	qualityFindings := []models.QualityFinding{}
	depVulns := []models.DependencyVulnerability{}
	qualityMetrics := models.QualityMetrics{}

	// addSecurity appends findings under the mutex.
	addSecurity := func(findings []models.SecurityFinding) {
		mu.Lock()
		securityFindings = append(securityFindings, findings...)
		mu.Unlock()
	}
	addQuality := func(findings []models.QualityFinding, metrics models.QualityMetrics) {
		mu.Lock()
		qualityFindings = append(qualityFindings, findings...)
		qualityMetrics.DuplicatedCode += metrics.DuplicatedCode
		qualityMetrics.UnusedImports += metrics.UnusedImports
		qualityMetrics.UnusedVars += metrics.UnusedVars
		qualityMetrics.DeadCode += metrics.DeadCode
		qualityMetrics.LongFunctions += metrics.LongFunctions
		qualityMetrics.LargeFiles += metrics.LargeFiles
		qualityMetrics.ComplexFunctions += metrics.ComplexFunctions
		qualityMetrics.StyleIssues += metrics.StyleIssues
		mu.Unlock()
	}
	addDeps := func(vulns []models.DependencyVulnerability) {
		mu.Lock()
		depVulns = append(depVulns, vulns...)
		mu.Unlock()
	}

	var wg sync.WaitGroup

	// ---- Built-in pattern analyzer (always runs, needs no external tools) ----
	// This is the guarantee that every scan — including serverless sandboxes
	// like Vercel where no SAST binaries are installed — produces real
	// findings. It runs first and independently of the external toolchain.
	wg.Add(1)
	go func() {
		defer wg.Done()
		addSecurity(a.builtin.Run(projectPath, statuses))
	}()

	// ---- Language-agnostic scanners (run for every project) ----
	wg.Add(1)
	go func() {
		defer wg.Done()
		addSecurity(a.semgrep.Run(projectPath, statuses))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		addSecurity(a.gitleaks.Run(projectPath, statuses))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		addDeps(a.trivy.Run(projectPath, statuses))
	}()

	// Enterprise SCA: OWASP Dependency-Check (NVD CVE matching for every
	// package-manager lockfile/manifest the project ships).
	wg.Add(1)
	go func() {
		defer wg.Done()
		addDeps(a.depcheck.Run(projectPath, statuses))
	}()

	// Enterprise data-flow analysis: CodeQL builds a database per detected
	// language and analyzes it with the official query packs.
	wg.Add(1)
	go func() {
		defer wg.Done()
		addSecurity(a.codeql.Run(projectPath, languages, statuses))
	}()

	// ---- Language-specific scanners ----
	for _, lang := range languages {
		switch lang {
		case "go":
			wg.Add(1)
			go func() {
				defer wg.Done()
				addSecurity(a.gosec.Run(projectPath, statuses))
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, metrics := a.golangci.Run(projectPath, statuses)
				addQuality(findings, metrics)
			}()
		case "python":
			wg.Add(1)
			go func() {
				defer wg.Done()
				addSecurity(a.bandit.Run(projectPath, statuses))
			}()
		case "javascript", "typescript":
			wg.Add(1)
			go func() {
				defer wg.Done()
				addSecurity(a.njsscan.Run(projectPath, statuses))
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				sec, qual, metrics := a.eslint.Run(projectPath, statuses)
				addSecurity(sec)
				addQuality(qual, metrics)
			}()
		case "rust":
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, metrics := a.clippy.Run(projectPath, statuses)
				addQuality(findings, metrics)
			}()
		case "java":
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, metrics := a.pmd.Run(projectPath, statuses)
				addQuality(findings, metrics)
			}()
		case "php":
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, metrics := a.phpstan.Run(projectPath, statuses)
				addQuality(findings, metrics)
			}()
			// Kotlin, C#, Ruby, C/C++, Swift and the rest are covered by the
			// language-agnostic Semgrep + CodeQL scanners, so no dedicated runner
			// is needed here.
		}
	}

	wg.Wait()

	toolStatuses := statuses.Snapshot()
	result := &models.AnalysisResult{
		SecurityFindings:   securityFindings,
		QualityFindings:    qualityFindings,
		QualityMetrics:     qualityMetrics,
		DependencyVulns:    depVulns,
		ToolStatuses:       toolStatuses,
		ProjectInfo:        projectInfo,
		FilesScanned:       fileCount,
		DurationSeconds:    0,
		LanguagesDetected:  languages,
		FrameworksDetected: frameworks,
		Summary:            buildSummary(securityFindings, depVulns, toolStatuses, languages, fileCount),
		Suggestions:        buildSuggestions(securityFindings, depVulns),
	}

	return result, nil
}

// buildSummary generates a concise, non-AI summary of the tool findings. When
// no vulnerabilities were found it still states the truth: if any scanner
// could not run, the result is flagged as potentially incomplete instead of
// being reported as a clean scan.
func buildSummary(security []models.SecurityFinding, deps []models.DependencyVulnerability, statuses []models.ToolStatus, languages []string, files int) string {
	succeeded := 0
	var degraded []string
	for _, st := range statuses {
		switch st.Status {
		case statusSuccess:
			succeeded++
		case statusSkipped:
			// Intentionally disabled by configuration — not a failure.
		default:
			degraded = append(degraded, st.Tool+" ("+st.Status+")")
		}
	}

	if len(security) == 0 && len(deps) == 0 {
		if len(degraded) > 0 {
			return "No vulnerabilities were detected by the " + strconv.Itoa(succeeded) + " scanner(s) that completed successfully, but " +
				strconv.Itoa(len(degraded)) + " scanner(s) could not run (" + strings.Join(degraded, ", ") + "). " +
				"This result may be INCOMPLETE — see the Scanner Status section below."
		}
		return "No vulnerabilities were detected by the static analysis tools."
	}

	sevCounts := map[string]int{}
	tools := map[string]bool{}
	for _, f := range security {
		sevCounts[f.Severity]++
		tools[f.Tool] = true
	}
	for _, d := range deps {
		sevCounts[d.Severity]++
		tools[d.Tool] = true
	}

	var parts []string
	order := []string{"critical", "high", "medium", "low"}
	for _, sev := range order {
		if n := sevCounts[sev]; n > 0 {
			parts = append(parts, strings.ToUpper(sev)+": "+strconv.Itoa(n))
		}
	}

	var toolNames []string
	for t := range tools {
		toolNames = append(toolNames, t)
	}

	summary := "Scanned " + strconv.Itoa(files) + " file(s) (" + strings.Join(languages, ", ") + "). " +
		"Found " + strconv.Itoa(len(security)) + " security issue(s) and " + strconv.Itoa(len(deps)) +
		" dependency risk(s) — " + strings.Join(parts, ", ") +
		". Detected by: " + strings.Join(toolNames, ", ") + "."

	if len(degraded) > 0 {
		summary += " Note: " + strconv.Itoa(len(degraded)) + " scanner(s) could not run (" +
			strings.Join(degraded, ", ") + "); results may be INCOMPLETE."
	}
	return summary
}

// buildSuggestions derives actionable, tool-backed remediation suggestions.
func buildSuggestions(security []models.SecurityFinding, deps []models.DependencyVulnerability) []string {
	seen := map[string]bool{}
	var suggestions []string

	for _, f := range security {
		if len(suggestions) >= 8 {
			break
		}
		rec := strings.TrimSpace(f.Recommendation)
		if rec == "" {
			rec = "Review the reported issue in " + f.FilePath
		}
		if !seen[rec] {
			seen[rec] = true
			suggestions = append(suggestions, rec)
		}
	}

	for _, d := range deps {
		if len(suggestions) >= 10 {
			break
		}
		if d.PatchedVersion != "" {
			rec := "Upgrade " + d.PackageName + " from " + d.InstalledVersion + " to " + d.PatchedVersion
			if !seen[rec] {
				seen[rec] = true
				suggestions = append(suggestions, rec)
			}
		}
	}

	return suggestions
}

func countFilesAndLines(root string) (int, int) {
	totalFiles := 0
	totalLines := 0
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") || strings.Contains(path, "vendor") {
			return nil
		}
		totalFiles++
		ext := strings.ToLower(filepath.Ext(path))
		textExtensions := map[string]bool{
			".go": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
			".py": true, ".java": true, ".rs": true, ".php": true, ".rb": true,
			".c": true, ".cpp": true, ".h": true, ".cs": true, ".swift": true,
			".kt": true, ".scala": true, ".lua": true, ".r": true, ".m": true,
			".html": true, ".css": true, ".scss": true, ".json": true, ".yaml": true,
			".yml": true, ".toml": true, ".xml": true, ".sql": true, ".sh": true,
			".md": true, ".txt": true, ".vue": true, ".svelte": true,
		}
		if textExtensions[ext] {
			data, err := os.ReadFile(path)
			if err == nil {
				totalLines += strings.Count(string(data), "\n") + 1
			}
		}
		return nil
	})
	return totalFiles, totalLines
}

func findLargestFiles(root string, limit int) []models.FileEntry {
	type fileEntry struct {
		path  string
		lines int
	}
	var entries []fileEntry

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") || strings.Contains(path, "vendor") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		textExtensions := map[string]bool{
			".go": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
			".py": true, ".java": true, ".rs": true, ".php": true, ".rb": true,
			".c": true, ".cpp": true, ".h": true, ".cs": true,
		}
		if textExtensions[ext] {
			data, err := os.ReadFile(path)
			if err == nil {
				lines := strings.Count(string(data), "\n") + 1
				relPath, _ := filepath.Rel(root, path)
				entries = append(entries, fileEntry{path: relPath, lines: lines})
			}
		}
		return nil
	})

	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].lines > entries[i].lines {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	if len(entries) > limit {
		entries = entries[:limit]
	}

	var result []models.FileEntry
	for _, e := range entries {
		result = append(result, models.FileEntry{Path: e.path, Lines: e.lines})
	}
	return result
}

func getProjectStructure(root string) string {
	var sb strings.Builder
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") || strings.Contains(path, "vendor") {
			return filepath.SkipDir
		}
		relPath, _ := filepath.Rel(root, path)
		if relPath == "." {
			return nil
		}
		depth := strings.Count(relPath, string(os.PathSeparator))
		if depth > 3 {
			return nil
		}
		prefix := strings.Repeat("  ", depth)
		if info.IsDir() {
			sb.WriteString(prefix + "📁 " + info.Name() + "/\n")
		} else {
			sb.WriteString(prefix + "📄 " + info.Name() + "\n")
		}
		return nil
	})
	return sb.String()
}

func countByLanguage(root string) map[string]int {
	counts := make(map[string]int)
	extensions := map[string]string{
		".go": "go", ".js": "javascript", ".ts": "typescript", ".jsx": "javascript", ".tsx": "typescript",
		".py": "python", ".java": "java", ".rs": "rust", ".php": "php", ".rb": "ruby",
		".c": "c", ".cpp": "cpp", ".h": "c", ".cs": "csharp",
	}
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") || strings.Contains(path, "vendor") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if lang, ok := extensions[ext]; ok {
			counts[lang]++
		}
		return nil
	})
	return counts
}
