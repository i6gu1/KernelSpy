package services

import (
	"black-hat/models"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Analyzer struct {
	detector  *Detector
	extractor *Extractor
	semgrep   *SemgrepRunner
	trivy     *TrivyRunner
	gitleaks  *GitleaksRunner
	eslint    *ESLintRunner
	golangci  *GolangCIRunner
	bandit    *BanditRunner
	clippy    *ClippyRunner
	pmd       *PMDRunner
	phpstan   *PHPStanRunner
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		detector:  NewDetector(),
		extractor: NewExtractor(),
		semgrep:   NewSemgrepRunner(),
		trivy:     NewTrivyRunner(),
		gitleaks:  NewGitleaksRunner(),
		eslint:    NewESLintRunner(),
		golangci:  NewGolangCIRunner(),
		bandit:    NewBanditRunner(),
		clippy:    NewClippyRunner(),
		pmd:       NewPMDRunner(),
		phpstan:   NewPHPStanRunner(),
	}
}

// AnalyzeProject returns a full analysis result. When an AI API key is
// configured, the AI model reads the project files and produces the findings
// (this is the primary path used in production on Vercel). Otherwise the
// classic static-analysis tool runners are used as a fallback for local dev.
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

	// ----- Primary path: AI analysis -----
	ai := NewAIAnalyzer()
	if ai.Enabled() {
		start := time.Now()
		aiResult, err := ai.Analyze(projectPath, projectInfo)
		duration := int(time.Since(start).Seconds())
		if err != nil {
			return nil, fmt.Errorf("AI analysis failed: %v", err)
		}
		return &models.AnalysisResult{
			SecurityFindings:   aiResult.SecurityFindings,
			QualityFindings:    aiResult.QualityFindings,
			QualityMetrics:     models.QualityMetrics{},
			DependencyVulns:    aiResult.DependencyVulns,
			ProjectInfo:        projectInfo,
			FilesScanned:       fileCount,
			DurationSeconds:    duration,
			LanguagesDetected:  languages,
			FrameworksDetected: frameworks,
			Summary:            aiResult.Summary,
			Suggestions:        aiResult.Suggestions,
		}, nil
	}

	// ----- Fallback path: classic static-analysis tools -----
	var mu sync.Mutex
	securityFindings := []models.SecurityFinding{}
	qualityFindings := []models.QualityFinding{}
	depVulns := []models.DependencyVulnerability{}
	qualityMetrics := models.QualityMetrics{}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		results := a.semgrep.Run(projectPath)
		mu.Lock()
		securityFindings = append(securityFindings, results...)
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		results := a.trivy.Run(projectPath)
		mu.Lock()
		depVulns = append(depVulns, results...)
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		results := a.gitleaks.Run(projectPath)
		mu.Lock()
		securityFindings = append(securityFindings, results...)
		mu.Unlock()
	}()

	for _, lang := range languages {
		switch lang {
		case "javascript", "typescript":
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, metrics := a.eslint.Run(projectPath)
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
			}()
		case "go":
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, metrics := a.golangci.Run(projectPath)
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
			}()
		case "python":
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, metrics := a.bandit.Run(projectPath)
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
			}()
		case "rust":
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, metrics := a.clippy.Run(projectPath)
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
			}()
		case "java":
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, metrics := a.pmd.Run(projectPath)
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
			}()
		case "php":
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, metrics := a.phpstan.Run(projectPath)
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
			}()
		}
	}

	wg.Wait()

	result := &models.AnalysisResult{
		SecurityFindings:   securityFindings,
		QualityFindings:    qualityFindings,
		QualityMetrics:     qualityMetrics,
		DependencyVulns:    depVulns,
		ProjectInfo:        projectInfo,
		FilesScanned:       fileCount,
		DurationSeconds:    0,
		LanguagesDetected:  languages,
		FrameworksDetected: frameworks,
	}

	return result, nil
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
