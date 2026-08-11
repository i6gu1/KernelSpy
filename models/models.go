package models

import "time"

type Project struct {
	ID         int       `json:"id"`
	UserID     *int      `json:"user_id"`
	Name       string    `json:"name"`
	SourceType string    `json:"source_type"`
	SourceURL  string    `json:"source_url"`
	FilePath   string    `json:"file_path"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Analysis struct {
	ID                 int        `json:"id"`
	ProjectID          int        `json:"project_id"`
	Status             string     `json:"status"`
	StartedAt          time.Time  `json:"started_at"`
	CompletedAt        *time.Time `json:"completed_at"`
	DurationSeconds    int        `json:"duration_seconds"`
	FilesScanned       int        `json:"files_scanned"`
	LanguagesDetected  []string   `json:"languages_detected"`
	FrameworksDetected []string   `json:"frameworks_detected"`
}

type SecurityFinding struct {
	ID             int    `json:"id"`
	AnalysisID     int    `json:"analysis_id"`
	Rule           string `json:"rule"`
	FilePath       string `json:"file_path"`
	LineNumber     int    `json:"line_number"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Tool           string `json:"tool"`
}

type QualityFinding struct {
	ID          int    `json:"id"`
	AnalysisID  int    `json:"analysis_id"`
	Category    string `json:"category"`
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Tool        string `json:"tool"`
}

type DependencyVulnerability struct {
	ID               int    `json:"id"`
	AnalysisID       int    `json:"analysis_id"`
	PackageName      string `json:"package_name"`
	InstalledVersion string `json:"installed_version"`
	PatchedVersion   string `json:"patched_version"`
	Severity         string `json:"severity"`
	ReferenceURL     string `json:"reference_url"`
	Tool             string `json:"tool"`
}

type Report struct {
	ID         int       `json:"id"`
	AnalysisID int       `json:"analysis_id"`
	Format     string    `json:"format"`
	FilePath   string    `json:"file_path"`
	CreatedAt  time.Time `json:"created_at"`
}

type QualityMetrics struct {
	DuplicatedCode   int `json:"duplicated_code"`
	UnusedImports    int `json:"unused_imports"`
	UnusedVars       int `json:"unused_vars"`
	DeadCode         int `json:"dead_code"`
	LongFunctions    int `json:"long_functions"`
	LargeFiles       int `json:"large_files"`
	ComplexFunctions int `json:"complex_functions"`
	StyleIssues      int `json:"style_issues"`
}

type ProjectInfo struct {
	Structure    string         `json:"structure"`
	Languages    map[string]int `json:"languages"`
	Frameworks   []string       `json:"frameworks"`
	ConfigFiles  []string       `json:"config_files"`
	TotalFiles   int            `json:"total_files"`
	TotalLines   int            `json:"total_lines"`
	LargestFiles []FileEntry    `json:"largest_files"`
}

type FileEntry struct {
	Path  string `json:"path"`
	Lines int    `json:"lines"`
}

// ToolStatus records the outcome of a single scanner invocation. This is the
// fail-safe: a scanner that could not run (not installed, timed out, crashed)
// is surfaced in the report instead of silently producing "no findings", which
// would be a false negative.
type ToolStatus struct {
	Tool            string  `json:"tool"`
	Status          string  `json:"status"` // success | missing | timeout | error
	Error           string  `json:"error,omitempty"`
	DurationSeconds float64 `json:"duration_seconds"`
	Findings        int     `json:"findings"`
}

type AnalysisResult struct {
	SecurityFindings   []SecurityFinding         `json:"security_findings"`
	QualityFindings    []QualityFinding          `json:"quality_findings"`
	QualityMetrics     QualityMetrics            `json:"quality_metrics"`
	DependencyVulns    []DependencyVulnerability `json:"dependency_vulns"`
	ToolStatuses       []ToolStatus              `json:"tool_statuses"`
	ProjectInfo        ProjectInfo               `json:"project_info"`
	FilesScanned       int                       `json:"files_scanned"`
	DurationSeconds    int                       `json:"duration_seconds"`
	LanguagesDetected  []string                  `json:"languages_detected"`
	FrameworksDetected []string                  `json:"frameworks_detected"`
	Summary            string                    `json:"summary"`
	Suggestions        []string                  `json:"suggestions"`
	Error              string                    `json:"error"`
}
