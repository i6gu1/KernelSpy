package services

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"black-hat/models"
)

// CodeQLRunner runs GitHub's CodeQL CLI for deep data-flow / taint-tracking
// analysis. It is the heaviest scanner in the pipeline: for every detected
// language it builds a CodeQL database (extracting the code into CodeQL's
// relational schema) and then analyzes that database with the official
// <lang>-queries pack, producing a SARIF report that is parsed into findings.
//
// CodeQL only runs where it is installed (the Docker image via build.sh; the
// full bundle ships the query packs). On serverless runtimes without the
// binary it records a "missing" status so the report explains why no CodeQL
// findings exist. Set CODQL_LANGUAGES to restrict the languages (e.g.
// "javascript,go") and SAST_CODQL_ENABLED=0 to disable it entirely.
type CodeQLRunner struct{}

func NewCodeQLRunner() *CodeQLRunner {
	return &CodeQLRunner{}
}

// codeqlLanguages maps the project's detected language names onto the
// extractor names CodeQL's CLI understands. Kotlin is analyzed with the Java
// extractor/query pack; C files with the C++ extractor.
var codeqlLanguages = map[string]string{
	"go":         "go",
	"python":     "python",
	"javascript": "javascript",
	"typescript": "javascript",
	"ruby":       "ruby",
	"java":       "java",
	"kotlin":     "java",
	"csharp":     "csharp",
	"cpp":        "cpp",
	"c":          "cpp",
	"swift":      "swift",
}

// Run builds a database and analyzes it for every detected language that
// CodeQL supports, then merges all SARIF results into security findings.
func (c *CodeQLRunner) Run(projectPath string, languages []string, status *ToolStatusCollector) []models.SecurityFinding {
	if os.Getenv("SAST_CODQL_ENABLED") == "0" {
		log.Printf("[codeql] disabled via SAST_CODQL_ENABLED=0")
		return nil
	}

	// Optional env override: CODQL_LANGUAGES=javascript,go
	langs := languages
	if override := os.Getenv("CODQL_LANGUAGES"); override != "" {
		langs = strings.Split(override, ",")
	}

	seen := map[string]bool{}
	var findings []models.SecurityFinding
	for _, lang := range langs {
		ql, ok := codeqlLanguages[lang]
		if !ok || seen[ql] {
			continue
		}
		seen[ql] = true

		outcome := &ToolOutcome{Tool: "codeql(" + ql + ")"}
		found := c.analyzeLanguage(projectPath, ql, outcome)
		outcome.Findings = len(found)
		status.Record(outcome)
		findings = append(findings, found...)
	}

	return findings
}

// analyzeLanguage runs database create + analyze for one CodeQL language and
// fills `outcome` with the result (success/missing/timeout/error).
func (c *CodeQLRunner) analyzeLanguage(projectPath, ql string, outcome *ToolOutcome) []models.SecurityFinding {
	if findTool("codeql") == "" {
		outcome.Status = statusMissing
		outcome.Error = "codeql is not available in this deployment (serverless containers skip the 1.5 GB bundle; the full Docker image installs it via build.sh)"
		return nil
	}

	// Parent dir for the database; `codeql database create` must create the
	// final db dir itself, so create an empty parent and let it do the rest.
	parent, err := os.MkdirTemp("", "blackhat-codeql-")
	if err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to create codeql workspace: " + err.Error()
		return nil
	}
	defer os.RemoveAll(parent)

	dbDir := filepath.Join(parent, "db")
	sarifPath := filepath.Join(parent, "out.sarif")

	// 1) Create the database. Prefer --build-mode=none (no compile step:
	// supported for js/ts, python, go, ruby, java and swift); on a non-zero
	// exit (unsupported mode, missing compilers) fall back to the autobuilder.
	// database create failures always print to stderr, so judge by exit code.
	createArgs := []string{"database", "create", dbDir,
		"--language=" + ql,
		"--source-root=" + projectPath,
		"--build-mode=none",
	}
	firstOut, firstErr := runToolEnv("", nil, codeqlTimeout, "codeql", createArgs...)
	createOut, createErr := firstOut, firstErr
	if firstErr.ExitCode != 0 {
		// --build-mode=none not supported for this language (or no extractor
		// deps): retry with the autobuilder.
		createOut, createErr = runToolEnv("", nil, codeqlTimeout, "codeql",
			"database", "create", dbDir,
			"--language="+ql,
			"--source-root="+projectPath,
		)
	}
	if createErr.ExitCode != 0 || createErr.Status != statusSuccess {
		*outcome = *createErr
		outcome.Tool = "codeql(" + ql + ")"
		// Keep both attempts' stderr: the first (--build-mode=none) error is
		// usually the more diagnostic one.
		if firstErr.ExitCode != 0 {
			outcome.Error = "database create failed — --build-mode=none: " + toolErrText(firstOut, firstErr) +
				"; autobuild: " + toolErrText(createOut, createErr)
		} else {
			outcome.Error = toolErrText(createOut, createErr)
		}
		return nil
	}

	// 2) Analyze with the official per-language queries (ships in the full
	// codeql bundle).
	analyzeOut, analyzeErrOut := runToolEnv("", nil, codeqlTimeout, "codeql",
		"database", "analyze", dbDir,
		"codeql/"+ql+"-queries",
		"--format=sarif-latest",
		"--output="+sarifPath,
		"--threads=2",
		"--no-sarif-add-snippets",
	)
	if analyzeErrOut.ExitCode != 0 || analyzeErrOut.Status != statusSuccess {
		*outcome = *analyzeErrOut
		outcome.Tool = "codeql(" + ql + ")"
		if len(analyzeOut) > 0 {
			outcome.Error = truncate(string(analyzeOut), 300)
		}
		return nil
	}

	data, readErr := readFileContent(sarifPath)
	if readErr != nil || len(data) == 0 {
		outcome.Status = statusError
		outcome.Error = "codeql analyze produced no SARIF output"
		return nil
	}

	return parseSARIF(projectPath, ql, data, outcome)
}

// sarifLog mirrors the fields of the SARIF 2.1.0 format that CodeQL emits.
type sarifLog struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID               string `json:"id"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					FullDescription struct {
						Text string `json:"text"`
					} `json:"fullDescription"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// parseSARIF converts a CodeQL SARIF report into security findings and
// records the outcome (success with N findings, or error when unparseable).
func parseSARIF(projectPath, ql string, data []byte, outcome *ToolOutcome) []models.SecurityFinding {
	var sarif sarifLog
	if err := json.Unmarshal(data, &sarif); err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse codeql SARIF output: " + truncate(string(data), 300)
		log.Printf("[codeql] %s", outcome.Error)
		return nil
	}

	outcome.Status = statusSuccess

	// Build a ruleId -> description index from the rules metadata.
	descriptions := map[string]string{}
	for _, run := range sarif.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			desc := rule.ShortDescription.Text
			if desc == "" {
				desc = rule.FullDescription.Text
			}
			if desc != "" {
				descriptions[rule.ID] = desc
			}
		}
	}

	var findings []models.SecurityFinding
	for _, run := range sarif.Runs {
		for _, res := range run.Results {
			if res.RuleID == "" {
				continue
			}
			file := ""
			line := 0
			if len(res.Locations) > 0 {
				loc := res.Locations[0].PhysicalLocation
				file = sarifURItoPath(loc.ArtifactLocation.URI)
				line = loc.Region.StartLine
			}
			description := descriptions[res.RuleID]
			if description == "" {
				description = res.Message.Text
			}
			if description == "" {
				description = "Security issue detected by CodeQL (" + res.RuleID + ")"
			}

			severity := "low"
			switch res.Level {
			case "error":
				severity = "high"
			case "warning":
				severity = "medium"
			}

			findings = append(findings, models.SecurityFinding{
				Rule:           res.RuleID,
				FilePath:       relPath(projectPath, file),
				LineNumber:     line,
				Severity:       severity,
				Description:    description,
				Recommendation: "Trace the data-flow path reported by CodeQL and apply the fix suggested by rule " + res.RuleID + ".",
				Tool:           "codeql",
			})
		}
	}

	return findings
}

// toolErrText returns the most useful error text from a failed run: the
// captured output when present, otherwise the classified error message.
func toolErrText(out []byte, err *ToolOutcome) string {
	if len(out) > 0 {
		return truncate(string(out), 200)
	}
	return err.Error
}

// sarifURItoPath converts a SARIF artifact URI ("file:///tmp/proj/src/app.py"
// or "src/app.py" or percent-encoded forms) into a plain filesystem path.
func sarifURItoPath(uri string) string {
	if uri == "" {
		return uri
	}
	if unescaped, err := url.PathUnescape(uri); err == nil {
		uri = unescaped
	}
	uri = strings.TrimPrefix(uri, "file://")
	uri = strings.TrimPrefix(uri, "file:")
	if runtime.GOOS == "windows" {
		uri = strings.TrimPrefix(uri, "/")
	}
	return uri
}
