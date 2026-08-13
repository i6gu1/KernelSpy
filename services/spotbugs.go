package services

import (
	"context"
	"encoding/xml"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"black-hat/models"
)

// SpotBugsRunner scans Java projects with SpotBugs + the FindSecBugs plugin
// (com.h3xstream.findsecbugs). It is the dedicated Java security scanner,
// complementing the PMD quality pass: XSS, SQL/command injection, path
// traversal, hardcoded credentials, weak crypto, SSRF, XXE, insecure
// deserialization and hundreds of other FindSecBugs detectors.
//
// SpotBugs analyzes BYTECODE, not source, so the runner first compiles the
// sources with javac (when a JDK is present) into a throwaway classes dir and
// scans those. Failures are recorded honestly — never reported as a clean
// scan:
//   - no spotbugs binary / no FindSecBugs jar / no JDK  -> statusMissing
//   - javac fails (missing dependencies, JDK mismatch)  -> statusError with
//     the compiler output
//   - spotbugs crashes or times out                      -> its own outcome
//
// build.sh installs SpotBugs + the FindSecBugs jar into SAST_TOOLS_DIR (see
// the FINDSECBUGS_JAR env var). The heavy tool is deliberately NOT part of the
// Docker execution matrix — it is installed natively by build.sh on Docker
// hosts and has no small official container image.
type SpotBugsRunner struct{}

func NewSpotBugsRunner() *SpotBugsRunner {
	return &SpotBugsRunner{}
}

// Run compiles the project's Java sources and scans the bytecode with
// SpotBugs + FindSecBugs, mapping the XML report onto security findings.
func (s *SpotBugsRunner) Run(projectPath string, status *ToolStatusCollector) []models.SecurityFinding {
	outcome := &ToolOutcome{Tool: "spotbugs"}
	defer func() { status.Record(outcome) }()

	if findTool("spotbugs") == "" {
		outcome.Status = statusMissing
		outcome.Error = "spotbugs is not available in this deployment (install via build.sh or SAST_TOOLS_DIR)"
		return nil
	}
	pluginJar := findSecBugsJar()
	if pluginJar == "" {
		outcome.Status = statusMissing
		outcome.Error = "findsecbugs plugin jar not found (set FINDSECBUGS_JAR or place findsecbugs-plugin.jar in SAST_TOOLS_DIR)"
		return nil
	}
	javac, err := exec.LookPath("javac")
	if err != nil {
		outcome.Status = statusMissing
		outcome.Error = "no JDK (javac) available — SpotBugs needs compiled bytecode; install a JDK (e.g. openjdk-17-jdk-headless)"
		return nil
	}

	sources := javaSources(projectPath)
	if len(sources) == 0 {
		outcome.Status = statusSkipped
		outcome.Error = "no .java sources found to compile for SpotBugs"
		return nil
	}

	work, err := os.MkdirTemp("", "blackhat-spotbugs-")
	if err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to create spotbugs workspace: " + err.Error()
		return nil
	}
	defer os.RemoveAll(work)

	classesDir := filepath.Join(work, "classes")
	if err := compileJava(javac, classesDir, sources); err != nil {
		outcome.Status = statusError
		outcome.Error = "javac failed to compile the project (missing dependencies or JDK mismatch?): " + truncate(err.Error(), 300)
		log.Printf("[spotbugs] %s", outcome.Error)
		return nil
	}

	reportPath := filepath.Join(work, "spotbugs.xml")
	out, sbOutcome := runToolInDir(projectPath, "spotbugs",
		"-xml:withMessages",
		"-output", reportPath,
		"-projectName", "black-hat",
		"-pluginList", pluginJar,
		"-sourcepath", projectPath,
		"-medium",
		classesDir,
	)
	if sbOutcome.Status != statusSuccess {
		*outcome = *sbOutcome
		outcome.Tool = "spotbugs"
		if len(out) > 0 {
			outcome.Error = truncate(string(out), 300)
		}
		return nil
	}

	data, readErr := readFileContent(reportPath)
	if readErr != nil {
		outcome.Status = statusError
		outcome.Error = "spotbugs finished but produced no report: " + readErr.Error()
		log.Printf("[spotbugs] %s", outcome.Error)
		return nil
	}

	findings, err := parseSpotbugsReport(projectPath, data)
	if err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse spotbugs report: " + truncate(err.Error(), 300)
		log.Printf("[spotbugs] %s", outcome.Error)
		return nil
	}

	outcome.Status = statusSuccess
	outcome.Findings = len(findings)
	return findings
}

// javaSources walks the project and returns every .java file (cross-platform,
// no shell involved).
func javaSources(root string) []string {
	var sources []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".java") {
			sources = append(sources, path)
		}
		return nil
	})
	return sources
}

// compileJava compiles the given sources into classesDir. A javac argfile
// (@file) keeps the command line short for large projects. The returned error
// carries the truncated compiler output so failures are diagnosable.
func compileJava(javac, classesDir string, sources []string) error {
	if err := os.MkdirAll(classesDir, 0o755); err != nil {
		return err
	}
	listFile := filepath.Join(filepath.Dir(classesDir), "sources.txt")
	if err := os.WriteFile(listFile, []byte(strings.Join(sources, "\n")), 0o644); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, javac, "-d", classesDir, "-nowarn", "-encoding", "UTF-8", "@"+listFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(truncate(string(out), 300))
	}
	return nil
}

// findSecBugsJar locates the FindSecBugs plugin jar: the FINDSECBUGS_JAR env
// var wins, then the SAST_TOOLS_DIR / /opt/bin / /usr/local/bin conventions
// where build.sh places it.
func findSecBugsJar() string {
	if p := os.Getenv("FINDSECBUGS_JAR"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	for _, dir := range []string{os.Getenv("SAST_TOOLS_DIR"), "/opt/bin", "/usr/local/bin"} {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, "findsecbugs-plugin.jar")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// spotbugsReport mirrors the relevant parts of the SpotBugs XML report
// (-xml:withMessages). FindSecBugs annotates BugInstance with a cweid
// attribute that becomes the CWE reference.
type spotbugsReport struct {
	XMLName     xml.Name      `xml:"BugCollection"`
	BugInstance []spotbugsBug `xml:"BugInstance"`
}

type spotbugsBug struct {
	Type         string       `xml:"type,attr"`
	Priority     int          `xml:"priority,attr"`
	CWEID        string       `xml:"cweid,attr"`
	ShortMessage string       `xml:"ShortMessage"`
	LongMessage  string       `xml:"LongMessage"`
	SourceLine   spotbugsLine `xml:"SourceLine"`
	Class        spotbugsCls  `xml:"Class"`
}

type spotbugsLine struct {
	SourcePath string `xml:"sourcepath,attr"`
	Start      int    `xml:"start,attr"`
	StartLine  int    `xml:"startline,attr"`
}

type spotbugsCls struct {
	SourcePath string `xml:"sourcepath,attr"`
}

// parseSpotbugsReport converts a SpotBugs XML report into unified security
// findings. Severity mapping follows SpotBugs priorities: 1=high, 2=medium,
// 3=low.
func parseSpotbugsReport(projectPath string, data []byte) ([]models.SecurityFinding, error) {
	var rep spotbugsReport
	if err := xml.Unmarshal(data, &rep); err != nil {
		return nil, err
	}

	findings := make([]models.SecurityFinding, 0, len(rep.BugInstance))
	for _, b := range rep.BugInstance {
		rule := strings.TrimSpace(b.Type)
		if rule == "" {
			continue
		}
		file := b.SourceLine.SourcePath
		if file == "" {
			file = b.Class.SourcePath
		}
		line := b.SourceLine.Start
		if line == 0 {
			line = b.SourceLine.StartLine
		}

		description := strings.TrimSpace(b.LongMessage)
		if description == "" {
			description = strings.TrimSpace(b.ShortMessage)
		}
		if description == "" {
			description = "Security issue detected by SpotBugs/FindSecBugs (" + rule + ")"
		}

		severity := "low"
		switch b.Priority {
		case 1:
			severity = "high"
		case 2:
			severity = "medium"
		}

		recommendation := "Review the flagged code path and apply the remediation for the FindSecBugs rule " + rule + "."
		if b.CWEID != "" {
			recommendation += " See CWE-" + b.CWEID + ": https://cwe.mitre.org/data/definitions/" + b.CWEID + ".html"
		}

		findings = append(findings, models.SecurityFinding{
			Rule:           rule,
			FilePath:       relPath(projectPath, file),
			LineNumber:     line,
			Severity:       severity,
			Description:    description,
			Recommendation: recommendation,
			Tool:           "spotbugs",
		})
	}
	return findings, nil
}
