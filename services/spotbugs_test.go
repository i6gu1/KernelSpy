package services

import (
	"testing"
)

const spotbugsFixture = `<?xml version="1.0" encoding="UTF-8"?>
<BugCollection sequence="0" release="1.0" analysisExceptionErrors="0" project="black-hat" version="4.9.1">
  <BugInstance type="SQL_INJECTION_HIBERNATE" priority="1" rank="1" abbrev="SECSQLI" category="SECURITY" cweid="89">
    <ShortMessage>Potential SQL Injection</ShortMessage>
    <LongMessage>Potential SQL Injection (Hibernate) detected in method getUsers(String)</LongMessage>
    <Class classname="com.example.UserDao" sourcepath="src/main/java/com/example/UserDao.java">
      <SourceLine classname="com.example.UserDao" start="25" end="28" sourcepath="src/main/java/com/example/UserDao.java" sourcefile="UserDao.java"/>
    </Class>
    <Method classname="com.example.UserDao" name="getUsers" signature="(Ljava/lang/String;)Ljava/util/List;" isStatic="false" role="METHOD_DEFAULT">
      <SourceLine classname="com.example.UserDao" start="25" end="28" sourcepath="src/main/java/com/example/UserDao.java" sourcefile="UserDao.java"/>
    </Method>
    <SourceLine classname="com.example.UserDao" start="26" end="26" startByte="512" endByte="560" sourcepath="src/main/java/com/example/UserDao.java" sourcefile="UserDao.java"/>
  </BugInstance>
  <BugInstance type="WEAK_MESSAGE_DIGEST_MD5" priority="2" rank="9" abbrev="WEAKMD5" category="SECURITY" cweid="327">
    <ShortMessage>Weak MessageDigest</ShortMessage>
    <LongMessage>Found usage of MD5/SHA1 MessageDigest</LongMessage>
    <Class classname="com.example.Hash" sourcepath="src/main/java/com/example/Hash.java">
      <SourceLine classname="com.example.Hash" start="10" end="10" sourcepath="src/main/java/com/example/Hash.java" sourcefile="Hash.java"/>
    </Class>
    <SourceLine classname="com.example.Hash" start="10" end="10" startByte="120" endByte="140" sourcepath="src/main/java/com/example/Hash.java" sourcefile="Hash.java"/>
  </BugInstance>
</BugCollection>
`

// TestParseSpotbugsReport verifies the FindSecBugs XML report maps onto the
// unified finding schema: rule, CWE reference, severity by priority, file,
// line and description.
func TestParseSpotbugsReport(t *testing.T) {
	findings, err := parseSpotbugsReport("/tmp/blackhat-projects/project_1", []byte(spotbugsFixture))
	if err != nil {
		t.Fatalf("parseSpotbugsReport failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	first := findings[0]
	if first.Rule != "SQL_INJECTION_HIBERNATE" {
		t.Errorf("rule = %q", first.Rule)
	}
	if first.FilePath != "src/main/java/com/example/UserDao.java" {
		t.Errorf("file path = %q", first.FilePath)
	}
	if first.LineNumber != 26 {
		t.Errorf("line number = %d, want 26", first.LineNumber)
	}
	if first.Severity != "high" {
		t.Errorf("severity = %q, want high (priority 1)", first.Severity)
	}
	if first.Tool != "spotbugs" {
		t.Errorf("tool = %q, want spotbugs", first.Tool)
	}
	if first.Description == "" {
		t.Error("description should not be empty")
	}
	if first.Recommendation == "" || !contains(first.Recommendation, "CWE-89") {
		t.Errorf("recommendation should reference CWE-89, got %q", first.Recommendation)
	}

	second := findings[1]
	if second.Rule != "WEAK_MESSAGE_DIGEST_MD5" {
		t.Errorf("second rule = %q", second.Rule)
	}
	if second.Severity != "medium" {
		t.Errorf("second severity = %q, want medium (priority 2)", second.Severity)
	}
	if second.LineNumber != 10 {
		t.Errorf("second line = %d, want 10", second.LineNumber)
	}
}

// TestParseSpotbugsReportEmpty verifies an empty report produces no findings.
func TestParseSpotbugsReportEmpty(t *testing.T) {
	findings, err := parseSpotbugsReport("/tmp/proj", []byte(`<BugCollection version="4.9.1"></BugCollection>`))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty report, got %d", len(findings))
	}
}

// TestParseSpotbugsReportGarbage verifies malformed XML surfaces an error.
func TestParseSpotbugsReportGarbage(t *testing.T) {
	if _, err := parseSpotbugsReport("/tmp/proj", []byte("not xml at all")); err == nil {
		t.Error("expected an error for malformed XML")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
