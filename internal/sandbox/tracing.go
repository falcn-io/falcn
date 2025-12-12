package sandbox

import (
	"strings"
)

// TraceAnalyzer analyzes execution logs for suspicious activities
type TraceAnalyzer struct {
	suspiciousKeywords map[string]string
}

// NewTraceAnalyzer creates a new trace analyzer
func NewTraceAnalyzer() *TraceAnalyzer {
	return &TraceAnalyzer{
		suspiciousKeywords: map[string]string{
			"connect":   "Network Connection Attempt",
			"socket":    "Socket Creation",
			"execve":    "Process Execution",
			"unlink":    "File Deletion",
			"chmod":     "Permission Change",
			"wget":      "File Download (wget)",
			"curl":      "File Download (curl)",
			"sh -i":     "Interactive Shell",
			"/bin/sh":   "Shell Invocation",
			"/bin/bash": "Shell Invocation",
		},
	}
}

// AnalyzeLogs scans the logs for suspicious patterns
// details maps the ThreatType (e.g. "network_activity") to a description
func (ta *TraceAnalyzer) AnalyzeLogs(stdout, stderr string) map[string]string {
	findings := make(map[string]string)

	combined := stdout + "\n" + stderr
	lines := strings.Split(combined, "\n")

	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		for keyword, desc := range ta.suspiciousKeywords {
			if strings.Contains(lowerLine, keyword) {
				findings[keyword] = desc
			}
		}
	}

	return findings
}
