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

// SuspiciousActivity represents a suspicious syscall event found in strace output.
type SuspiciousActivity struct {
	Syscall     string
	Description string
	Severity    string
}

// ParseStraceOutput parses strace -f output and returns suspicious syscall events.
// It detects: connect() to non-loopback IPs, execve() of shell binaries,
// open()/openat() writes to sensitive paths (/etc/, /tmp/, ~/.bashrc, etc.).
func (ta *TraceAnalyzer) ParseStraceOutput(output string) []SuspiciousActivity {
	var activities []SuspiciousActivity
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// connect() to non-loopback
		if strings.Contains(line, "connect(") && strings.Contains(line, "sin_addr") {
			if !strings.Contains(line, "127.0.0.1") && !strings.Contains(line, "0.0.0.0") {
				activities = append(activities, SuspiciousActivity{
					Syscall:     "connect",
					Description: "Network connection attempt: " + extractIPFromStrace(line),
					Severity:    "HIGH",
				})
			}
		}
		// execve() of shell
		if strings.Contains(line, "execve(") {
			for _, sh := range []string{"/bin/sh", "/bin/bash", "/bin/dash", "python", "curl", "wget"} {
				if strings.Contains(line, sh) {
					activities = append(activities, SuspiciousActivity{
						Syscall:     "execve",
						Description: "Process execution: " + sh,
						Severity:    "HIGH",
					})
				}
			}
		}
		// open/openat writes to sensitive paths
		if (strings.Contains(line, "open(") || strings.Contains(line, "openat(")) &&
			(strings.Contains(line, "O_WRONLY|") || strings.Contains(line, "O_RDWR")) {
			for _, sp := range []string{"/etc/", "/bin/", "/usr/", "/.bashrc", "/.profile", "/.ssh/"} {
				if strings.Contains(line, sp) {
					activities = append(activities, SuspiciousActivity{
						Syscall:     "open",
						Description: "Write to sensitive path: " + sp,
						Severity:    "CRITICAL",
					})
				}
			}
		}
	}
	return activities
}

func extractIPFromStrace(line string) string {
	// Extract sin_addr="1.2.3.4" from strace line
	start := strings.Index(line, `sin_addr="`)
	if start == -1 {
		return "unknown"
	}
	start += len(`sin_addr="`)
	end := strings.Index(line[start:], `"`)
	if end == -1 {
		return "unknown"
	}
	return line[start : start+end]
}
