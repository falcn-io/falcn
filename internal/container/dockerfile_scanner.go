package container

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strings"
)

// ─── Dockerfile security rules ────────────────────────────────────────────────

// dockerfileRule describes a single Dockerfile security check.
type dockerfileRule struct {
	id          string
	severity    string
	title       string
	detail      string
	remediation string
	check       func(instructions []dfInstruction) *SecurityFinding
}

// dfInstruction is one parsed Dockerfile instruction.
type dfInstruction struct {
	lineNum int
	opcode  string // upper-cased, e.g. "FROM", "RUN", "ENV"
	args    string
}

// ─── Regex patterns ───────────────────────────────────────────────────────────

var (
	// Patterns that look like secrets inside ENV/ARG/RUN lines.
	secretEnvRe = regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|token|auth|private[_-]?key|access[_-]?key)\s*=\s*\S+`)
	// Fetch-and-pipe patterns that download and execute code at build time.
	fetchPipeRe = regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(ba)?sh`)
	// eval-based obfuscation (base64 | python exec, etc.)
	evalExecRe = regexp.MustCompile(`(?i)(echo\s+[A-Za-z0-9+/]{30,}=*\s*\|\s*base64\s+-d|python[23]?\s+-c\s+["']?\s*exec\s*\()`)
	// ADD with a remote URL is discouraged.
	addRemoteURLRe = regexp.MustCompile(`(?i)^https?://`)
	// Detect `:latest` tag (pinning to latest is risky).
	latestTagRe = regexp.MustCompile(`^([^@:]+):latest$`)
	// Detect no-tag / implicit latest.
	noTagRe = regexp.MustCompile(`^([^@:/]+/)?[^@:/]+$`)
)

// dockerfileRules is the ordered list of checks applied to every Dockerfile.
var dockerfileRules = []dockerfileRule{
	{
		id: "IMG001", severity: "high",
		title:       "Container runs as root",
		detail:      "No USER instruction was found; the container will run as root by default.",
		remediation: "Add a non-root USER instruction before the final ENTRYPOINT/CMD, e.g. `USER 1000:1000`.",
		check: func(ins []dfInstruction) *SecurityFinding {
			for _, i := range ins {
				if i.opcode == "USER" {
					user := strings.ToLower(strings.Fields(i.args)[0])
					if user != "root" && user != "0" {
						return nil // has a non-root USER
					}
				}
			}
			return &SecurityFinding{ID: "IMG001", Severity: "high",
				Title:       "Container runs as root",
				Detail:      "No USER instruction was found; the container will run as root by default.",
				Remediation: "Add a non-root USER instruction, e.g. `USER 1000:1000`."}
		},
	},
	{
		id: "IMG002", severity: "high",
		title:       "Secrets embedded in ENV or ARG",
		detail:      "One or more ENV or ARG instructions contain what looks like a secret value.",
		remediation: "Use Docker build secrets (`--secret`) or a secrets manager instead of hard-coding credentials.",
		check: func(ins []dfInstruction) *SecurityFinding {
			for _, i := range ins {
				if i.opcode == "ENV" || i.opcode == "ARG" {
					if secretEnvRe.MatchString(i.args) {
						return &SecurityFinding{ID: "IMG002", Severity: "high",
							Title:       "Secrets embedded in ENV or ARG",
							Detail:      "Line contains a potential credential: `" + truncate(i.args, 80) + "`",
							Remediation: "Use `--secret` flags or a runtime secrets manager."}
					}
				}
			}
			return nil
		},
	},
	{
		id: "IMG003", severity: "critical",
		title:       "Fetch-and-pipe pattern in RUN",
		detail:      "curl/wget output is piped directly into a shell, allowing remote code execution.",
		remediation: "Download files, verify their checksums, then execute. Never pipe to sh inline.",
		check: func(ins []dfInstruction) *SecurityFinding {
			for _, i := range ins {
				if i.opcode == "RUN" && fetchPipeRe.MatchString(i.args) {
					return &SecurityFinding{ID: "IMG003", Severity: "critical",
						Title:       "Fetch-and-pipe pattern in RUN instruction",
						Detail:      "Remote code may be executed: `" + truncate(i.args, 100) + "`",
						Remediation: "Download, checksum-verify, then execute separately."}
				}
			}
			return nil
		},
	},
	{
		id: "IMG004", severity: "high",
		title:       "Base image uses ':latest' tag",
		detail:      "Using the ':latest' tag makes builds non-deterministic and can pull compromised images.",
		remediation: "Pin the base image to a specific version tag or SHA256 digest.",
		check: func(ins []dfInstruction) *SecurityFinding {
			for _, i := range ins {
				if i.opcode == "FROM" {
					img := strings.Fields(i.args)[0]
					if img == "scratch" || img == "FROM" {
						continue
					}
					if latestTagRe.MatchString(img) || noTagRe.MatchString(img) {
						return &SecurityFinding{ID: "IMG004", Severity: "medium",
							Title:       "Base image uses ':latest' or no tag",
							Detail:      "FROM " + img + " — non-deterministic build.",
							Remediation: "Pin to a specific version, e.g. `FROM " + img + ":1.27.2` or add a SHA256 digest."}
					}
				}
			}
			return nil
		},
	},
	{
		id: "IMG005", severity: "medium",
		title:       "ADD used with a remote URL",
		detail:      "ADD with a URL downloads content without checksum verification.",
		remediation: "Use RUN curl/wget with explicit checksum verification, or COPY with a local file.",
		check: func(ins []dfInstruction) *SecurityFinding {
			for _, i := range ins {
				if i.opcode == "ADD" && addRemoteURLRe.MatchString(strings.Fields(i.args)[0]) {
					return &SecurityFinding{ID: "IMG005", Severity: "medium",
						Title:       "ADD used with a remote URL",
						Detail:      "`ADD " + truncate(i.args, 80) + "` — no integrity check.",
						Remediation: "Replace with `RUN curl -fsSL <url> -o file && sha256sum --check`."}
				}
			}
			return nil
		},
	},
	{
		id: "IMG006", severity: "high",
		title:       "Obfuscated command in RUN",
		detail:      "A base64-decode-then-execute or eval pattern was detected.",
		remediation: "Avoid obfuscated commands; keep RUN instructions transparent and auditable.",
		check: func(ins []dfInstruction) *SecurityFinding {
			for _, i := range ins {
				if i.opcode == "RUN" && evalExecRe.MatchString(i.args) {
					return &SecurityFinding{ID: "IMG006", Severity: "high",
						Title:       "Obfuscated command in RUN instruction",
						Detail:      "`" + truncate(i.args, 100) + "`",
						Remediation: "Remove obfuscation; use explicit, auditable commands."}
				}
			}
			return nil
		},
	},
	{
		id: "IMG007", severity: "low",
		title:       "HEALTHCHECK not defined",
		detail:      "No HEALTHCHECK instruction was found; container orchestrators cannot detect unhealthy containers.",
		remediation: "Add a HEALTHCHECK instruction, e.g. `HEALTHCHECK CMD curl -f http://localhost/ || exit 1`.",
		check: func(ins []dfInstruction) *SecurityFinding {
			for _, i := range ins {
				if i.opcode == "HEALTHCHECK" {
					return nil
				}
			}
			return &SecurityFinding{ID: "IMG007", Severity: "low",
				Title:       "HEALTHCHECK not defined",
				Detail:      "Container liveness/readiness cannot be checked by orchestrators.",
				Remediation: "Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1"}
		},
	},
}

// ─── Public API ───────────────────────────────────────────────────────────────

// ScanDockerfile reads a Dockerfile from path and returns a list of security
// findings. Returns nil, nil if the file is not a recognisable Dockerfile.
func ScanDockerfile(path string) ([]SecurityFinding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ScanDockerfileReader(f)
}

// ScanDockerfileReader parses a Dockerfile from r and returns security findings.
func ScanDockerfileReader(r io.Reader) ([]SecurityFinding, error) {
	ins, err := parseDockerfile(r)
	if err != nil {
		return nil, err
	}
	if len(ins) == 0 {
		return nil, nil
	}

	var findings []SecurityFinding
	for _, rule := range dockerfileRules {
		if f := rule.check(ins); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

// ─── Dockerfile parser ────────────────────────────────────────────────────────

// parseDockerfile performs a simple line-by-line parse of a Dockerfile,
// returning each complete instruction with its opcode and argument string.
// Continuation lines (ending with `\`) are joined.
func parseDockerfile(r io.Reader) ([]dfInstruction, error) {
	var (
		out    []dfInstruction
		buf    strings.Builder
		lineNo int
		startLine int
	)
	flush := func() {
		line := strings.TrimSpace(buf.String())
		if line == "" || strings.HasPrefix(line, "#") {
			buf.Reset()
			return
		}
		fields := strings.SplitN(line, " ", 2)
		ins := dfInstruction{lineNum: startLine, opcode: strings.ToUpper(fields[0])}
		if len(fields) > 1 {
			ins.args = strings.TrimSpace(fields[1])
		}
		out = append(out, ins)
		buf.Reset()
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lineNo++
		text := scanner.Text()
		// Strip trailing whitespace for continuation detection.
		trimmed := strings.TrimRight(text, " \t")
		if buf.Len() == 0 {
			startLine = lineNo
		}
		if strings.HasSuffix(trimmed, "\\") {
			buf.WriteString(strings.TrimSuffix(trimmed, "\\"))
			buf.WriteByte(' ')
		} else {
			buf.WriteString(text)
			flush()
		}
	}
	// Handle unterminated continuation.
	if buf.Len() > 0 {
		flush()
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
