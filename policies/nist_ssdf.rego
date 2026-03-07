package falcn.policy

# ── NIST Secure Software Development Framework (SP 800-218) Alignment ─────────
#
# Maps Falcn detections to NIST SSDF practices required by Executive Order 14028
# for U.S. federal software procurement.
#
# Key SSDF practices covered:
#   PW.4  — Reuse existing, well-secured software (typosquatting / reputation)
#   PW.7  — Review and/or analyze human-readable code (obfuscated code)
#   PW.9  — Test for vulnerabilities (CVE / vulnerability scanning)
#   PS.1  — Monitor and respond to software vulnerabilities (embedded secrets)
#   PS.2  — Analyze the organization for vulnerabilities (install scripts)
#   RV.1  — Identify and confirm vulnerabilities (malicious packages)

# SSDF PW.4: Use vetted, well-reputed packages (flag unknown / low-reputation)
violations[{
	"message": sprintf("[NIST SSDF PW.4] Unknown or low-reputation package: %s — verify supply chain provenance", [input["package"].name]),
	"severity": "medium",
	"framework": "NIST_SSDF",
	"practice": "PW.4",
}] {
	t := input["package"].threats[_]
	t.type == "unknown_package"
}

violations[{
	"message": sprintf("[NIST SSDF PW.4] Low-reputation package: %s — validate maintainer identity", [input["package"].name]),
	"severity": "medium",
	"framework": "NIST_SSDF",
	"practice": "PW.4",
}] {
	t := input["package"].threats[_]
	t.type == "low_reputation"
}

# SSDF PW.7: Review code for obfuscation (obfuscated packages obscure intent)
violations[{
	"message": sprintf("[NIST SSDF PW.7] Obfuscated code found in %s — manual review required before use", [input["package"].name]),
	"severity": "high",
	"framework": "NIST_SSDF",
	"practice": "PW.7",
}] {
	t := input["package"].threats[_]
	t.type == "obfuscated_code"
}

# SSDF PW.9 / RV.1: Known vulnerabilities (CVEs)
violations[{
	"message": sprintf("[NIST SSDF PW.9] Known vulnerability in %s: %s — apply patch or upgrade", [input["package"].name, t.description]),
	"severity": "high",
	"framework": "NIST_SSDF",
	"practice": "PW.9",
}] {
	t := input["package"].threats[_]
	t.type == "vulnerable"
	t.severity == "critical"
}

violations[{
	"message": sprintf("[NIST SSDF RV.1] Confirmed vulnerability in %s — remediation required", [input["package"].name]),
	"severity": "high",
	"framework": "NIST_SSDF",
	"practice": "RV.1",
}] {
	t := input["package"].threats[_]
	t.type == "malicious"
}

# SSDF PS.1: Embedded secrets violate secret management requirements
violations[{
	"message": sprintf("[NIST SSDF PS.1] Embedded credentials detected in %s — secrets must not be stored in packages", [input["package"].name]),
	"severity": "critical",
	"framework": "NIST_SSDF",
	"practice": "PS.1",
}] {
	t := input["package"].threats[_]
	t.type == "embedded_secret"
}

# SSDF PS.2: Install scripts are a common attack vector requiring scrutiny
violations[{
	"message": sprintf("[NIST SSDF PS.2] Post-install script in %s — review script content for malicious commands", [input["package"].name]),
	"severity": "medium",
	"framework": "NIST_SSDF",
	"practice": "PS.2",
}] {
	t := input["package"].threats[_]
	t.type == "install_script"
}

# SSDF PS.2: Unexpected binaries increase attack surface
violations[{
	"message": sprintf("[NIST SSDF PS.2] Unexpected binary artifact in %s — verify binary provenance and necessity", [input["package"].name]),
	"severity": "medium",
	"framework": "NIST_SSDF",
	"practice": "PS.2",
}] {
	t := input["package"].threats[_]
	t.type == "unexpected_binary"
}

# Supply-chain CI/CD injection attacks
violations[{
	"message": sprintf("[NIST SSDF PW.7] CI/CD injection pattern in %s — pipeline integrity at risk", [input["package"].name]),
	"severity": "critical",
	"framework": "NIST_SSDF",
	"practice": "PW.7",
}] {
	t := input["package"].threats[_]
	t.type == "cicd_injection"
}
