package falcn.policy

# ── Block Critical / High Severity Packages ───────────────────────────────────
#
# This policy is a CI gate: any package with a CRITICAL or HIGH severity
# threat causes a policy violation that should fail the pipeline.
#
# Usage:
#   falcn scan . --policy-dir ./policies
#
# To enforce only on CRITICAL (allow HIGH through), remove the "high" rule.

# Block packages with CRITICAL severity threats
violations[{
	"message": sprintf("CRITICAL threat detected in %s: %s", [input["package"].name, t.description]),
	"severity": "critical",
	"threat_type": t.type,
}] {
	t := input["package"].threats[_]
	t.severity == "critical"
}

# Block packages with HIGH severity threats
violations[{
	"message": sprintf("HIGH threat detected in %s: %s", [input["package"].name, t.description]),
	"severity": "high",
	"threat_type": t.type,
}] {
	t := input["package"].threats[_]
	t.severity == "high"
}

# Block malicious packages regardless of assigned severity
violations[{
	"message": sprintf("Malicious package detected: %s", [input["package"].name]),
	"severity": "critical",
	"threat_type": "malicious_package",
}] {
	t := input["package"].threats[_]
	t.type == "malicious_package"
}

# Block packages flagged as typosquatting with high confidence
violations[{
	"message": sprintf("Typosquatting detected: %s resembles %s", [input["package"].name, t.similar_to]),
	"severity": "high",
	"threat_type": "typosquatting",
}] {
	t := input["package"].threats[_]
	t.type == "typosquatting"
	t.confidence >= 0.85
}

# Block packages with dependency confusion indicators
violations[{
	"message": sprintf("Dependency confusion risk: %s (version %s)", [input["package"].name, input["package"].version]),
	"severity": "high",
	"threat_type": "dependency_confusion",
}] {
	t := input["package"].threats[_]
	t.type == "dependency_confusion"
}
