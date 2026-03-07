package falcn.policy

# ── EU Cyber Resilience Act (CRA) SBOM Compliance Policy ─────────────────────
#
# The EU CRA (published November 2024, full compliance December 2027) requires:
#   - Machine-readable SBOM for every product placed on the EU market
#   - SBOM must include: supplier, component name, version, and relationships
#   - Vulnerability disclosure within 24h (exploited) / 72h (non-exploited)
#   - Penalty: up to EUR 15M or 2.5% of worldwide annual turnover
#
# This policy flags packages that would produce an incomplete SBOM or that
# would trigger mandatory disclosure obligations under the CRA.
#
# References:
#   https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R2847
#   https://www.enisa.europa.eu/topics/cybersecurity-policy/cra

# CRA Article 13 §5 — SBOM completeness: components must have name + version
violations[{
	"message": sprintf("[EU CRA Art.13§5] Package %s has no version — SBOM will be incomplete and non-compliant", [input["package"].name]),
	"severity": "high",
	"framework": "EU_CRA",
	"article": "Art.13§5",
}] {
	input["package"].version == ""
}

# CRA Article 13 §5 — Components must have identifiable supplier / source registry
violations[{
	"message": sprintf("[EU CRA Art.13§5] Package %s has no registry/ecosystem — provenance cannot be established in SBOM", [input["package"].name]),
	"severity": "high",
	"framework": "EU_CRA",
	"article": "Art.13§5",
}] {
	not input["package"].registry
}

# CRA Article 14 §1 — Actively exploited vulnerabilities must be reported within 24h
# Flag critical CVEs as requiring immediate CRA disclosure notification
violations[{
	"message": sprintf("[EU CRA Art.14§1] CRITICAL vulnerability in %s — may require 24h disclosure to ENISA/national CSIRT: %s", [input["package"].name, t.description]),
	"severity": "critical",
	"framework": "EU_CRA",
	"article": "Art.14§1",
}] {
	t := input["package"].threats[_]
	t.type == "vulnerable"
	t.severity == "critical"
}

# CRA Article 14 §2 — Non-exploited vulnerabilities must be reported within 72h
violations[{
	"message": sprintf("[EU CRA Art.14§2] HIGH vulnerability in %s — 72h disclosure obligation to ENISA may apply: %s", [input["package"].name, t.description]),
	"severity": "high",
	"framework": "EU_CRA",
	"article": "Art.14§2",
}] {
	t := input["package"].threats[_]
	t.type == "vulnerable"
	t.severity == "high"
}

# CRA Article 13 §8 — Secure development: malicious packages violate secure-by-default
violations[{
	"message": sprintf("[EU CRA Art.13§8] Malicious package %s violates secure-by-default requirement — remove immediately", [input["package"].name]),
	"severity": "critical",
	"framework": "EU_CRA",
	"article": "Art.13§8",
}] {
	t := input["package"].threats[_]
	t.type == "malicious_package"
}

violations[{
	"message": sprintf("[EU CRA Art.13§8] Malware detected in %s — product cannot be placed on EU market in current state", [input["package"].name]),
	"severity": "critical",
	"framework": "EU_CRA",
	"article": "Art.13§8",
}] {
	t := input["package"].threats[_]
	t.type == "malicious"
}

# CRA Recital 58 — Supply chain security: suspicious packages undermine CRA attestations
violations[{
	"message": sprintf("[EU CRA Rec.58] Supply chain risk in %s — third-party due diligence required before EU market placement", [input["package"].name]),
	"severity": "medium",
	"framework": "EU_CRA",
	"article": "Rec.58",
}] {
	t := input["package"].threats[_]
	t.type == "supply_chain_risk"
}

# CRA Article 13 — Embedded secrets in packages violate minimum security requirements
violations[{
	"message": sprintf("[EU CRA Art.13] Embedded credentials in %s — hardcoded secrets violate CRA minimum security requirements", [input["package"].name]),
	"severity": "critical",
	"framework": "EU_CRA",
	"article": "Art.13",
}] {
	t := input["package"].threats[_]
	t.type == "embedded_secret"
}

# CRA Article 13 §3 — Products must be delivered without known exploitable vulnerabilities
violations[{
	"message": sprintf("[EU CRA Art.13§3] Typosquatting risk in %s — may indicate compromised package; verify before EU market placement", [input["package"].name]),
	"severity": "medium",
	"framework": "EU_CRA",
	"article": "Art.13§3",
}] {
	t := input["package"].threats[_]
	t.type == "typosquatting"
	t.confidence >= 0.8
}
