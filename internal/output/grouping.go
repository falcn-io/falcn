package output

import (
	"sort"

	"github.com/falcn-io/falcn/pkg/types"
)

// ThreatGroup groups all threats for a single package.
type ThreatGroup struct {
	PackageName  string
	Version      string
	Registry     string
	MaxSeverity  types.Severity
	ThreatCount  int
	CVEIDs       []string
	FixedVersion string
	Reachable    *bool
	Types        []string
	// IsDirect is true when the package is a direct dependency (not transitive).
	// Populated from threat metadata["is_direct"] when available.
	IsDirect bool
	// CallChain is the dependency chain leading to this package, e.g.
	// ["app", "webpack", "lodash"]. Populated from Threat.CallPath when available.
	CallChain []string
}

// GroupThreatsByPackage aggregates a flat threat list into per-package groups,
// deduplicating CVE IDs and computing the maximum severity per group.
func GroupThreatsByPackage(threats []types.Threat) []ThreatGroup {
	groupMap := map[string]*ThreatGroup{}
	for _, t := range threats {
		key := t.Package + "@" + t.Version
		g, ok := groupMap[key]
		if !ok {
			g = &ThreatGroup{
				PackageName: t.Package,
				Version:     t.Version,
				Registry:    t.Registry,
			}
			groupMap[key] = g
		}
		g.ThreatCount++
		// Treat SeverityUnknown (4) as lower priority than SeverityCritical (3)
		// so known-severity threats always rank above unscored ones.
		if effectiveSev(t.Severity) > effectiveSev(g.MaxSeverity) {
			g.MaxSeverity = t.Severity
		}
		for _, c := range t.CVEs {
			if c != "" {
				found := false
				for _, existing := range g.CVEIDs {
					if existing == c {
						found = true
						break
					}
				}
				if !found {
					g.CVEIDs = append(g.CVEIDs, c)
				}
			}
		}
		if t.FixedVersion != "" && g.FixedVersion == "" {
			g.FixedVersion = t.FixedVersion
		}
		if t.Reachable != nil && g.Reachable == nil {
			r := *t.Reachable
			g.Reachable = &r
		}
		// Populate direct/transitive flag from threat metadata.
		if isD, ok := t.Metadata["is_direct"].(bool); ok && isD {
			g.IsDirect = true
		}
		// Capture call/dependency chain from CallPath (first threat wins).
		if len(t.CallPath) > 0 && len(g.CallChain) == 0 {
			g.CallChain = t.CallPath
		}
		typeStr := string(t.Type)
		found := false
		for _, ex := range g.Types {
			if ex == typeStr {
				found = true
				break
			}
		}
		if !found {
			g.Types = append(g.Types, typeStr)
		}
	}
	groups := make([]ThreatGroup, 0, len(groupMap))
	for _, g := range groupMap {
		groups = append(groups, *g)
	}
	// Sort by effective severity descending (CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN),
	// then package name ascending.
	sort.Slice(groups, func(i, j int) bool {
		si, sj := effectiveSev(groups[i].MaxSeverity), effectiveSev(groups[j].MaxSeverity)
		if si != sj {
			return si > sj
		}
		return groups[i].PackageName < groups[j].PackageName
	})
	return groups
}

// effectiveSev maps SeverityUnknown to -1 so it sorts below all known severities.
func effectiveSev(s types.Severity) int {
	if s == types.SeverityUnknown {
		return -1
	}
	return int(s)
}
