package main

import (
	_ "embed"

	"github.com/falcn-io/falcn/internal/detector"
)

// popularPackagesJSON is the bundled copy of data/popular_packages.json.
// Embedded at compile time — always available offline, even in an airgap environment.
//
//go:embed data/popular_packages.json
var popularPackagesJSON []byte

func init() {
	// Inject the embedded data into the detector before any scan runs.
	// The detector still accepts runtime overrides via `falcn update-packages`.
	detector.SetEmbeddedPopularPackages(popularPackagesJSON)
}
