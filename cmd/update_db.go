package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/falcn-io/falcn/internal/vulnerability"
	"github.com/spf13/cobra"
)

var (
	updateDBPath        string
	updateDBEcosystems  []string
	updateDBAirgap      bool
	updateDBAirgapOut   string
)

var updateDBCmd = &cobra.Command{
	Use:   "update-db",
	Short: "Download or refresh the local offline CVE database",
	Long: `Downloads vulnerability data from OSV.dev for all supported ecosystems
and stores it in a local SQLite database for offline use.

Examples:
  falcn update-db
  falcn update-db --ecosystems npm,PyPI,Go
  falcn update-db --airgap-bundle --output /tmp/falcn-bundle.json.gz`,
	RunE: runUpdateDB,
}

func init() {
	defaultDB := filepath.Join(defaultDataDir(), "cve.db")
	updateDBCmd.Flags().StringVar(&updateDBPath, "db", defaultDB, "Path to local CVE SQLite database")
	updateDBCmd.Flags().StringSliceVar(&updateDBEcosystems, "ecosystems", nil,
		"Comma-separated list of ecosystems to update (default: all supported)")
	updateDBCmd.Flags().BoolVar(&updateDBAirgap, "airgap-bundle", false,
		"Export a gzip-compressed bundle after updating (for offline transfer)")
	updateDBCmd.Flags().StringVar(&updateDBAirgapOut, "output", "",
		"Output path for the airgap bundle (default: <db-dir>/cve-bundle.json.gz)")

	RootCmd.AddCommand(updateDBCmd)
}

func runUpdateDB(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	fmt.Printf("Opening local CVE database: %s\n", updateDBPath)
	db, err := vulnerability.NewLocalCVEDatabase(updateDBPath)
	if err != nil {
		return fmt.Errorf("update-db: %w", err)
	}
	defer db.Close()

	meta := db.Metadata()
	if lastUpdated, ok := meta["last_updated"]; ok {
		fmt.Printf("Last updated: %s\n", lastUpdated)
	}
	fmt.Printf("Current entries: %d\n\n", db.Count())

	ecosystems := updateDBEcosystems
	if len(ecosystems) == 0 {
		ecosystems = vulnerability.DefaultEcosystems()
	}
	fmt.Printf("Updating ecosystems: %s\n\n", strings.Join(ecosystems, ", "))

	progressFn := func(ecosystem string, done, total int) {
		if ecosystem == "done" {
			fmt.Printf("\n[%d/%d] Done.\n", done, total)
			return
		}
		fmt.Printf("[%d/%d] Downloading %s...\n", done+1, total, ecosystem)
	}

	stats, err := db.Update(ctx, ecosystems, progressFn)
	if err != nil {
		return fmt.Errorf("update-db: update: %w", err)
	}

	fmt.Printf("\nUpdate complete in %s\n", stats.Duration.Round(1e6))
	fmt.Printf("  Fetched  : %d\n", stats.TotalFetched)
	fmt.Printf("  Inserted : %d\n", stats.TotalInserted)
	fmt.Printf("  Updated  : %d\n", stats.TotalUpdated)
	fmt.Printf("  Total    : %d\n", db.Count())

	if len(stats.Errors) > 0 {
		fmt.Printf("\nWarnings (%d):\n", len(stats.Errors))
		for _, e := range stats.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	if updateDBAirgap {
		bundlePath := updateDBAirgapOut
		if bundlePath == "" {
			bundlePath = filepath.Join(filepath.Dir(updateDBPath), "cve-bundle.json.gz")
		}
		fmt.Printf("\nExporting airgap bundle → %s\n", bundlePath)
		if err := db.ExportBundle(bundlePath); err != nil {
			return fmt.Errorf("update-db: export bundle: %w", err)
		}
		info, _ := os.Stat(bundlePath)
		if info != nil {
			fmt.Printf("Bundle size: %.1f MB\n", float64(info.Size())/1024/1024)
		}
	}

	return nil
}

// defaultDataDir returns the platform-appropriate data directory for falcn.
func defaultDataDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "falcn")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "falcn")
}
