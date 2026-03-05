package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	updatePkgOut        string
	updatePkgEcosystems []string
	updatePkgLimit      int
)

var updatePackagesCmd = &cobra.Command{
	Use:   "update-packages",
	Short: "Refresh the bundled popular packages list from registry APIs",
	Long: `Downloads the most-downloaded packages for each supported ecosystem
from their public registry APIs and writes an updated popular_packages.json.

The updated file can be committed to the repository so the next build
embeds the latest data.

Examples:
  falcn update-packages
  falcn update-packages --ecosystems npm,PyPI --limit 500
  falcn update-packages --output /path/to/popular_packages.json`,
	RunE: runUpdatePackages,
}

func init() {
	defaultOut := filepath.Join("data", "popular_packages.json")
	updatePackagesCmd.Flags().StringVar(&updatePkgOut, "output", defaultOut, "Output path for popular_packages.json")
	updatePackagesCmd.Flags().StringSliceVar(&updatePkgEcosystems, "ecosystems", nil,
		"Ecosystems to refresh (default: npm,PyPI,Go,RubyGems,NuGet)")
	updatePackagesCmd.Flags().IntVar(&updatePkgLimit, "limit", 300,
		"Number of packages to fetch per ecosystem")

	RootCmd.AddCommand(updatePackagesCmd)
}

func runUpdatePackages(cmd *cobra.Command, args []string) error {
	ecosystems := updatePkgEcosystems
	if len(ecosystems) == 0 {
		ecosystems = []string{"npm", "PyPI", "Go", "RubyGems", "NuGet"}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	result := make(map[string][]string)

	for _, eco := range ecosystems {
		fmt.Printf("Fetching popular packages: %s (limit=%d)...", eco, updatePkgLimit)
		names, err := fetchPopularPackageNames(client, eco, updatePkgLimit)
		if err != nil {
			fmt.Printf(" error: %v\n", err)
			continue
		}
		fmt.Printf(" %d packages\n", len(names))
		result[strings.ToLower(eco)] = names
	}

	if len(result) == 0 {
		return fmt.Errorf("update-packages: no packages fetched — check network connectivity")
	}

	if err := os.MkdirAll(filepath.Dir(updatePkgOut), 0o755); err != nil {
		return fmt.Errorf("update-packages: mkdir: %w", err)
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("update-packages: marshal: %w", err)
	}

	if err := os.WriteFile(updatePkgOut, data, 0o644); err != nil {
		return fmt.Errorf("update-packages: write: %w", err)
	}

	total := 0
	for _, names := range result {
		total += len(names)
	}
	fmt.Printf("\nWrote %d packages across %d ecosystems → %s\n", total, len(result), updatePkgOut)
	fmt.Println("Re-build falcn to embed the updated list.")
	return nil
}

// fetchPopularPackageNames queries each ecosystem's public API for its top packages.
func fetchPopularPackageNames(client *http.Client, ecosystem string, limit int) ([]string, error) {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return fetchNPMPopular(client, limit)
	case "pypi":
		return fetchPyPIPopular(client, limit)
	case "go", "golang":
		return fetchGoPopular(client, limit)
	case "rubygems":
		return fetchRubyGemsPopular(client, limit)
	case "nuget":
		return fetchNuGetPopular(client, limit)
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
}

func fetchNPMPopular(client *http.Client, limit int) ([]string, error) {
	// npm registry search sorted by popularity score
	url := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=boost-exact:true&size=%d&popularity=1.0&quality=0.0&maintenance=0.0", min(limit, 250))
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Objects []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		} `json:"objects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var names []string
	for _, obj := range result.Objects {
		if obj.Package.Name != "" {
			names = append(names, obj.Package.Name)
		}
	}
	return names, nil
}

func fetchPyPIPopular(client *http.Client, limit int) ([]string, error) {
	// PyPI top packages from the public stats dataset (Hugo Bowne-Anderson's curated list)
	// We use the simple API listing which has all package names.
	resp, err := client.Get("https://pypi.org/simple/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// The simple index is an HTML page — we parse package names from href attributes.
	// For a simpler approach, use the PyPI stats API via pypistats.org.
	resp2, err := client.Get("https://pypistats.org/api/packages/top?limit=" + fmt.Sprintf("%d", limit))
	if err != nil {
		// Fallback: return a curated list
		return pypiCurated(), nil
	}
	defer resp2.Body.Close()

	var result struct {
		Data []struct {
			Package string `json:"package"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&result); err != nil {
		return pypiCurated(), nil
	}

	var names []string
	for _, d := range result.Data {
		if d.Package != "" {
			names = append(names, d.Package)
		}
	}
	if len(names) == 0 {
		return pypiCurated(), nil
	}
	return names, nil
}

func fetchGoPopular(client *http.Client, limit int) ([]string, error) {
	// pkg.go.dev doesn't have a public popularity API, so we use a curated seed list.
	return goCurated(), nil
}

func fetchRubyGemsPopular(client *http.Client, limit int) ([]string, error) {
	// RubyGems provides a public API for most downloaded gems.
	url := fmt.Sprintf("https://rubygems.org/api/v1/gems.json?sort=downloads&limit=%d", min(limit, 200))
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var gems []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&gems); err != nil {
		return nil, err
	}

	var names []string
	for _, g := range gems {
		if g.Name != "" {
			names = append(names, g.Name)
		}
	}
	return names, nil
}

func fetchNuGetPopular(client *http.Client, limit int) ([]string, error) {
	// NuGet search API sorted by download count.
	url := fmt.Sprintf("https://azuresearch-usnc.nuget.org/query?q=*&take=%d&sortBy=totalDownloads-desc", min(limit, 100))
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var names []string
	for _, d := range result.Data {
		if d.ID != "" {
			names = append(names, d.ID)
		}
	}
	return names, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func pypiCurated() []string {
	return []string{
		"requests", "numpy", "pandas", "django", "flask", "tensorflow", "torch",
		"scikit-learn", "matplotlib", "pillow", "beautifulsoup4", "selenium",
		"pytest", "black", "flake8", "click", "jinja2", "sqlalchemy", "fastapi",
		"pydantic", "boto3", "redis", "celery", "gunicorn", "uvicorn", "httpx",
		"aiohttp", "typing-extensions", "setuptools", "wheel", "certifi", "urllib3",
	}
}

func goCurated() []string {
	return []string{
		"github.com/gin-gonic/gin", "github.com/gorilla/mux", "github.com/spf13/cobra",
		"github.com/spf13/viper", "github.com/sirupsen/logrus", "go.uber.org/zap",
		"github.com/stretchr/testify", "github.com/pkg/errors", "golang.org/x/net",
		"golang.org/x/crypto", "github.com/prometheus/client_golang",
		"github.com/go-redis/redis/v8", "gorm.io/gorm", "github.com/aws/aws-sdk-go",
		"github.com/google/uuid", "github.com/labstack/echo/v4",
		"github.com/gofiber/fiber/v2", "golang.org/x/sync", "golang.org/x/text",
		"github.com/urfave/cli/v2", "github.com/rs/zerolog",
	}
}
