package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/falcn-io/falcn/internal/registry"
	"github.com/sirupsen/logrus"
)

// AutoDetector automatically detects project types and creates appropriate registry connectors
type AutoDetector struct {
	factory   *registry.Factory
	detectors map[string]ProjectDetector
}

// NewAutoDetector creates a new auto detector
func NewAutoDetector() *AutoDetector {
	return &AutoDetector{
		factory: registry.NewFactory(),
		detectors: map[string]ProjectDetector{
			"nodejs": &NodeJSDetector{},
			"python": &PythonDetector{},
			"go":     &GoDetector{},
			"rust":   &RustDetector{},
			"php":    &PHPDetector{},
			"java":   &JavaDetector{},
			"dotnet": &DotNetDetector{},
			"ruby":   &RubyDetector{},
		},
	}
}

// DetectProjectType detects the project type from a given directory
func (ad *AutoDetector) DetectProjectType(projectPath string) (*ProjectInfo, error) {
	// Try each detector to find the project type
	for projectType, detector := range ad.detectors {
		if projectInfo, err := detector.Detect(projectPath); err == nil {
			return projectInfo, nil
		} else {
			// Log the error for debugging but continue trying other detectors
			logrus.Debugf("%s detector failed for %s: %v", projectType, projectPath, err)
		}
	}

	return nil, fmt.Errorf("no supported project type detected in %s", projectPath)
}

// DetectAndCreateConnector detects project type and creates the appropriate registry connector
func (ad *AutoDetector) DetectAndCreateConnector(projectPath string) (registry.Connector, error) {
	projectInfo, err := ad.DetectProjectType(projectPath)
	if err != nil {
		return nil, err
	}

	// Map project type to registry type
	registryType := ad.mapProjectTypeToRegistry(projectInfo.Type)
	if registryType == "" {
		return nil, fmt.Errorf("unsupported project type: %s", projectInfo.Type)
	}

	// Create connector using factory
	return ad.factory.CreateConnectorFromType(registryType)
}

// DetectAllProjectTypes scans a directory and detects all project types
func (ad *AutoDetector) DetectAllProjectTypes(rootPath string) ([]*ProjectInfo, error) {
	var projects []*ProjectInfo

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking despite errors
		}

		// Skip hidden directories and common non-project directories
		if info.IsDir() {
			dirName := filepath.Base(path)
			if strings.HasPrefix(dirName, ".") ||
				dirName == "node_modules" ||
				dirName == "vendor" ||
				dirName == "target" ||
				dirName == "build" ||
				dirName == "dist" ||
				dirName == "__pycache__" ||
				dirName == ".git" {
				return filepath.SkipDir
			}

			// Try to detect project in this directory
			if projectInfo, err := ad.DetectProjectType(path); err == nil {
				projects = append(projects, projectInfo)
				// Skip subdirectories of detected projects to avoid duplicates
				return filepath.SkipDir
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return projects, nil
}

// mapProjectTypeToRegistry maps project type to registry type
func (ad *AutoDetector) mapProjectTypeToRegistry(projectType string) string {
	switch projectType {
	case "nodejs":
		return "npm"
	case "python":
		return "pypi"
	case "go":
		return "go"
	case "rust":
		return "cargo"
	case "php":
		return "packagist"
	case "java":
		return "maven"
	case "dotnet":
		return "nuget"
	case "ruby":
		return "rubygems"
	default:
		return ""
	}
}
