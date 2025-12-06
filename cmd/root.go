package cmd

import (
	"github.com/falcn-io/falcn/pkg/logger"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	configFile   string
	verbose      bool
	outputFormat string
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "falcn",
	Short: "Falcn - Precision Supply Chain Security",
	Long: `Falcn is an intelligent supply chain firewall that actively blocks 
malicious packages, typosquatting attacks, and supply chain threats in real-time.

It provides:
- Multi-language package support (npm, PyPI, Go, Maven, NuGet, etc.)
- Advanced threat detection algorithms (RUNT, DIRT, GTR)  
- Policy-based security enforcement
- SBOM generation (SPDX, CycloneDX)
- Graph visualization (DOT, SVG, Mermaid)
- CI/CD integration`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			logger.SetGlobalLevel(logger.DEBUG)
			logrus.SetLevel(logrus.DebugLevel)
		} else {
			// Suppress info/warn logs to keep CLI output clean
			logger.SetGlobalLevel(logger.ERROR)
			logrus.SetLevel(logrus.ErrorLevel)
		}
	},
}

func init() {
	// Global flags
	RootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file (default is $HOME/.falcn.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "futuristic", "output format (json, yaml, table, futuristic)")
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return RootCmd.Execute()
}
