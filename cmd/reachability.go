package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/falcn-io/falcn/internal/reachability"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(reachabilityCmd)

	reachabilityCmd.Flags().String("project-dir", ".", "Project directory to analyse")
	reachabilityCmd.Flags().String("language", "", "Source language (go, python, javascript, typescript); auto-detected if omitted")
	reachabilityCmd.Flags().Int("depth", reachability.DefaultMaxDepth, "Maximum transitive hops (1-20)")
	reachabilityCmd.Flags().String("format", "text", "Output format: text or json")
	reachabilityCmd.Flags().Bool("include-tests", false, "Include test entry points in analysis")
}

var reachabilityCmd = &cobra.Command{
	Use:   "reachability [package-name]",
	Short: "Check if a dependency's code is actually reachable",
	Long: `Analyse your project's call graph to determine if a dependency's functions
are actually invoked from entry points. Reduces false positives by ~80%.

The analysis builds a function-level call graph and performs BFS from entry
points (main, init, HTTP handlers, exported functions) through the graph. If
any path reaches a call site of the target package, it is marked as reachable.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runReachability,
}

// reachabilityJSONOutput is the JSON wire format for --format=json.
type reachabilityJSONOutput struct {
	Package        string                     `json:"package"`
	Reachable      bool                       `json:"reachable"`
	Language       string                     `json:"language"`
	Depth          int                        `json:"depth"`
	CallPath       []reachabilityJSONHop      `json:"call_path,omitempty"`
	GraphSize      int                        `json:"graph_size"`
	EntryPoints    int                        `json:"entry_points"`
	AnalysisTimeMs int64                      `json:"analysis_time_ms"`
	Error          string                     `json:"error,omitempty"`
}

type reachabilityJSONHop struct {
	Function string `json:"function"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
}

func runReachability(cmd *cobra.Command, args []string) error {
	packageName := args[0]

	projectDir, _ := cmd.Flags().GetString("project-dir")
	langStr, _ := cmd.Flags().GetString("language")
	depth, _ := cmd.Flags().GetInt("depth")
	format, _ := cmd.Flags().GetString("format")
	includeTests, _ := cmd.Flags().GetBool("include-tests")

	start := time.Now()

	analyzer, err := reachability.New(projectDir)
	if err != nil {
		return fmt.Errorf("initialise reachability analyser: %w", err)
	}

	if langStr != "" {
		analyzer.SetLanguage(reachability.Language(langStr))
	}
	analyzer.SetMaxDepth(depth)
	analyzer.SetIncludeTests(includeTests)

	// Run analysis for all requested packages.
	results := make([]reachability.ReachabilityResult, 0, len(args))
	if len(args) == 1 {
		results = append(results, analyzer.Check(packageName))
	} else {
		rm := analyzer.CheckMultiple(args)
		for _, pkg := range args {
			results = append(results, rm[pkg])
		}
	}

	elapsed := time.Since(start)

	switch format {
	case "json":
		return outputReachabilityJSON(results, elapsed)
	default:
		return outputReachabilityText(results, elapsed)
	}
}

func outputReachabilityText(results []reachability.ReachabilityResult, elapsed time.Duration) error {
	for i, r := range results {
		if i > 0 {
			fmt.Println()
			fmt.Println(strings.Repeat("─", 60))
			fmt.Println()
		}

		reachableStr := "NO"
		if r.Reachable {
			reachableStr = "YES"
		}

		fmt.Printf("Package: %s\n", r.PackageName)
		fmt.Printf("Reachable: %s\n", reachableStr)
		fmt.Printf("Language: %s\n", r.Language)

		if r.Reachable && r.Depth > 0 {
			fmt.Printf("Depth: %d hops\n", r.Depth)
		} else if r.Reachable {
			fmt.Printf("Depth: direct\n")
		}

		if r.Error != nil {
			fmt.Printf("Warning: %s\n", r.Error)
		}

		if len(r.TransitivePath) > 0 {
			fmt.Println("Call path:")
			for i, hop := range r.TransitivePath {
				indent := strings.Repeat("  ", i)
				prefix := ""
				if i > 0 {
					prefix = "-> "
				}
				if hop.File != "" {
					fmt.Printf("%s%s%s [%s:%d]\n", indent, prefix, hop.Function, hop.File, hop.Line)
				} else {
					fmt.Printf("%s%s%s\n", indent, prefix, hop.Function)
				}
			}
		} else if len(r.CallPath) > 0 {
			fmt.Println("Call path:")
			for i, step := range r.CallPath {
				indent := strings.Repeat("  ", i)
				prefix := ""
				if i > 0 {
					prefix = "-> "
				}
				fmt.Printf("%s%s%s\n", indent, prefix, step)
			}
		}

		if r.GraphSize > 0 {
			fmt.Printf("Functions in call graph: %d\n", r.GraphSize)
		}
	}
	return nil
}

func outputReachabilityJSON(results []reachability.ReachabilityResult, elapsed time.Duration) error {
	var outputs []reachabilityJSONOutput

	for _, r := range results {
		out := reachabilityJSONOutput{
			Package:        r.PackageName,
			Reachable:      r.Reachable,
			Language:       string(r.Language),
			Depth:          r.Depth,
			GraphSize:      r.GraphSize,
			AnalysisTimeMs: elapsed.Milliseconds(),
		}
		if r.Error != nil {
			out.Error = r.Error.Error()
		}

		if len(r.TransitivePath) > 0 {
			for _, hop := range r.TransitivePath {
				out.CallPath = append(out.CallPath, reachabilityJSONHop{
					Function: hop.Function,
					File:     hop.File,
					Line:     hop.Line,
				})
			}
		} else {
			for _, step := range r.CallPath {
				out.CallPath = append(out.CallPath, reachabilityJSONHop{
					Function: step,
				})
			}
		}

		outputs = append(outputs, out)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if len(outputs) == 1 {
		return enc.Encode(outputs[0])
	}
	return enc.Encode(outputs)
}
