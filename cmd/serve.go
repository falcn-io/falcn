package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(serveCmd)
	serveCmd.Flags().Int("port", 8080, "Port to listen on")
	serveCmd.Flags().String("host", "0.0.0.0", "Host to bind to")
	serveCmd.Flags().Bool("tls", false, "Enable TLS (requires --tls-cert and --tls-key)")
	serveCmd.Flags().String("tls-cert", "", "Path to TLS certificate file")
	serveCmd.Flags().String("tls-key", "", "Path to TLS private key file")
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Falcn API server and web dashboard",
	Long: `Start the Falcn REST API server with the embedded web dashboard.

The API is available at /v1/* and the web UI at /.

Environment variables:
  FALCN_PORT          Override --port
  FALCN_CORS_ORIGINS  Comma-separated allowed CORS origins
  FALCN_JWT_SECRET    JWT signing secret for authentication`,
	RunE: runServe,
}

func runServe(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	host, _ := cmd.Flags().GetString("host")
	tlsEnabled, _ := cmd.Flags().GetBool("tls")
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")

	// Allow env override
	if p := os.Getenv("FALCN_PORT"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			port = parsed
		} else {
			return fmt.Errorf("invalid FALCN_PORT: %s", p)
		}
	}

	scheme := "http"
	if tlsEnabled || tlsCert != "" {
		scheme = "https"
	}

	fmt.Printf("\n\033[36m◈  Falcn\033[0m  v%s\n", Version)
	fmt.Printf("   Dashboard  → \033[4m%s://%s:%d\033[0m\n", scheme, host, port)
	fmt.Printf("   API        → \033[4m%s://%s:%d/v1\033[0m\n", scheme, host, port)
	fmt.Printf("   Docs       → \033[4m%s://%s:%d/v1/docs\033[0m\n\n", scheme, host, port)

	return startAPIServer(port, host, tlsCert, tlsKey)
}

// startAPIServer starts the Falcn API+UI server. It locates the api binary
// (installed alongside the falcn CLI) and exec's it with the configured port.
// Falls back to `go run ./api` for development use when the binary is absent.
func startAPIServer(port int, host, tlsCert, tlsKey string) error {
	// Propagate configuration via environment variables understood by api/main.go.
	env := append(os.Environ(),
		fmt.Sprintf("PORT=%d", port),
		fmt.Sprintf("FALCN_BIND_HOST=%s", host),
	)
	if tlsCert != "" {
		env = append(env, "FALCN_TLS_CERT="+tlsCert)
	}
	if tlsKey != "" {
		env = append(env, "FALCN_TLS_KEY="+tlsKey)
	}

	// 1. Look for falcn-api binary next to the current executable.
	apiCandidates := apiBinaryCandidates()
	for _, candidate := range apiCandidates {
		if _, err := os.Stat(candidate); err == nil {
			c := exec.Command(candidate)
			c.Env = env
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			c.Stdin = os.Stdin
			return c.Run()
		}
	}

	// 2. Fall back to go run ./api (development mode).
	fmt.Println("\033[90m[serve] falcn-api binary not found — falling back to `go run ./api` (dev mode)\033[0m")
	goExe, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("falcn-api binary not found and 'go' is not in PATH; " +
			"build the api binary with `make build-api` and ensure it is in your PATH")
	}
	c := exec.Command(goExe, "run", "./api")
	c.Env = env
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Run()
}

// apiBinaryCandidates returns a list of paths to check for the api binary.
func apiBinaryCandidates() []string {
	apiExe := "falcn-api"
	if runtime.GOOS == "windows" {
		apiExe += ".exe"
	}

	var candidates []string

	// Next to the current executable
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), apiExe))
	}

	// In PATH
	if p, err := exec.LookPath(apiExe); err == nil {
		candidates = append(candidates, p)
	}

	// Common install locations
	candidates = append(candidates,
		filepath.Join("/usr/local/bin", apiExe),
		filepath.Join("/usr/bin", apiExe),
	)

	return candidates
}
