package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/falcn-io/falcn/internal/config"
	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/internal/proxy"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().String("listen", ":8888", "Address to listen on")
	proxyCmd.Flags().String("npm-upstream", "https://registry.npmjs.org", "Upstream npm registry URL")
	proxyCmd.Flags().String("pypi-upstream", "https://pypi.org", "Upstream PyPI registry URL")
	proxyCmd.Flags().String("maven-upstream", "https://repo1.maven.org/maven2", "Upstream Maven Central URL")
	proxyCmd.Flags().String("go-proxy-upstream", "https://proxy.golang.org", "Upstream Go module proxy URL")
	proxyCmd.Flags().String("cargo-upstream", "https://crates.io", "Upstream Cargo/crates.io URL")
	proxyCmd.Flags().String("block-severity", "high", "Minimum severity to block (critical, high, medium, low)")
	proxyCmd.Flags().String("warn-severity", "medium", "Minimum severity to add warning header (critical, high, medium, low)")
	proxyCmd.Flags().StringSlice("allow-list", []string{}, "Packages to always allow (bypass scanning)")
	proxyCmd.Flags().StringSlice("block-list", []string{}, "Packages to always block")
	proxyCmd.Flags().Duration("cache-ttl", 5*time.Minute, "Cache TTL for scan results")
	proxyCmd.Flags().String("tls-cert", "", "Path to TLS certificate file")
	proxyCmd.Flags().String("tls-key", "", "Path to TLS private key file")
	proxyCmd.Flags().Int("max-audit-log", 10000, "Maximum audit log entries to retain in memory")
	proxyCmd.Flags().String("admin-token", "", "Bearer token for admin API authentication (required in production)")
	proxyCmd.Flags().String("audit-log-file", "", "Path for persistent JSONL audit log (optional)")
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start registry firewall proxy",
	Long: `Start an enterprise registry firewall that intercepts package installations
and blocks malicious packages in real-time.

Configure your package manager to use this proxy:

  npm:    npm config set registry http://localhost:8888/npm/
  pip:    pip install --index-url http://localhost:8888/pypi/simple/ <package>
  maven:  settings.xml mirror → http://localhost:8888/maven/
  go:     GOPROXY=http://localhost:8888/go,direct
  cargo:  [registries.falcn] index = "http://localhost:8888/cargo/"

Admin API:
  GET  /api/v1/policies    — view current policies
  PUT  /api/v1/policies    — update policies (JSON body)
  GET  /api/v1/audit-log   — view audit log
  GET  /api/v1/stats       — view proxy statistics`,
	RunE: runProxy,
}

func runProxy(cmd *cobra.Command, args []string) error {
	listen, _ := cmd.Flags().GetString("listen")
	npmUpstream, _ := cmd.Flags().GetString("npm-upstream")
	pypiUpstream, _ := cmd.Flags().GetString("pypi-upstream")
	mavenUpstream, _ := cmd.Flags().GetString("maven-upstream")
	goProxyUpstream, _ := cmd.Flags().GetString("go-proxy-upstream")
	cargoUpstream, _ := cmd.Flags().GetString("cargo-upstream")
	blockSeverity, _ := cmd.Flags().GetString("block-severity")
	warnSeverity, _ := cmd.Flags().GetString("warn-severity")
	allowList, _ := cmd.Flags().GetStringSlice("allow-list")
	blockList, _ := cmd.Flags().GetStringSlice("block-list")
	cacheTTL, _ := cmd.Flags().GetDuration("cache-ttl")
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")
	maxAuditLog, _ := cmd.Flags().GetInt("max-audit-log")
	adminToken, _ := cmd.Flags().GetString("admin-token")
	auditLogFile, _ := cmd.Flags().GetString("audit-log-file")
	// Also check environment variables
	if adminToken == "" {
		adminToken = os.Getenv("FALCN_PROXY_ADMIN_TOKEN")
	}
	if auditLogFile == "" {
		auditLogFile = os.Getenv("FALCN_PROXY_AUDIT_LOG")
	}

	// Load falcn config for the detector.
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		cfg = createDefaultConfig()
		if verbose {
			logrus.WithError(err).Debug("Using default config for detector engine")
		}
	}

	// Create the detector engine.
	engine := detector.New(cfg)

	proxyCfg := &proxy.ProxyConfig{
		ListenAddr:    listen,
		NPMUpstream:   npmUpstream,
		PyPIUpstream:    pypiUpstream,
		MavenUpstream:   mavenUpstream,
		GoProxyUpstream: goProxyUpstream,
		CargoUpstream:   cargoUpstream,
		BlockSeverity:   blockSeverity,
		WarnSeverity:  warnSeverity,
		MaxAuditLog:   maxAuditLog,
		TLSCert:       tlsCert,
		TLSKey:        tlsKey,
		AllowList:     allowList,
		BlockList:     blockList,
		CacheTTL:      cacheTTL,
		AdminToken:    adminToken,
		AuditLogFile:  auditLogFile,
	}

	scheme := "http"
	if tlsCert != "" {
		scheme = "https"
	}

	fmt.Printf("\n\033[36m◈  Falcn Registry Proxy\033[0m  v%s\n", Version)
	fmt.Printf("   Listening  → \033[4m%s://%s\033[0m\n", scheme, listen)
	fmt.Printf("   npm        → %s\n", npmUpstream)
	fmt.Printf("   PyPI       → %s\n", pypiUpstream)
	fmt.Printf("   Maven      → %s\n", mavenUpstream)
	fmt.Printf("   Go Proxy   → %s\n", goProxyUpstream)
	fmt.Printf("   Cargo      → %s\n", cargoUpstream)
	fmt.Printf("   Block      → severity >= %s\n", blockSeverity)
	fmt.Printf("   Warn       → severity >= %s\n", warnSeverity)
	if adminToken != "" {
		fmt.Printf("   Auth      → admin API protected with bearer token\n")
	} else {
		fmt.Printf("   Auth      → admin API UNPROTECTED (set --admin-token for production)\n")
	}
	if auditLogFile != "" {
		fmt.Printf("   Audit Log  → %s\n", auditLogFile)
	}
	fmt.Printf("   Admin API  → \033[4m%s://%s/api/v1/\033[0m\n\n", scheme, listen)

	p := proxy.NewRegistryProxy(proxyCfg, engine)
	return p.Start(listen)
}
