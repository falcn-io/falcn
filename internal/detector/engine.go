// Package detector provides typosquatting and threat detection algorithms.
package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/falcn-io/falcn/internal/config"
	"github.com/falcn-io/falcn/pkg/types"
	redis "github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

type Options struct {
	SimilarityThreshold float64
	DeepAnalysis        bool
}

type Engine struct {
	enhancedDetector *EnhancedTyposquattingDetector
	popularCache     *PopularCache
	maxPopular       int
}

func New(cfg *config.Config) *Engine {
	ttl := time.Duration(0)
	max := 25
	if cfg != nil && cfg.TypoDetection != nil {
		if cfg.Cache != nil && cfg.Cache.TTL > 0 {
			ttl = cfg.Cache.TTL
		}
	}
	if d := viper.GetDuration("detector.popular_ttl"); d > 0 {
		ttl = d
	}
	if ttl == 0 {
		ttl = time.Hour
	}
	var cache *PopularCache
	useRedis := viper.GetBool("redis.enabled") && ttl > 0
	if useRedis {
		addr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)
		rdb := redis.NewClient(&redis.Options{Addr: addr, Password: cfg.Redis.Password, DB: cfg.Redis.Database})
		cache = NewPopularCacheWithRedis(ttl, rdb)
	} else {
		cache = NewPopularCache(ttl)
	}
	// Backoff and NPM bias config
	if ss := viper.GetStringSlice("detector.backoff_schedule"); len(ss) > 0 {
		var durs []time.Duration
		for _, s := range ss {
			if dur, err := time.ParseDuration(s); err == nil {
				durs = append(durs, dur)
			}
		}
		if len(durs) > 0 {
			cache.SetBackoffs(durs)
		}
	}
	if att := viper.GetInt("detector.backoff_attempts"); att > 0 {
		cache.SetAttempts(att)
	}
	cache.SetNPMWeights(viper.GetFloat64("detector.npm_quality_weight"), viper.GetFloat64("detector.npm_popularity_weight"), viper.GetFloat64("detector.npm_maintenance_weight"))
	return &Engine{
		enhancedDetector: NewEnhancedTyposquattingDetector(),
		popularCache:     cache,
		maxPopular:       max,
	}
}

func (e *Engine) Version() string { return "1.0.0" }

type CheckPackageResult struct {
	Name     string
	Threats  []types.Threat
	Warnings []types.Warning
}

func (e *Engine) CheckPackage(ctx context.Context, name, registry string) (*CheckPackageResult, error) {
	// Select popular packages based on registry for better coverage
	if e.popularCache != nil {
		// Allow per-request override via context
		reqMax := e.maxPopular
		if ov := maxPopularFromContext(ctx); ov > 0 {
			reqMax = ov
		}
		popularPackages := e.popularCache.Get(registry, reqMax)
		curated := getPopularByRegistry(registry)
		// Union curated with dynamic to ensure coverage of well-known names
		m := map[string]struct{}{}
		for _, p := range popularPackages {
			m[p] = struct{}{}
		}
		for _, c := range curated {
			if _, ok := m[c]; !ok {
				popularPackages = append(popularPackages, c)
			}
		}
		if len(popularPackages) == 0 {
			popularPackages = curated
		}
		// use popularPackages below
		dep := types.Dependency{
			Name:     name,
			Version:  "unknown",
			Registry: registry,
		}
		threats, warnings := e.AnalyzeDependency(dep, popularPackages, &Options{
			SimilarityThreshold: 0.75,
			DeepAnalysis:        true,
		})
		return &CheckPackageResult{Name: name, Threats: threats, Warnings: warnings}, nil
	}
	popularPackages := getPopularByRegistry(registry)

	// Create a dependency for analysis
	dep := types.Dependency{
		Name:     name,
		Version:  "unknown",
		Registry: registry,
	}

	threats, warnings := e.AnalyzeDependency(dep, popularPackages, &Options{
		SimilarityThreshold: 0.75,
		DeepAnalysis:        true,
	})

	return &CheckPackageResult{
		Name:     name,
		Threats:  threats,
		Warnings: warnings,
	}, nil
}

// cfgFromContext placeholder (not used)
type ctxKey int

const detectorCfgKey ctxKey = iota

func WithConfig(ctx context.Context, cfg *config.Config) context.Context {
	return context.WithValue(ctx, detectorCfgKey, cfg)
}
func cfgFromContext(ctx context.Context) *config.Config {
	if v := ctx.Value(detectorCfgKey); v != nil {
		if c, ok := v.(*config.Config); ok {
			return c
		}
	}
	return nil
}

// Optional per-request override for max popular candidates
type ctxMaxKey int

const maxPopularKey ctxMaxKey = iota

func WithMaxPopular(ctx context.Context, n int) context.Context {
	return context.WithValue(ctx, maxPopularKey, n)
}
func maxPopularFromContext(ctx context.Context) int {
	if v := ctx.Value(maxPopularKey); v != nil {
		if n, ok := v.(int); ok {
			return n
		}
	}
	return 0
}

// popularPackagesData holds the loaded popular packages
var popularPackagesData map[string][]string
var popularPackagesLoaded bool

// embeddedPopularPackagesJSON is set by the main package via SetEmbeddedPopularPackages.
// When non-empty it acts as the primary source, replacing the on-disk file lookup.
var embeddedPopularPackagesJSON []byte

// SetEmbeddedPopularPackages injects the compile-time embedded popular_packages.json.
// Call this from an init() in package main before any scan runs.
func SetEmbeddedPopularPackages(data []byte) {
	if len(data) > 0 {
		embeddedPopularPackagesJSON = data
		popularPackagesLoaded = false // force reload from embedded data
	}
}

// loadPopularPackages loads popular packages from the JSON file
func loadPopularPackages() {
	if popularPackagesLoaded {
		return
	}

	// Try embedded data first (set by main package via SetEmbeddedPopularPackages).
	if len(embeddedPopularPackagesJSON) > 0 {
		var loadedData map[string][]string
		if err := json.Unmarshal(embeddedPopularPackagesJSON, &loadedData); err == nil && len(loadedData) > 0 {
			popularPackagesData = loadedData
			popularPackagesLoaded = true
			return
		}
	}

	// Default hardcoded data as fallback
	popularPackagesData = map[string][]string{
		"npm":      {"react", "lodash", "express", "axios", "webpack", "babel", "eslint", "typescript", "jquery", "moment", "next", "vue", "angular", "rxjs", "vite", "rollup", "yarn", "pnpm", "mocha", "jest", "chai", "sinon", "cross-env", "nodemon", "pm2"},
		"pypi":     {"requests", "numpy", "pandas", "django", "flask", "tensorflow", "pytorch", "scikit-learn", "matplotlib", "pillow", "beautifulsoup4", "selenium", "pytest", "black", "flake8", "click", "jinja2", "sqlalchemy", "fastapi", "pydantic", "boto3", "redis", "celery", "gunicorn", "uvicorn", "httpx", "aiohttp", "typing-extensions", "setuptools", "wheel", "pip", "certifi", "urllib3", "charset-normalizer"},
		"rubygems": {"rails", "bundler", "rake", "rspec", "puma", "nokogiri", "devise", "activerecord", "activesupport", "thor", "json", "minitest", "rack", "sinatra", "capistrano", "sidekiq", "redis", "pg", "mysql2", "sqlite3", "faraday", "httparty", "factory_bot", "rubocop", "pry"},
		"maven":    {"org.springframework:spring-core", "org.springframework:spring-boot-starter", "junit:junit", "org.apache.commons:commons-lang3", "com.google.guava:guava", "org.slf4j:slf4j-api", "ch.qos.logback:logback-classic", "com.fasterxml.jackson.core:jackson-core", "org.apache.httpcomponents:httpclient", "org.hibernate:hibernate-core", "org.mockito:mockito-core", "org.apache.maven.plugins:maven-compiler-plugin", "org.springframework.boot:spring-boot-starter-web", "org.springframework.boot:spring-boot-starter-data-jpa", "mysql:mysql-connector-java", "org.postgresql:postgresql", "redis.clients:jedis", "org.apache.kafka:kafka-clients", "com.amazonaws:aws-java-sdk", "org.elasticsearch.client:elasticsearch-rest-high-level-client"},
		"nuget":    {"Newtonsoft.Json", "Microsoft.Extensions.DependencyInjection", "Microsoft.Extensions.Logging", "Microsoft.EntityFrameworkCore", "AutoMapper", "Serilog", "FluentValidation", "Microsoft.AspNetCore.Mvc", "System.Text.Json", "Microsoft.Extensions.Configuration", "NUnit", "xunit", "Moq", "Microsoft.Extensions.Hosting", "Swashbuckle.AspNetCore", "Microsoft.EntityFrameworkCore.SqlServer", "Microsoft.AspNetCore.Authentication.JwtBearer", "StackExchange.Redis", "Polly", "MediatR"},
		"default":  {"react", "lodash", "express", "axios", "requests", "numpy", "pandas", "django", "flask", "rails", "bundler", "rake", "junit:junit", "org.apache.commons:commons-lang3"},
	}

	// Try to load from file
	// Check multiple possible locations for the data file
	paths := []string{
		"data/popular_packages.json",
		"../../data/popular_packages.json",
		"/etc/Falcn/popular_packages.json",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err == nil {
				var loadedData map[string][]string
				if err := json.Unmarshal(data, &loadedData); err == nil {
					// Merge loaded data with defaults (override)
					for k, v := range loadedData {
						popularPackagesData[k] = v
					}
					// fmt.Printf("Loaded popular packages from %s\n", path) // Debug logging
					break
				}
			}
		}
	}

	popularPackagesLoaded = true
}

// getPopularByRegistry returns curated popular package names per registry
func getPopularByRegistry(registry string) []string {
	loadPopularPackages()

	reg := strings.ToLower(registry)
	if list, ok := popularPackagesData[reg]; ok {
		return list
	}

	return popularPackagesData["default"]
}

func (e *Engine) AnalyzeDependency(dep types.Dependency, popularPackages []string, options *Options) ([]types.Threat, []types.Warning) {
	if e.enhancedDetector == nil {
		return []types.Threat{}, []types.Warning{}
	}

	// Use enhanced detector for typosquatting analysis
	threshold := 0.75 // default threshold
	if options != nil && options.SimilarityThreshold > 0 {
		threshold = options.SimilarityThreshold
	}

	threats := e.enhancedDetector.DetectEnhanced(dep, popularPackages, threshold)

	return threats, []types.Warning{}
}

type EnhancedSupplyChainDetector struct{}

func NewEnhancedSupplyChainDetector() *EnhancedSupplyChainDetector {
	return &EnhancedSupplyChainDetector{}
}

type EnhancedSupplyChainResult struct {
	Package           string
	Registry          string
	ThreatType        string
	Severity          string
	ConfidenceScore   float64
	IsFiltered        bool
	Recommendations   []string
	SupplyChainRisk   float64
	FalsePositiveRisk float64
	FilterReasons     []string
	Evidence          []string
}

// DetectThreats runs heuristic supply-chain analysis on a slice of packages.
// It detects dependency-confusion candidates, suspicious version patterns, and
// namespace-squatting indicators without making any network calls.
func (d *EnhancedSupplyChainDetector) DetectThreats(ctx context.Context, pkgs []types.Package) ([]EnhancedSupplyChainResult, error) {
	results := make([]EnhancedSupplyChainResult, 0, len(pkgs))

	for _, pkg := range pkgs {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		result := EnhancedSupplyChainResult{
			Package:           pkg.Name,
			Registry:          pkg.Registry,
			ConfidenceScore:   0,
			FalsePositiveRisk: 0.1,
		}

		var evidence []string
		score := 0.0

		// ── 1. Dependency-confusion heuristic ──────────────────────────────
		// Internal/scoped packages that also exist as public names are high-risk.
		// Signals: contains internal naming conventions, very high version numbers,
		// or a version number higher than 9 for a fresh public package.
		name := strings.ToLower(pkg.Name)

		// Unscoped package with internal-sounding name
		internalKeywords := []string{"internal", "private", "corp", "enterprise", "infra", "backend", "frontend"}
		for _, kw := range internalKeywords {
			if strings.Contains(name, kw) {
				score += 0.3
				evidence = append(evidence, fmt.Sprintf("package name contains internal keyword '%s'", kw))
				break
			}
		}

		// Very high major version for a new/unknown package (version confusion)
		if pkg.Version != "" {
			parts := strings.SplitN(pkg.Version, ".", 2)
			if len(parts) > 0 {
				major := 0
				fmt.Sscanf(parts[0], "%d", &major)
				if major >= 99 {
					score += 0.4
					evidence = append(evidence, fmt.Sprintf("unusually high major version %d (dependency-confusion indicator)", major))
				}
			}
		}

		// ── 2. Namespace-squatting heuristic ──────────────────────────────
		// Package names that differ from popular packages by one character in the scope/prefix.
		popularPrefixes := []string{"@babel", "@types", "@angular", "@react", "@vue", "@aws", "@google", "@microsoft"}
		for _, prefix := range popularPrefixes {
			if strings.HasPrefix(name, prefix) {
				// Scoped package that looks like a popular scope — only flag if it's the EXACT scope
				// but has a suspicious sub-package name.
				subPkg := strings.TrimPrefix(name, prefix+"/")
				if strings.ContainsAny(subPkg, "_-.") && len(subPkg) < 3 {
					score += 0.25
					evidence = append(evidence, fmt.Sprintf("very short sub-package name '%s' under popular scope '%s'", subPkg, prefix))
				}
			}
		}

		// ── 3. Suspicious version pattern ─────────────────────────────────
		// Version "0.0.1" or "0.0.0" as v1+ equivalent (common in supply-chain attacks
		// where attacker uploads a low version to claim the namespace then bumps quickly).
		if pkg.Version == "0.0.1" || pkg.Version == "0.0.0" || pkg.Version == "0.1.0" {
			score += 0.15
			evidence = append(evidence, fmt.Sprintf("suspiciously low initial version '%s'", pkg.Version))
		}

		// ── 4. Homoglyph / lookalike in plain name segment ────────────────
		// We check for digits substituting letters (0→o, 1→l, 3→e, 4→a, 5→s).
		homoglyphMap := map[rune]rune{'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's'}
		normalized := []rune(name)
		replaced := false
		for i, ch := range normalized {
			if sub, ok := homoglyphMap[ch]; ok {
				normalized[i] = sub
				replaced = true
			}
		}
		if replaced && string(normalized) != name {
			score += 0.2
			evidence = append(evidence, fmt.Sprintf("possible homoglyph substitution detected in '%s'", pkg.Name))
		}

		// ── Aggregate result ──────────────────────────────────────────────
		if score == 0 {
			// Clean package — still add to results so caller has full coverage
			result.IsFiltered = true
			result.FilterReasons = []string{"no supply-chain indicators detected"}
			results = append(results, result)
			continue
		}

		// Cap at 1.0
		if score > 1.0 {
			score = 1.0
		}
		result.ConfidenceScore = score
		result.SupplyChainRisk = score
		result.Evidence = evidence

		switch {
		case score >= 0.7:
			result.ThreatType = "dependency_confusion"
			result.Severity = "high"
			result.Recommendations = []string{
				"Verify this package is from a trusted publisher",
				"Check if an internal package of the same name exists in your private registry",
				"Pin the exact version and hash in your lock file",
			}
		case score >= 0.4:
			result.ThreatType = "namespace_squatting"
			result.Severity = "medium"
			result.Recommendations = []string{
				"Review package ownership and publishing history",
				"Compare with expected package metadata before use",
			}
		default:
			result.ThreatType = "suspicious_version_pattern"
			result.Severity = "low"
			result.Recommendations = []string{
				"Monitor this package for unexpected behaviour",
			}
		}

		results = append(results, result)
	}

	return results, nil
}
