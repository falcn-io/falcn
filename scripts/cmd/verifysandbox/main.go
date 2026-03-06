package main

import (
	"context"
	"fmt"
	"time"

	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/internal/sandbox"
	"github.com/falcn-io/falcn/pkg/types"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	// 1. Setup Sandbox
	cfg := &sandbox.SandboxConfig{
		MemoryLimit: 512 * 1024 * 1024, // 512MB
		NetworkMode: "bridge",
	}

	sb, err := sandbox.NewDockerSandbox(cfg)
	if err != nil {
		logrus.Fatalf("Failed to create sandbox: %v", err)
	}

	// 2. Setup Behavioral Engine
	engine := detector.NewBehavioralEngine(sb)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 3. Test Case: Suspicious Package
	fmt.Println("=== Verifying Behavioral Analysis ===")
	// We use 'express' to test successful install attempt
	dep := types.Dependency{
		Name:     "express",
		Version:  "latest",
		Registry: "npm",
	}

	fmt.Println("--- Analyzing 'express' ---")
	threats, err := engine.AnalyzeBehavior(ctx, dep)
	if err != nil {
		fmt.Printf("Analysis Error (possibly expected if npm install fails): %v\n", err)
	}

	printThreats(threats)

	// 4. Manual Test of TraceAnalyzer via Sandbox
	// We want to force a "Threat".
	fmt.Println("\n--- Manual Sandbox Test (Triggering Threat) ---")
	if err := sb.Start(ctx, "node:18-alpine"); err != nil {
		logrus.Fatalf("Manual Start Failed: %v", err)
	}
	defer sb.Stop(ctx)

	// Run a command that prints keywords
	cmd := []string{"/bin/sh", "-c", "echo 'Connecting to malicious site via curl'; echo 'execve /bin/bash'"}
	res, err := sb.Execute(ctx, cmd, nil)
	if err != nil {
		logrus.Errorf("Exec failed: %v", err)
	} else {
		fmt.Printf("Exec Output via stdout: %s\n", res.Stdout)
		analyzer := sandbox.NewTraceAnalyzer()
		findings := analyzer.AnalyzeLogs(res.Stdout, res.Stderr)
		if len(findings) > 0 {
			fmt.Println("SUCCESS: Detected suspicious keywords:")
			for k, v := range findings {
				fmt.Printf(" - %s: %s\n", k, v)
			}
		} else {
			fmt.Println("FAILURE: Did not detect keywords.")
		}
	}
}

func printThreats(threats []types.Threat) {
	if len(threats) == 0 {
		fmt.Println("No behavioral threats found.")
		return
	}
	for _, t := range threats {
		fmt.Printf("Threat: %s (Severity: %s)\n", t.Type, t.Severity)
		for _, e := range t.Evidence {
			fmt.Printf(" Evidence: %s found in logs (Score: %.2f)\n", e.Value, e.Score)
		}
	}
}
