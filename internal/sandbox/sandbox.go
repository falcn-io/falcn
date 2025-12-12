package sandbox

import (
	"context"
	"time"
)

// Sandbox defines the interface for secure execution environments
type Sandbox interface {
	// Start provisions the sandbox environment
	Start(ctx context.Context, image string) error

	// Execute runs a command inside the sandbox
	Execute(ctx context.Context, cmd []string, env []string) (ExecutionResult, error)

	// Stop tears down the sandbox
	Stop(ctx context.Context) error

	// GetLogs returns the logs (stdout/stderr) from the sandbox
	GetLogs(ctx context.Context) (string, error)

	// ID returns the unique identifier of the sandbox instance
	ID() string
}

// ExecutionResult holds the result of a command execution
type ExecutionResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
}
