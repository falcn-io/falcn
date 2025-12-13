package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// DockerSandbox implements Sandbox interface using Docker
type DockerSandbox struct {
	cli         *client.Client
	containerID string
	config      *SandboxConfig
}

type SandboxConfig struct {
	MemoryLimit int64 // Bytes
	CPUShares   int64
	NetworkMode string // "none", "bridge", etc.
}

func NewDockerSandbox(cfg *SandboxConfig) (*DockerSandbox, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	return &DockerSandbox{
		cli:    cli,
		config: cfg,
	}, nil
}

func (d *DockerSandbox) ID() string {
	return d.containerID
}

func (d *DockerSandbox) Start(ctx context.Context, image string) error {
	// 1. Pull Image (if needed)
	// For speed, assume image exists or use simple ones.
	// But robustly we should pull.
	reader, err := d.cli.ImagePull(ctx, image, types.ImagePullOptions{})
	if err == nil {
		defer reader.Close()
		io.Copy(io.Discard, reader) // Consume output
	} else {
		// Log warning but proceed, maybe we have it locally
		logrus.Warnf("Failed to pull image %s (might be local): %v", image, err)
	}

	// 2. Create Container
	containerConfig := &container.Config{
		Image:        image,
		Cmd:          []string{"tail", "-f", "/dev/null"}, // Keep running
		Tty:          false,
		OpenStdin:    false,
		AttachStdout: false,
		AttachStderr: false,
	}

	hostConfig := &container.HostConfig{
		Resources: container.Resources{
			Memory: d.config.MemoryLimit,
		},
		NetworkMode: container.NetworkMode(d.config.NetworkMode),
	}

	name := fmt.Sprintf("falcn-sandbox-%s", uuid.New().String())
	resp, err := d.cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, name)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	d.containerID = resp.ID
	logrus.Debugf("Created sandbox container %s (%s)", name, d.containerID)

	// 3. Start Container
	if err := d.cli.ContainerStart(ctx, d.containerID, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	return nil
}

func (d *DockerSandbox) Stop(ctx context.Context) error {
	if d.containerID == "" {
		return nil
	}

	// Force remove container
	err := d.cli.ContainerRemove(ctx, d.containerID, types.ContainerRemoveOptions{
		Force: true,
	})
	if err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	d.containerID = ""
	return nil
}

func (d *DockerSandbox) Execute(ctx context.Context, cmd []string, env []string) (ExecutionResult, error) {
	if d.containerID == "" {
		return ExecutionResult{}, fmt.Errorf("sandbox not started")
	}

	start := time.Now()

	// 1. Create Exec Config
	execConfig := types.ExecConfig{
		Cmd:          cmd,
		Env:          env,
		AttachStdout: true,
		AttachStderr: true,
	}

	execIDResp, err := d.cli.ContainerExecCreate(ctx, d.containerID, execConfig)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("failed to create exec: %w", err)
	}

	// 2. Attach and Run
	resp, err := d.cli.ContainerExecAttach(ctx, execIDResp.ID, types.ExecStartCheck{})
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("failed to attach exec: %w", err)
	}
	defer resp.Close()

	var outBuf, errBuf bytes.Buffer
	// Docker multiplexes stdout/stderr, stdcopy demultiplexes it
	if _, err := stdcopy.StdCopy(&outBuf, &errBuf, resp.Reader); err != nil {
		return ExecutionResult{}, fmt.Errorf("failed to read execution output: %w", err)
	}

	// 3. Inspect to get exit code
	inspectResp, err := d.cli.ContainerExecInspect(ctx, execIDResp.ID)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("failed to inspect exec: %w", err)
	}

	return ExecutionResult{
		ExitCode: inspectResp.ExitCode,
		Stdout:   outBuf.String(),
		Stderr:   errBuf.String(),
		Duration: time.Since(start),
	}, nil
}

func (d *DockerSandbox) GetLogs(ctx context.Context) (string, error) {
	if d.containerID == "" {
		return "", fmt.Errorf("sandbox not started")
	}

	out, err := d.cli.ContainerLogs(ctx, d.containerID, types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return "", err
	}
	defer out.Close()

	buf := new(bytes.Buffer)
	// Again, demultiplex if TTY was false (which it is)
	stdcopy.StdCopy(buf, buf, out)
	return buf.String(), nil
}
