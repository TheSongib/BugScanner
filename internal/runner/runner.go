package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"syscall"
	"time"

	"github.com/brandon/bugscanner/internal/ratelimit"
)

// Runner executes external security tools with rate limiting and timeouts.
type Runner struct {
	limiter        *ratelimit.Limiter
	defaultTimeout time.Duration
}

// Result holds the output of an executed command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// New creates a new command runner.
func New(limiter *ratelimit.Limiter) *Runner {
	return &Runner{
		limiter:        limiter,
		defaultTimeout: 10 * time.Minute,
	}
}

// Run executes a command with rate limiting, timeout, and optional stdin.
func (r *Runner) Run(ctx context.Context, toolName string, args []string, stdin io.Reader) (*Result, error) {
	// Wait for rate limit clearance
	if r.limiter != nil {
		if err := r.limiter.WaitTool(ctx, toolName); err != nil {
			return nil, fmt.Errorf("rate limit wait for %s: %w", toolName, err)
		}
	}

	// Apply default timeout if context has no deadline
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.defaultTimeout)
		defer cancel()
	}

	slog.Info("executing tool", "tool", toolName, "args", args)
	start := time.Now()

	cmd := exec.CommandContext(ctx, toolName, args...)
	// Create a new session so subprocesses don't inherit the worker's process group,
	// which can cause network/signal behavior differences vs docker exec.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if stdin != nil {
		cmd.Stdin = stdin
	}

	err := cmd.Run()
	duration := time.Since(start)

	result := &Result{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: duration,
	}

	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	slog.Info("tool completed",
		"tool", toolName,
		"duration", duration,
		"exit_code", result.ExitCode,
		"stdout_len", len(result.Stdout),
		"stderr_len", len(result.Stderr),
	)

	// Always log stderr if present — helps diagnose tool failures.
	if len(result.Stderr) > 0 {
		stderrStr := string(result.Stderr)
		if len(stderrStr) > 2000 {
			stderrStr = stderrStr[:2000] + "...(truncated)"
		}
		slog.Info("tool stderr", "tool", toolName, "stderr", stderrStr)
	}

	if err != nil {
		// Exit code 2 is standard for ProjectDiscovery tools meaning
		// "ran successfully but found no results" — not a real error.
		if result.ExitCode == 2 {
			slog.Info("tool found no results", "tool", toolName)
			return result, nil
		}
		return result, fmt.Errorf("execute %s: %w (stderr: %s)", toolName, err, stderr.String())
	}

	return result, nil
}

// RunWithTimeout executes a command with a specific timeout.
func (r *Runner) RunWithTimeout(ctx context.Context, toolName string, args []string, stdin io.Reader, timeout time.Duration) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return r.Run(ctx, toolName, args, stdin)
}
