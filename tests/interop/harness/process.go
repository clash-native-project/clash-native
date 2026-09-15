package harness

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Process owns a child process and captures both output streams until it exits.
type Process struct {
	cmd *exec.Cmd

	outputMu sync.RWMutex
	stdout   bytes.Buffer
	stderr   bytes.Buffer

	done      chan struct{}
	resultMu  sync.RWMutex
	resultErr error
}

func Start(ctx context.Context, executable string, args ...string) (*Process, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("create stderr pipe: %w", err)
	}

	process := &Process{cmd: cmd, done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %q: %w", executable, err)
	}

	stdoutDone := make(chan struct{})
	stderrDone := make(chan struct{})
	go capture(stdout, &process.stdout, &process.outputMu, stdoutDone)
	go capture(stderr, &process.stderr, &process.outputMu, stderrDone)
	go func() {
		err := cmd.Wait()
		<-stdoutDone
		<-stderrDone
		process.resultMu.Lock()
		process.resultErr = err
		process.resultMu.Unlock()
		close(process.done)
	}()

	return process, nil
}

func capture(reader io.Reader, buffer *bytes.Buffer, mutex *sync.RWMutex, done chan<- struct{}) {
	defer close(done)
	_, _ = io.Copy(lockedBuffer{buffer: buffer, mutex: mutex}, reader)
}

type lockedBuffer struct {
	buffer *bytes.Buffer
	mutex  *sync.RWMutex
}

func (b lockedBuffer) Write(data []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.Write(data)
}

func (p *Process) Wait(ctx context.Context) error {
	select {
	case <-p.done:
		p.resultMu.RLock()
		defer p.resultMu.RUnlock()
		return p.resultErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Process) Stop(ctx context.Context) error {
	select {
	case <-p.done:
		return p.Wait(ctx)
	default:
	}

	if err := p.cmd.Process.Kill(); err != nil {
		select {
		case <-p.done:
		default:
			return fmt.Errorf("kill process: %w", err)
		}
	}

	err := p.Wait(ctx)
	if _, killed := err.(*exec.ExitError); killed {
		return nil
	}
	return err
}

func (p *Process) Output() (stdout string, stderr string) {
	p.outputMu.RLock()
	defer p.outputMu.RUnlock()
	return p.stdout.String(), p.stderr.String()
}

func WaitForLine(ctx context.Context, process *Process, prefix string) (string, error) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for {
		stdout, stderr := process.Output()
		scanner := bufio.NewScanner(strings.NewReader(stdout))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, prefix) {
				return line, nil
			}
		}

		select {
		case <-process.done:
			return "", fmt.Errorf("process exited before readiness; stdout=%q stderr=%q", stdout, stderr)
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}
