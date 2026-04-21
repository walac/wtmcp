// Package sandbox wraps go-arapuca to provide OS-level isolation
// for plugin handler processes. All plugins are sandboxed unconditionally
// (configurable only via sandbox.enabled for development).
//
// Sandbox profiles are derived from plugin manifests — plugins have
// no control over their own security policy.
package sandbox

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/LeGambiArt/wtmcp/internal/config"
	arapuca "github.com/sergio-correia/go-arapuca"
)

// PluginInfo holds the plugin metadata needed to build a sandbox
// profile. Avoids importing internal/plugin (circular dependency).
type PluginInfo struct {
	Name            string
	Dir             string
	Handler         string
	CredentialGroup string
}

// Manager manages sandboxed plugin process lifecycles.
type Manager struct {
	sb      *arapuca.Sandbox
	cfg     config.SandboxConfig
	credDir string
	dataDir string
}

// NewManager creates a sandbox manager. credDir is the base
// credentials directory; dataDir is the base persistent data
// directory (e.g., ~/.local/share/wtmcp/data).
func NewManager(cfg config.SandboxConfig, credDir, dataDir string) (*Manager, error) {
	sb, err := arapuca.New()
	if err != nil {
		return nil, fmt.Errorf("create sandbox: %w", err)
	}
	return &Manager{sb: sb, cfg: cfg, credDir: credDir, dataDir: dataDir}, nil
}

// Close releases the sandbox resources.
func (m *Manager) Close() {
	if m.sb != nil {
		m.sb.Close()
	}
}

// Enabled returns whether sandboxing is active.
func (m *Manager) Enabled() bool {
	return m.cfg.SandboxEnabled()
}

// BuildProfile constructs an arapuca Profile from plugin metadata
// and server configuration. The profile grants:
//   - Read: plugin dir, credential dir, system libs, /proc/self, devices
//   - Write: per-plugin tmpdir and datadir
//   - Network: isolated (UseNetNS=true, all traffic via core proxy)
//   - Resources: memory, CPU, PIDs, file size from config
func (m *Manager) BuildProfile(info PluginInfo) arapuca.Profile {
	limits := m.limitsFor(info.Name)

	read := systemReadPaths()
	read = append(read, info.Dir)

	if m.credDir != "" && info.CredentialGroup != "" {
		groupDir := filepath.Join(m.credDir, info.CredentialGroup)
		read = append(read, groupDir)
	}

	if isPython(info.Handler) {
		read = append(read, pythonReadPaths()...)
	}

	tmpDir := m.TmpDir(info.Name)
	dataDir := m.DataDir(info.Name)

	return arapuca.Profile{
		ReadPaths:     read,
		WritePaths:    []string{tmpDir, dataDir},
		MaxMemoryMB:   limits.MaxMemoryMB,
		MaxCPUPct:     limits.MaxCPUPct,
		MaxPIDs:       limits.MaxPIDs,
		MaxFileSizeMB: limits.MaxFileSizeMB,
		UseNetNS:      true,
	}
}

// PrepareDirs creates the per-plugin tmpdir and datadir with 0700
// permissions. Returns the paths. Safe to call multiple times.
func (m *Manager) PrepareDirs(pluginName string) (tmpDir, dataDir string, err error) {
	tmpDir = m.TmpDir(pluginName)
	dataDir = m.DataDir(pluginName)

	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create tmpdir: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create datadir: %w", err)
	}
	return tmpDir, dataDir, nil
}

// CleanupTmpDir removes the per-plugin tmpdir.
func (m *Manager) CleanupTmpDir(pluginName string) {
	if err := os.RemoveAll(m.TmpDir(pluginName)); err != nil {
		log.Printf("[%s] cleanup tmpdir: %v", pluginName, err)
	}
}

// TmpDir returns the per-plugin temporary directory path.
func (m *Manager) TmpDir(pluginName string) string {
	return filepath.Join(os.TempDir(), "wtmcp", pluginName)
}

// DataDir returns the per-plugin persistent data directory path.
func (m *Manager) DataDir(pluginName string) string {
	return filepath.Join(m.dataDir, pluginName)
}

// Launch starts a sandboxed process for the given plugin. Returns
// a Process with stdin/stdout/stderr pipes for the parent.
func (m *Manager) Launch(ctx context.Context, info PluginInfo, env map[string]string) (*Process, error) {
	profile := m.BuildProfile(info)
	tmpDir, _, err := m.PrepareDirs(info.Name)
	if err != nil {
		return nil, err
	}

	pipes, err := newPipeSet()
	if err != nil {
		return nil, err
	}

	if env == nil {
		env = make(map[string]string)
	}
	env["TMPDIR"] = tmpDir

	cfg := arapuca.Config{
		Profile: profile,
		TaskID:  sanitizeTaskID(info.Name),
		WorkDir: info.Dir,
		Stdin:   pipes.stdinR,
		Stdout:  pipes.stdoutW,
		Stderr:  pipes.stderrW,
		Env:     env,
	}

	handlerPath := filepath.Join(info.Dir, info.Handler)
	proc, err := m.sb.Launch(ctx, cfg, handlerPath, nil, nil)
	if err != nil {
		pipes.closeAll()
		return nil, err
	}

	pipes.closeChildSide()

	return &Process{
		proc:   proc,
		stdin:  pipes.stdinW,
		stdout: pipes.stdoutR,
		stderr: pipes.stderrR,
		name:   info.Name,
	}, nil
}

// limitsFor returns resource limits for a plugin, with per-plugin
// overrides merged on top of defaults.
func (m *Manager) limitsFor(pluginName string) config.SandboxResourceLimits {
	limits := m.cfg.Defaults
	if override, ok := m.cfg.Plugins[pluginName]; ok {
		if override.MaxMemoryMB > 0 {
			limits.MaxMemoryMB = override.MaxMemoryMB
		}
		if override.MaxCPUPct > 0 {
			limits.MaxCPUPct = override.MaxCPUPct
		}
		if override.MaxPIDs > 0 {
			limits.MaxPIDs = override.MaxPIDs
		}
		if override.MaxFileSizeMB > 0 {
			limits.MaxFileSizeMB = override.MaxFileSizeMB
		}
	}
	return limits
}

// sanitizeTaskID converts a plugin name to a valid arapuca task ID.
// Arapuca allows [a-zA-Z0-9-] only; underscores are replaced with hyphens.
func sanitizeTaskID(name string) string {
	return strings.ReplaceAll(name, "_", "-")
}

func isPython(handler string) bool {
	return strings.HasSuffix(handler, ".py")
}

func systemReadPaths() []string {
	paths := []string{
		"/usr",
		"/lib",
		"/etc/ssl/certs",
		"/proc/self",
		"/dev/null",
		"/dev/urandom",
		"/dev/zero",
	}
	if runtime.GOOS == "linux" {
		paths = append(paths, "/lib64", "/etc/pki")
	}
	return paths
}

func pythonReadPaths() []string {
	interp, err := exec.LookPath("python3")
	if err != nil {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(interp)
	if err != nil {
		return []string{interp}
	}
	return []string{resolved, filepath.Dir(resolved)}
}

// Process wraps an arapuca sandboxed process, providing the parent-
// side pipes and lifecycle methods.
type Process struct {
	proc   *arapuca.Process
	stdin  *os.File
	stdout *os.File
	stderr *os.File
	name   string
}

// Stdin returns the write end of the child's stdin pipe.
func (p *Process) Stdin() io.WriteCloser { return p.stdin }

// Stdout returns the read end of the child's stdout pipe.
func (p *Process) Stdout() io.ReadCloser { return p.stdout }

// Stderr returns the read end of the child's stderr pipe.
func (p *Process) Stderr() io.ReadCloser { return p.stderr }

// Wait waits for the sandboxed process to exit. Returns the exit code.
func (p *Process) Wait() (int, error) { return p.proc.Wait() }

// PID returns the sandboxed process ID.
func (p *Process) PID() int { return p.proc.PID() }

// ResourceStats returns cgroup v2 resource usage. Must be called
// after Wait() and before Cleanup().
func (p *Process) ResourceStats() arapuca.ResourceUsage {
	return p.proc.ResourceStats()
}

// OOMCount returns the number of OOM kills detected.
func (p *Process) OOMCount() int {
	return p.proc.OOMCount()
}

// Cleanup releases cgroup, tmpdir, and other kernel resources.
// Must be called after Wait(). Safe to call multiple times.
func (p *Process) Cleanup() {
	p.proc.Cleanup()
}

// pipeSet holds the six FDs for stdin/stdout/stderr pipe pairs.
type pipeSet struct {
	stdinR, stdinW   *os.File
	stdoutR, stdoutW *os.File
	stderrR, stderrW *os.File
}

func newPipeSet() (*pipeSet, error) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		closeFDs(stdinR, stdinW)
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		closeFDs(stdinR, stdinW, stdoutR, stdoutW)
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	return &pipeSet{stdinR, stdinW, stdoutR, stdoutW, stderrR, stderrW}, nil
}

func (p *pipeSet) closeAll() {
	closeFDs(p.stdinR, p.stdinW, p.stdoutR, p.stdoutW, p.stderrR, p.stderrW)
}

func (p *pipeSet) closeChildSide() {
	closeFDs(p.stdinR, p.stdoutW, p.stderrW)
}

func closeFDs(fds ...*os.File) {
	for _, f := range fds {
		f.Close() //nolint:errcheck,gosec // best effort cleanup
	}
}
