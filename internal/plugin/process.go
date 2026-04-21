package plugin

import (
	"context"
	"fmt"
	"github.com/LeGambiArt/wtmcp/internal/protocol"
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// State represents the plugin process lifecycle state.
type State int

// Plugin process lifecycle states.
const (
	StateUnloaded State = iota
	StateStarting
	StateRunning
	StateFailed
	StateStopping
)

// Process manages a plugin handler's OS process and transport.
type Process struct {
	cmd               *exec.Cmd
	Transport         *Transport
	manifest          *Manifest
	handler           ServiceHandler
	groupVars         map[string]string
	state             State
	Resources         []protocol.ResourceDef // resources discovered at init
	Domains           []string               // dynamic domains from init_ok
	initTimeout       time.Duration
	shutdownTimeout   time.Duration
	shutdownKillAfter time.Duration
	maxMessageSize    int
}

// ProcessConfig holds process management settings.
type ProcessConfig struct {
	InitTimeout       time.Duration
	ShutdownTimeout   time.Duration
	ShutdownKillAfter time.Duration
	MaxMessageSize    int
}

// NewProcess creates a Process for the given manifest. groupVars are
// the scoped env.d variables for this plugin's credential_group.
func NewProcess(manifest *Manifest, handler ServiceHandler, cfg ProcessConfig, groupVars map[string]string) *Process {
	return &Process{
		manifest:          manifest,
		handler:           handler,
		groupVars:         groupVars,
		state:             StateUnloaded,
		initTimeout:       cfg.InitTimeout,
		shutdownTimeout:   cfg.ShutdownTimeout,
		shutdownKillAfter: cfg.ShutdownKillAfter,
		maxMessageSize:    cfg.MaxMessageSize,
	}
}

// State returns the current process state.
func (p *Process) State() State { return p.state }

// Start launches the plugin handler process and sends init for
// persistent plugins.
func (p *Process) Start(ctx context.Context) error {
	p.state = StateStarting

	p.cmd = exec.CommandContext(ctx, p.manifest.HandlerPath()) //nolint:gosec // handler path is validated by Manifest.Validate()
	p.cmd.Dir = p.manifest.Dir
	p.cmd.Env = buildPluginEnv(p.manifest, p.groupVars)

	stdin, err := p.cmd.StdinPipe()
	if err != nil {
		p.state = StateFailed
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		p.state = StateFailed
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := p.cmd.StderrPipe()
	if err != nil {
		p.state = StateFailed
		return fmt.Errorf("stderr pipe: %w", err)
	}

	p.Transport = NewTransport(stdin, stdout, stderr, p.maxMessageSize)

	if err := p.cmd.Start(); err != nil {
		p.state = StateFailed
		return fmt.Errorf("start handler: %w", err)
	}

	// Forward stderr to core log
	go p.Transport.ForwardStderr(p.manifest.Name)

	// Start the read loop
	go p.Transport.ReadLoop(p.manifest.Name, p.manifest.Concurrency, p.handler)

	// Send init for persistent plugins
	if p.manifest.Execution == "persistent" {
		initCtx, cancel := context.WithTimeout(ctx, p.initTimeout)
		defer cancel()

		id := p.Transport.GenerateID("init")
		resp, err := p.Transport.SendAndWait(id, protocol.Message{
			Type:     protocol.TypeInit,
			Protocol: protocol.ProtocolVersion,
			Config:   p.manifest.resolvedConfig,
		})
		if err != nil {
			p.kill()
			p.state = StateFailed
			return fmt.Errorf("plugin %s init timed out: %w", p.manifest.Name, err)
		}
		_ = initCtx // consumed by SendAndWait via Transport.done
		if resp.Type == protocol.TypeInitError {
			p.kill()
			p.state = StateFailed
			errMsg := "unknown error"
			if resp.Error != nil {
				errMsg = resp.Error.Message
			}
			return fmt.Errorf("plugin %s init failed: %s", p.manifest.Name, errMsg)
		}
		p.Domains = resp.Domains
	}

	// Query resources from resource provider plugins
	if p.manifest.ProvidesResources() {
		id := p.Transport.GenerateID("res")
		resp, err := p.Transport.SendAndWait(id, protocol.Message{
			Type: protocol.TypeListResources,
		})
		if err != nil {
			p.kill()
			p.state = StateFailed
			return fmt.Errorf("plugin %s list_resources: %w", p.manifest.Name, err)
		}
		if resp.Error != nil {
			p.kill()
			p.state = StateFailed
			return fmt.Errorf("plugin %s list_resources failed: %s", p.manifest.Name, resp.Error.Message)
		}
		p.Resources = resp.Resources
		log.Printf("[%s] discovered %d resources", p.manifest.Name, len(p.Resources))
	}

	p.state = StateRunning
	return nil
}

// Stop gracefully shuts down the plugin process.
func (p *Process) Stop(ctx context.Context) error {
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}

	p.state = StateStopping

	if p.manifest.Execution == "persistent" {
		shutdownCtx, cancel := context.WithTimeout(ctx, p.shutdownTimeout)
		defer cancel()

		id := p.Transport.GenerateID("shutdown")
		_, err := p.Transport.SendAndWait(id, protocol.Message{Type: protocol.TypeShutdown})
		_ = shutdownCtx // consumed by SendAndWait
		if err != nil {
			log.Printf("[%s] shutdown timed out, sending SIGTERM", p.manifest.Name)
			return p.forceStop()
		}
	}

	return p.cmd.Wait()
}

func (p *Process) forceStop() error {
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		p.cmd.Process.Kill() //nolint:errcheck,gosec // best effort
		return p.cmd.Wait()
	}

	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-time.After(p.shutdownKillAfter):
		log.Printf("[%s] SIGTERM timed out, sending SIGKILL", p.manifest.Name)
		p.cmd.Process.Kill() //nolint:errcheck,gosec // best effort
		return p.cmd.Wait()
	}
}

func (p *Process) kill() {
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill() //nolint:errcheck,gosec // best effort
		p.cmd.Wait()         //nolint:errcheck,gosec // reap zombie
	}
}

// buildPluginEnv constructs a filtered environment for plugin processes.
// Only safe system variables are passed from the process environment.
// Plugin-specific variables come exclusively from the scoped env.d
// vars map (matched by credential_group) — never from the process
// environment.
func buildPluginEnv(manifest *Manifest, groupVars map[string]string) []string {
	allowlist := []string{
		"PATH", "HOME", "USER", "SHELL", "LANG", "TERM", "TZ", "TMPDIR",
		"XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
	}

	env := make([]string, 0, len(allowlist)+len(manifest.Env))
	for _, key := range allowlist {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}

	// Pass env vars from the plugin's credential_group env.d file.
	// When env_passthrough is "all", pass everything (for plugins
	// that discover config dynamically, like GitLab multi-instance).
	// Otherwise, only pass vars listed in the manifest's env: field.
	if manifest.EnvPassthrough == "all" {
		for key, val := range groupVars {
			env = append(env, key+"="+val)
		}
	} else {
		for _, key := range manifest.Env {
			if val, ok := groupVars[key]; ok {
				env = append(env, key+"="+val)
			}
		}
	}

	return env
}
