package plugin

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/LeGambiArt/wtmcp/internal/config"
)

// DiscoveryOptions configures plugin discovery behavior.
type DiscoveryOptions struct {
	ConfigPath          string // Optional config file path
	WorkdirOverride     string // Optional workdir override
	SkipConfigFiltering bool   // If true, ignore plugins.enabled and plugins.disabled during discovery
}

// DiscoveryResult contains the results of plugin discovery.
type DiscoveryResult struct {
	Workdir     string
	ConfigPath  string // Resolved config file path (for write-back)
	Config      *config.Config
	EnvGroups   map[string]map[string]string
	EnvErrors   map[string]string
	EnvDirError string // env.d directory-level error, if any
	Manager     *Manager
}

// Discover performs plugin discovery without loading plugins.
// This is the common discovery logic used by CLI tools and the check command.
// For the main server runtime, use the full initialization in run().
func Discover(opts DiscoveryOptions) (*DiscoveryResult, error) {
	// Resolve workdir
	workdir := config.WorkDir()
	if opts.WorkdirOverride != "" {
		workdir = opts.WorkdirOverride
	}

	// Resolve config path (same defaulting logic as config.Load)
	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		cfgPath = filepath.Join(workdir, "config.yaml")
	}

	// Load config first so we can use cfg.EnvDir.
	cfg, err := config.Load(opts.ConfigPath, workdir)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// Load scoped env.d groups (not into process env)
	envDir := config.ResolveEnvDir(cfg, workdir)
	envResult, err := config.LoadEnvGroups(envDir)
	if err != nil {
		return nil, fmt.Errorf("load env: %w", err)
	}
	if envResult.DirError != "" {
		log.Printf("WARNING: env.d directory error: %s", envResult.DirError)
	}

	// When SkipConfigFiltering is set, temporarily clear the enabled
	// and disabled lists so all plugins end up in Manifests(). Restore
	// after discovery so the config is available to the caller.
	var savedDisabled, savedEnabled []string
	if opts.SkipConfigFiltering {
		savedDisabled = cfg.Plugins.Disabled
		savedEnabled = cfg.Plugins.Enabled
		cfg.Plugins.Disabled = nil
		cfg.Plugins.Enabled = nil
	}

	// Create manager with nil dependencies (discovery only)
	mgr := NewManager(nil, nil, nil, cfg, envResult.Groups, envResult.Errors, envResult.DirError, workdir, envDir)

	// Discover plugins (without loading/starting them)
	if err := mgr.Discover(cfg.PluginDirs, cfg.UserPluginDir); err != nil {
		return nil, fmt.Errorf("plugin discovery: %w", err)
	}

	if opts.SkipConfigFiltering {
		cfg.Plugins.Disabled = savedDisabled
		cfg.Plugins.Enabled = savedEnabled
	}

	return &DiscoveryResult{
		Workdir:     workdir,
		ConfigPath:  cfgPath,
		Config:      cfg,
		EnvGroups:   envResult.Groups,
		EnvErrors:   envResult.Errors,
		EnvDirError: envResult.DirError,
		Manager:     mgr,
	}, nil
}
