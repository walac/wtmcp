// wtmcp is an MCP server with a language-agnostic plugin protocol.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/spf13/cobra"

	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/LeGambiArt/wtmcp/internal/auth"
	"github.com/LeGambiArt/wtmcp/internal/cache"
	"github.com/LeGambiArt/wtmcp/internal/config"
	"github.com/LeGambiArt/wtmcp/internal/plugin"
	"github.com/LeGambiArt/wtmcp/internal/proxy"
	"github.com/LeGambiArt/wtmcp/internal/server"
	"github.com/LeGambiArt/wtmcp/internal/stats"
)

// Version and BuildDate are set via ldflags at build time.
var (
	Version   = "dev"
	BuildDate = "unknown"
)

// Flags shared across root/serve/check commands.
var (
	configPath string
	workdir    string
	readOnly   bool
)

var rootCmd = &cobra.Command{
	Use:           "wtmcp",
	Short:         "MCP server with language-agnostic plugin protocol",
	Version:       Version,
	SilenceUsage:  true,
	SilenceErrors: true,
	// Default action: run the server (backward compatible with MCP clients).
	RunE: func(_ *cobra.Command, _ []string) error {
		return run()
	},
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start MCP server (default)",
	RunE: func(_ *cobra.Command, _ []string) error {
		return run()
	},
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Print diagnostic info about config and plugins",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runCheck()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		// Write to stderr to protect MCP stdio protocol.
		fmt.Fprintf(os.Stderr, "wtmcp %s (built %s)\n", Version, BuildDate)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Config file path")
	rootCmd.PersistentFlags().StringVar(&workdir, "workdir", "", "Working directory")
	rootCmd.PersistentFlags().BoolVar(&readOnly, "read-only", false, "Only register read-access tools (no write tools)")
	if err := rootCmd.MarkPersistentFlagDirname("workdir"); err != nil {
		panic(err)
	}
	if err := rootCmd.MarkPersistentFlagFilename("config", "yaml", "yml"); err != nil {
		panic(err)
	}

	// DO NOT use rootCmd.SetOut(os.Stderr) — this would break cobra's
	// hidden __complete command, which must write to stdout for shell
	// completion to work. Instead, commands that produce non-protocol
	// output (version) write to stderr explicitly.

	rootCmd.SetVersionTemplate(
		fmt.Sprintf("wtmcp %s (built %s)\n", Version, BuildDate))
	rootCmd.DisableAutoGenTag = true

	rootCmd.AddCommand(serveCmd, checkCmd, versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Resolve workdir
	wd := config.WorkDir()
	if workdir != "" {
		wd = workdir
	}

	// Load config first so we can use cfg.LogFile.
	cfg, err := config.Load(configPath, wd)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Set up file logging (from config or default path).
	logPath := cfg.LogFile
	if logPath != "" {
		logPath = config.ResolveEnvVars(logPath)
	} else {
		logPath = filepath.Join(wd, "logs", "server.log")
	}
	logsDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logsDir, 0o700); err == nil {
		if logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil { //nolint:gosec // log file in user's config dir
			log.SetOutput(logFile)
			log.SetFlags(log.LstdFlags | log.Lshortfile)
			fmt.Fprintf(os.Stderr, "wtmcp %s, log file at %s\n", Version, logPath)
		}
	}

	// Load scoped env.d groups (not into process env)
	envDir := config.ResolveEnvDir(cfg, wd)
	envResult, err := config.LoadEnvGroups(envDir)
	if err != nil {
		return fmt.Errorf("load env: %w", err)
	}
	if envResult.DirError != "" {
		msg := fmt.Sprintf("WARNING: env.d directory error, all credential plugins disabled: %s", envResult.DirError)
		log.Println(msg)
		fmt.Fprintln(os.Stderr, msg)
	}
	for group, msg := range envResult.Errors {
		log.Printf("WARNING: env group %s disabled: %s", group, msg)
	}

	// CLI flag escalates to read-only (one-way: cannot disable via CLI
	// if config.yaml enables it).
	if readOnly {
		cfg.ReadOnly = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	authReg := auth.NewRegistry()

	// Initialize Kerberos if available and not disabled.
	if slices.Contains(cfg.Providers.Disabled, "kerberos/spnego") {
		log.Println("kerberos/spnego disabled via config")
	} else if err := auth.InitKerberos(); err != nil {
		log.Printf("kerberos not available: %v", err)
	} else if auth.KerberosAvailable() {
		defer auth.CloseKerberos()
		log.Println("kerberos/spnego auth available")
	}

	cacheStore := cache.NewMemoryStore()
	httpProxy := proxy.New(nil, cfg.Plugins.MaxMessageSize, cfg.HTTP.Timeout)

	mgr := plugin.NewManager(authReg, httpProxy, cacheStore, cfg, envResult.Groups, envResult.Errors, envResult.DirError, wd, envDir)

	if err := mgr.Discover(cfg.PluginDirs, cfg.UserPluginDir); err != nil {
		return fmt.Errorf("plugin discovery: %w", err)
	}

	// Phase 1 (synchronous): resolve dependencies, load auth providers,
	// filter disabled plugins, prepare handles. After this, m.disabled
	// is fully populated and all tools can be registered.
	if err := mgr.LoadAll(ctx); err != nil {
		return fmt.Errorf("plugin loading: %w", err)
	}

	// Create stats collector if enabled.
	var collector *stats.Collector
	if cfg.Stats.Enabled {
		collector = stats.NewCollector(stats.CharsTokenizer{}, cfg.Stats.LogCalls)
		collector.SetRetentionDays(cfg.Stats.RetentionDays)
		if cfg.Stats.Persist {
			statsPath := filepath.Join(cfg.Cache.Dir, "stats.json")
			if err := collector.SetPersistPath(statsPath); err != nil {
				log.Printf("stats persistence disabled: %v", err)
			}
		}
	}

	index := server.NewToolIndex(mgr, cfg.ReadOnly)
	srv := server.New(Version, mgr, cfg, index, collector)

	// Phase 2 (background): start plugin processes. The MCP server
	// accepts requests immediately; tools for still-loading plugins
	// return "plugin still loading" until their init completes.
	go func() {
		mgr.StartPending(ctx)
		// Post-load: swap tools for plugins that failed to start
		// from normal registrations to [DISABLED] stubs, register
		// plugin-provided resources, and rebuild the tool index.
		server.SwapStartFailedTools(srv, mgr, cfg)
		server.RegisterPluginResources(srv, mgr, collector)
		index.Rebuild(mgr)
		log.Printf("all plugins loaded (%d)", len(mgr.LoadedPlugins()))
	}()

	// Start control directory watcher for external reload triggers
	controlWatcher := server.NewControlWatcher(wd, srv, mgr, cfg, index, collector)
	if err := controlWatcher.Start(); err != nil {
		log.Printf("control watcher disabled: %v", err)
	}

	go func() {
		<-ctx.Done()
		controlWatcher.Stop()
		if collector != nil {
			collector.Close()
		}
		log.Println("shutting down plugins...")
		mgr.WaitLoaded()
		mgr.ShutdownAll(context.Background())
	}()

	log.Printf("wtmcp %s starting (workdir: %s)", Version, wd)

	stdioSrv := mcpserver.NewStdioServer(srv)
	stdioSrv.SetErrorLogger(log.Default())

	err = stdioSrv.Listen(ctx, os.Stdin, os.Stdout)
	os.Stdin.Close() //nolint:errcheck,gosec // best-effort cleanup at shutdown

	// Signal-initiated shutdown is not an error.
	if err != nil && ctx.Err() != nil {
		return nil
	}
	return err
}

// runCheck prints diagnostic info about the config and discovered plugins.
func runCheck() error {
	result, err := plugin.Discover(plugin.DiscoveryOptions{
		ConfigPath:      configPath,
		WorkdirOverride: workdir,
	})
	if err != nil {
		return err
	}

	// CLI flag escalates to read-only.
	if readOnly {
		result.Config.ReadOnly = true
	}

	fmt.Printf("wtmcp %s\n", Version)
	fmt.Printf("workdir: %s\n", result.Workdir)
	if result.Config.ReadOnly {
		fmt.Printf("read-only: true (write tools will not be registered)\n")
	}
	if len(result.Config.Plugins.Enabled) > 0 {
		fmt.Printf("plugin mode: allowlist (%d plugins)\n", len(result.Config.Plugins.Enabled))
	} else {
		fmt.Printf("plugin mode: default\n")
	}
	fmt.Printf("user plugins: %v\n", result.Config.Plugins.UserPlugins)
	fmt.Printf("env groups: %d\n", len(result.EnvGroups))
	for group := range result.EnvGroups {
		fmt.Printf("  - %s\n", group)
	}
	if result.EnvDirError != "" {
		fmt.Printf("env.d directory error: %s\n", result.EnvDirError)
	}
	if len(result.EnvErrors) > 0 {
		fmt.Printf("env group errors: %d\n", len(result.EnvErrors))
		for group, msg := range result.EnvErrors {
			fmt.Printf("  - %s: %s\n", group, msg)
		}
	}
	fmt.Printf("\nplugin search path:\n")
	for i, dir := range result.Config.PluginDirs {
		exists := "missing"
		if info, statErr := os.Stat(dir); statErr == nil && info.IsDir() {
			exists = "ok"
		}
		fmt.Printf("  %d. %s [%s]\n", i+1, dir, exists)
	}

	manifests := result.Manager.Manifests()
	fmt.Printf("\ndiscovered plugins: %d\n", len(manifests))
	var totalPrimary, totalDeferred int
	for _, m := range manifests {
		var primaryCount, deferredCount int
		for _, t := range m.Tools {
			if t.IsPrimary() {
				primaryCount++
			} else {
				deferredCount++
			}
		}
		totalPrimary += primaryCount
		totalDeferred += deferredCount
		fmt.Printf("  - %s v%s (%s)\n", m.Name, m.Version, m.Dir)
		fmt.Printf("    handler: %s | execution: %s | tools: %d (primary: %d, deferred: %d)\n",
			m.Handler, m.Execution, len(m.Tools), primaryCount, deferredCount)
	}

	fmt.Printf("\ntool discovery: %s\n", result.Config.Tools.Discovery)
	fmt.Printf("primary tools: %d\n", totalPrimary)
	fmt.Printf("deferred tools: %d\n", totalDeferred)

	if len(manifests) == 0 {
		fmt.Println("\nno plugins found. check that plugin directories contain")
		fmt.Println("subdirectories with plugin.yaml files.")
	}

	return nil
}
