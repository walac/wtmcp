package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/LeGambiArt/wtmcp/internal/audit"
	"github.com/LeGambiArt/wtmcp/internal/config"
	"github.com/LeGambiArt/wtmcp/internal/plugin"
	"github.com/LeGambiArt/wtmcp/internal/ratelimit"
	"github.com/LeGambiArt/wtmcp/internal/stats"
)

// ControlWatcher monitors a control directory for external reload commands.
// External tools write command files to {workdir}/control/commands/ and
// results appear in {workdir}/control/results/.
type ControlWatcher struct {
	commandsDir string
	resultsDir  string
	pidFile     string
	infoFile    string
	srv         *mcpserver.MCPServer
	mgr         *plugin.Manager
	cfg         *config.Config
	index       *ToolIndex
	collector   *stats.Collector
	auditor     *audit.Logger
	rateLimiter *ratelimit.Registry
	stop        chan struct{}
	done        chan struct{}
}

// NewControlWatcher creates a control watcher for the given workdir.
func NewControlWatcher(workdir string, srv *mcpserver.MCPServer, mgr *plugin.Manager, cfg *config.Config, index *ToolIndex, collector *stats.Collector, auditor *audit.Logger, rateLimiter *ratelimit.Registry) *ControlWatcher {
	controlDir := filepath.Join(workdir, "control")
	return &ControlWatcher{
		commandsDir: filepath.Join(controlDir, "commands"),
		resultsDir:  filepath.Join(controlDir, "results"),
		pidFile:     filepath.Join(controlDir, "mcp.pid"),
		infoFile:    filepath.Join(controlDir, "mcp.info"),
		srv:         srv,
		mgr:         mgr,
		cfg:         cfg,
		index:       index,
		collector:   collector,
		auditor:     auditor,
		rateLimiter: rateLimiter,
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// Start creates the control directories, writes the PID file,
// and begins polling for command files.
func (w *ControlWatcher) Start() error {
	for _, dir := range []string{w.commandsDir, w.resultsDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create control dir: %w", err)
		}
	}

	if err := w.writePIDFile(); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}

	go w.pollLoop()
	log.Printf("control watcher started: %s", w.commandsDir)
	return nil
}

// Stop stops the polling loop and cleans up the PID file.
func (w *ControlWatcher) Stop() {
	close(w.stop)
	<-w.done
	_ = os.Remove(w.pidFile)
	_ = os.Remove(w.infoFile)
	log.Println("control watcher stopped")
}

func (w *ControlWatcher) pollLoop() {
	defer close(w.done)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			w.processCommands()
		}
	}
}

func (w *ControlWatcher) processCommands() {
	entries, err := os.ReadDir(w.commandsDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		w.processCommand(entry.Name())
	}
}

func (w *ControlWatcher) processCommand(filename string) {
	commandPath := filepath.Join(w.commandsDir, filename)
	commandName := strings.TrimSuffix(filename, filepath.Ext(filename))

	result := map[string]any{
		"command":   commandName,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	// Parse command: "action-plugin" or just "action"
	action, pluginName := parseCommand(commandName)

	ctx := context.Background()

	switch action {
	case "reload":
		if w.cfg.ReadOnly {
			result["status"] = "error"
			result["error"] = "reload is not available in read-only mode"
			break
		}
		switch pluginName {
		case "all", "":
			result["status"] = "success"
			var reloaded []string
			for name := range w.mgr.Manifests() {
				if err := ReloadPlugin(ctx, w.srv, w.mgr, w.cfg, name, w.index, w.collector, w.auditor, w.rateLimiter); err != nil {
					result["status"] = "partial"
					result["error"] = fmt.Sprintf("failed to reload %s: %v", name, err)
				} else {
					reloaded = append(reloaded, name)
				}
			}
			result["reloaded"] = reloaded
		default:
			if err := ReloadPlugin(ctx, w.srv, w.mgr, w.cfg, pluginName, w.index, w.collector, w.auditor, w.rateLimiter); err != nil {
				result["status"] = "error"
				result["error"] = err.Error()
			} else {
				result["status"] = "success"
				result["plugin"] = pluginName
			}
		}

	case "list":
		var plugins []string
		for name := range w.mgr.Manifests() {
			plugins = append(plugins, name)
		}
		result["status"] = "success"
		result["plugins"] = plugins

	default:
		result["status"] = "error"
		result["error"] = fmt.Sprintf("unknown command: %s", action)
	}

	// Write result
	resultData, _ := json.MarshalIndent(result, "", "  ")
	resultPath := filepath.Join(w.resultsDir, commandName+".json")
	_ = os.WriteFile(resultPath, resultData, 0o600)

	// Remove command file
	_ = os.Remove(commandPath)

	log.Printf("control: processed %s (status: %s)", commandName, result["status"])
}

func parseCommand(name string) (action, pluginName string) {
	idx := strings.IndexByte(name, '-')
	if idx < 0 {
		return name, ""
	}
	return name[:idx], name[idx+1:]
}

func (w *ControlWatcher) writePIDFile() error {
	if err := os.WriteFile(w.pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600); err != nil {
		return err
	}

	info := map[string]any{
		"pid":        os.Getpid(),
		"started_at": time.Now().UTC().Format(time.RFC3339),
		"plugins":    len(w.mgr.Manifests()),
	}
	data, _ := json.MarshalIndent(info, "", "  ")
	return os.WriteFile(w.infoFile, data, 0o600)
}
