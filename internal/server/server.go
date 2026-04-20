// Package server wires the MCP server to the plugin manager,
// registering tools from plugin manifests and serving via stdio.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/LeGambiArt/wtmcp/internal/audit"
	"github.com/LeGambiArt/wtmcp/internal/config"
	"github.com/LeGambiArt/wtmcp/internal/encoding"

	"github.com/LeGambiArt/wtmcp/internal/plugin"
	"github.com/LeGambiArt/wtmcp/internal/pluginctx"
	"github.com/LeGambiArt/wtmcp/internal/protocol"
	"github.com/LeGambiArt/wtmcp/internal/ratelimit"
	"github.com/LeGambiArt/wtmcp/internal/stats"
)

// New creates an MCP server with tools from all loaded plugins.
// The index is used for tool_search and must be rebuilt on plugin
// reload via ReloadPlugin.
//
// When cfg.ReadOnly is true, only read-access tools are registered.
// This is immutable for the server's lifetime — ReadOnly must not be
// changed after New returns.
func New(version string, manager *plugin.Manager, cfg *config.Config, index *ToolIndex, collector *stats.Collector, auditor *audit.Logger, rateLimiter *ratelimit.Registry) *mcpserver.MCPServer {
	srv := mcpserver.NewMCPServer(
		"wtmcp",
		version,
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithResourceCapabilities(true, true),
	)

	progressive := cfg.Tools.Discovery == "progressive"

	if cfg.ReadOnly {
		log.Println("read-only mode: write tools will not be registered")
	}

	disabled := manager.DisabledPlugins()

	// Register tools from all plugin manifests. In progressive
	// mode, non-primary tools get the defer_loading flag.
	// Skip disabled plugins — they get separate registration below.
	for name, manifest := range manager.Manifests() {
		if _, isDisabled := disabled[name]; isDisabled {
			continue
		}
		outputFormat := cfg.Output.Format
		if manifest.Output.Format != "" {
			outputFormat = manifest.Output.Format
		}
		registerPluginTools(srv, manager, manifest, outputFormat, cfg.Output.ToonFallback, progressive, cfg.ReadOnly, collector, auditor, rateLimiter)
	}

	// Register disabled plugin tools with [DISABLED] descriptions
	registerDisabledPluginTools(srv, disabled, progressive, cfg.ReadOnly)

	// Register context files as MCP resources
	registerContextResources(srv, manager, collector)

	// Register resources from resource provider plugins
	RegisterPluginResources(srv, manager, collector)

	// Built-in management tools
	registerManagementTools(srv, manager, cfg, index, collector, auditor, rateLimiter)

	// tool_search — useful in both modes
	registerToolSearch(srv, index)

	return srv
}

func registerPluginTools(srv *mcpserver.MCPServer, mgr *plugin.Manager, manifest *plugin.Manifest, outputFormat string, toonFallback bool, progressive bool, readOnly bool, collector *stats.Collector, auditor *audit.Logger, rateLimiter *ratelimit.Registry) {
	var skipped int
	for _, toolDef := range manifest.Tools {
		if readOnly && !toolDef.IsReadOnly() {
			skipped++
			continue
		}

		tool, schemaJSON := buildMCPTool(toolDef, progressive)
		toolName := toolDef.Name
		format := outputFormat
		fallback := toonFallback
		plugName := manifest.Name
		isRead := toolDef.IsReadOnly()

		validator, err := plugin.CompileParamsSchema(toolName, toolDef)
		if err != nil {
			log.Printf("[%s] %v — tool disabled", plugName, err)
			skipped++
			continue
		}

		// Record schema token cost.
		if collector != nil {
			collector.RecordSchema(toolName, plugName, toolDef.Description, schemaJSON)
		}

		srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// Defense-in-depth: reject write tools even if they
			// somehow got registered in read-only mode.
			if readOnly && !isRead {
				return mcp.NewToolResultError("tool not available"), nil
			}

			ctx = audit.WithCorrelationID(ctx)
			start := time.Now()
			var inputRaw []byte
			var outputText string
			var isErr bool
			var errMsg string

			defer func() {
				if collector != nil {
					collector.Record(toolName, plugName, start,
						inputRaw, outputText, isErr)
				}
				if auditor != nil {
					auditor.ToolCall(ctx, plugName, toolName,
						inputRaw, time.Since(start), errMsg)
				}
			}()

			if d := rateLimiter.Allow(plugName); d > 0 {
				outputText = fmt.Sprintf("rate limited — retry after %s", d.Truncate(time.Millisecond))
				isErr = true
				errMsg = outputText
				return mcp.NewToolResultError(outputText), nil
			}

			_, handle := mgr.CallTool(ctx, toolName)
			if handle == nil {
				if mgr.IsLoading() {
					outputText = fmt.Sprintf("plugin for tool %s is still loading, try again shortly", toolName)
				} else {
					outputText = fmt.Sprintf("plugin for tool %s not loaded", toolName)
				}
				isErr = true
				errMsg = outputText
				return mcp.NewToolResultError(outputText), nil
			}

			params, err := json.Marshal(req.GetArguments())
			if err != nil {
				outputText = "invalid parameters: " + err.Error()
				isErr = true
				errMsg = outputText
				return mcp.NewToolResultError(outputText), nil //nolint:nilerr // MCP convention: tool errors returned as result, not Go error
			}
			inputRaw = params

			if err := validator.Validate(params); err != nil {
				outputText = err.Error()
				isErr = true
				errMsg = outputText
				return mcp.NewToolResultError(outputText), nil
			}

			callResult, err := handle.CallTool(ctx, toolName, params)
			if err != nil {
				var pluginErr *protocol.Error
				if isPluginError(err, &pluginErr) {
					outputText = fmt.Sprintf("[%s] %s", pluginErr.Code, pluginErr.Message)
				} else {
					outputText = err.Error()
				}
				isErr = true
				errMsg = outputText
				return mcp.NewToolResultError(outputText), nil
			}

			// Process post-tool actions in background
			if len(callResult.Actions) > 0 {
				go processToolActions(srv, mgr, plugName, callResult.Actions, collector)
			}

			// Apply output encoding (JSON passthrough or TOON)
			outputText = encoding.FormatResult(callResult.Result, format, fallback)
			return mcp.NewToolResultText(outputText), nil
		})
	}
	if skipped > 0 && readOnly {
		log.Printf("read-only: skipped %d write tools from %s", skipped, manifest.Name)
	}
}

func buildMCPTool(def plugin.ToolDef, progressive bool) (mcp.Tool, []byte) {
	schema := def.ParamsSchema()
	schemaJSON, _ := json.Marshal(schema)
	tool := mcp.NewToolWithRawSchema(def.Name, def.Description, schemaJSON)

	if progressive && !def.IsPrimary() {
		tool.DeferLoading = true
	}

	if def.IsReadOnly() {
		t := true
		tool.Annotations.ReadOnlyHint = &t
	} else {
		t := true
		tool.Annotations.DestructiveHint = &t
	}

	return tool, schemaJSON
}

func registerDisabledPluginTools(srv *mcpserver.MCPServer, disabled map[string]plugin.DisabledPlugin, progressive bool, readOnly bool) {
	for _, dp := range disabled {
		pluginName := dp.Name
		for _, toolDef := range dp.Manifest.Tools {
			if readOnly && !toolDef.IsReadOnly() {
				continue
			}

			tool, _ := buildMCPTool(toolDef, progressive)
			tool.Description = fmt.Sprintf(
				"[DISABLED] %s — after fixing, run plugin_reload(name=\"%s\") to enable.\n\n---\n\n%s",
				dp.Reason, pluginName, toolDef.Description,
			)

			reason := dp.Reason
			name := pluginName
			srv.AddTool(tool, func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return mcp.NewToolResultError(fmt.Sprintf(
					"[DISABLED] %s\n\nAfter fixing, run: plugin_reload(name=\"%s\")",
					reason, name,
				)), nil
			})
		}
	}
}

func registerManagementTools(srv *mcpserver.MCPServer, mgr *plugin.Manager, cfg *config.Config, index *ToolIndex, collector *stats.Collector, auditor *audit.Logger, rateLimiter *ratelimit.Registry) {
	// plugin_list: list all plugins and their status
	srv.AddTool(
		mcp.NewTool("plugin_list",
			mcp.WithDescription("List all plugins and their status (loaded, disabled)"),
		),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var plugins []map[string]any

			disabled := mgr.DisabledPlugins()
			for name, manifest := range mgr.Manifests() {
				if dp, ok := disabled[name]; ok {
					plugins = append(plugins, map[string]any{
						"name":             name,
						"status":           "disabled",
						"reason":           dp.Reason,
						"credential_group": manifest.CredentialGroup,
						"tools":            len(manifest.Tools),
					})
					continue
				}

				var primaryCount, deferredCount int
				for _, t := range manifest.Tools {
					if t.IsPrimary() {
						primaryCount++
					} else {
						deferredCount++
					}
				}
				plugins = append(plugins, map[string]any{
					"name":        name,
					"version":     manifest.Version,
					"description": manifest.Description,
					"execution":   manifest.Execution,
					"tools":       len(manifest.Tools),
					"primary":     primaryCount,
					"deferred":    deferredCount,
				})
			}
			data, _ := json.Marshal(plugins)
			return mcp.NewToolResultText(string(data)), nil
		},
	)

	// plugin_reload: reload a plugin by name (not available in read-only mode)
	if !cfg.ReadOnly {
		srv.AddTool(
			mcp.NewTool("plugin_reload",
				mcp.WithDescription("Reload a plugin by name, re-registering tools and context resources"),
				mcp.WithString("name", mcp.Required(), mcp.Description("Plugin name to reload")),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				name, ok := req.GetArguments()["name"].(string)
				if !ok || name == "" {
					return mcp.NewToolResultError("name is required"), nil
				}
				if err := ReloadPlugin(ctx, srv, mgr, cfg, name, index, collector, auditor, rateLimiter); err != nil {
					return mcp.NewToolResultError(err.Error()), nil
				}
				return mcp.NewToolResultText(fmt.Sprintf("plugin %s reloaded", name)), nil
			},
		)
	}

	// tool_stats: show tool usage stats
	if collector != nil {
		registerToolStats(srv, collector)
	}
}

// excludedTools is the set of management tools excluded from stats recording.
var excludedTools = map[string]bool{
	"tool_stats":    true,
	"plugin_list":   true,
	"plugin_reload": true,
	"tool_search":   true,
}

// ExcludedTools returns the set of tool names excluded from stats.
func ExcludedTools() map[string]bool { return excludedTools }

func registerToolStats(srv *mcpserver.MCPServer, collector *stats.Collector) {
	srv.AddTool(
		mcp.NewTool("tool_stats",
			mcp.WithDescription("Show tool usage stats: call counts, token estimates, durations, schema costs, resource reads"),
			mcp.WithString("group_by",
				mcp.Description("Group results by 'tool' (default) or 'plugin'"),
			),
			mcp.WithBoolean("include_schemas",
				mcp.Description("Include tool schema token costs (default: false)"),
			),
			mcp.WithBoolean("include_resources",
				mcp.Description("Include resource read stats (default: false)"),
			),
		),
		func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			groupBy, _ := args["group_by"].(string)
			includeSchemas, _ := args["include_schemas"].(bool)
			includeResources, _ := args["include_resources"].(bool)

			result := map[string]any{
				"tokenizer":      collector.TokenizerName(),
				"excluded_tools": excludedToolNames(),
			}

			if groupBy == "plugin" {
				result["calls"] = collector.PluginSummaries()
			} else {
				result["calls"] = collector.Summary()
			}

			if includeSchemas {
				result["schema_cost"] = collector.SchemaCost()
			}

			if includeResources {
				result["resources"] = collector.ResourceSummary()
			}

			inputTk, outputTk := collector.TotalTokens()
			totals := map[string]any{
				"total_input_tokens":  inputTk,
				"total_output_tokens": outputTk,
				"total_tokens":        inputTk + outputTk,
			}
			if includeSchemas {
				sc := collector.SchemaCost()
				totals["schema_overhead_tokens"] = sc.TotalSchemaTokens
			}
			if includeResources {
				var resTk, resReads int
				for _, r := range collector.ResourceSummary() {
					resTk += r.ContentTokens
					resReads += r.ReadCount
				}
				totals["resource_tokens"] = resTk
				totals["resource_reads"] = resReads
			}
			result["totals"] = totals

			data, _ := json.Marshal(result)
			return mcp.NewToolResultText(string(data)), nil
		},
	)
}

func excludedToolNames() []string {
	names := make([]string, 0, len(excludedTools))
	for name := range excludedTools {
		names = append(names, name)
	}
	return names
}

// ReloadPlugin reloads a plugin and re-registers its tools and context
// resources with the MCP server. The mcp-go library automatically sends
// notifications/tools/list_changed and notifications/resources/list_changed
// when tools and resources are added or deleted.
//
// The index is rebuilt to reflect manifest changes, and tool_search is
// re-registered so its CategorySummary stays current.
func ReloadPlugin(ctx context.Context, srv *mcpserver.MCPServer, mgr *plugin.Manager, cfg *config.Config, name string, index *ToolIndex, collector *stats.Collector, auditor *audit.Logger, rateLimiter *ratelimit.Registry) error {
	progressive := cfg.Tools.Discovery == "progressive"

	// Collect old tool names, context URIs, and provided resource URIs.
	// Check both loaded plugins (Manifests) and disabled plugins
	// (DisabledPlugins) so that [DISABLED] stub tools are properly
	// removed when a previously disabled plugin is re-enabled.
	var oldToolNames []string
	var oldContextURIs []string
	var oldResourceURIs []string
	if manifest, ok := mgr.Manifests()[name]; ok {
		for _, t := range manifest.Tools {
			oldToolNames = append(oldToolNames, t.Name)
		}
		for _, f := range manifest.ContextFiles {
			oldContextURIs = append(oldContextURIs, pluginctx.ResourceURI(name, f))
		}
		if manifest.ProvidesResources() {
			if handle := mgr.Handle(name); handle != nil {
				for _, r := range handle.InitialResources() {
					oldResourceURIs = append(oldResourceURIs, r.URI)
				}
			}
		}
	} else if dp, ok := mgr.DisabledPlugins()[name]; ok {
		for _, t := range dp.Manifest.Tools {
			oldToolNames = append(oldToolNames, t.Name)
		}
	}

	// Clear stats for this plugin before reload.
	if collector != nil {
		collector.RemovePluginSchemas(name)
		collector.RemovePluginResources(name)
	}

	// Reload the plugin (stops handler, re-reads manifest, restarts)
	if err := mgr.Reload(ctx, name); err != nil {
		return err
	}

	// Remove old tools, context resources, and provided resources
	if len(oldToolNames) > 0 {
		srv.DeleteTools(oldToolNames...)
	}
	if len(oldContextURIs) > 0 {
		srv.DeleteResources(oldContextURIs...)
	}
	if len(oldResourceURIs) > 0 {
		srv.DeleteResources(oldResourceURIs...)
	}

	// Re-register tools. Check disabled first — a plugin can be in
	// both m.manifests (discovered) and m.disabled (failed to load),
	// so checking manifests first would skip the disabled branch.
	if dp, ok := mgr.DisabledPlugins()[name]; ok {
		single := map[string]plugin.DisabledPlugin{name: dp}
		registerDisabledPluginTools(srv, single, progressive, cfg.ReadOnly)
	} else if manifest, ok := mgr.Manifests()[name]; ok {
		outputFormat := cfg.Output.Format
		if manifest.Output.Format != "" {
			outputFormat = manifest.Output.Format
		}
		registerPluginTools(srv, mgr, manifest, outputFormat, cfg.Output.ToonFallback, progressive, cfg.ReadOnly, collector, auditor, rateLimiter)
		registerPluginContextResources(srv, manifest, collector)
		if manifest.ProvidesResources() {
			if handle := mgr.Handle(name); handle != nil {
				registerHandleResources(srv, name, handle, collector)
			}
		}
	}

	// Rebuild tool index and re-register tool_search so the
	// CategorySummary reflects the reloaded manifest.
	index.Rebuild(mgr)
	srv.DeleteTools("tool_search")
	registerToolSearch(srv, index)

	return nil
}

// SwapStartFailedTools replaces normally-registered tools with
// [DISABLED] stubs for plugins that failed during StartPending.
// Tools are registered as normal in New() before StartPending runs;
// this function reconciles the tool list after startup completes.
//
// Call this after mgr.StartPending() returns (or after WaitLoaded).
func SwapStartFailedTools(srv *mcpserver.MCPServer, mgr *plugin.Manager, cfg *config.Config) {
	progressive := cfg.Tools.Discovery == "progressive"

	for name, dp := range mgr.DisabledPlugins() {
		// Only swap tools that are currently registered as normal
		// (not already [DISABLED]). Check the first tool's description.
		if len(dp.Manifest.Tools) == 0 {
			continue
		}
		tools := srv.ListTools()
		firstTool := dp.Manifest.Tools[0].Name
		st, exists := tools[firstTool]
		if !exists {
			continue // not registered (e.g., was disabled before New())
		}
		if strings.Contains(st.Tool.Description, "[DISABLED]") {
			continue // already a stub
		}

		// Delete normal tools and re-register as disabled stubs
		var toolNames []string
		for _, t := range dp.Manifest.Tools {
			toolNames = append(toolNames, t.Name)
		}
		srv.DeleteTools(toolNames...)

		single := map[string]plugin.DisabledPlugin{name: dp}
		registerDisabledPluginTools(srv, single, progressive, cfg.ReadOnly)
		log.Printf("swapped tools for failed plugin %s to [DISABLED] stubs", name)
	}
}

func registerContextResources(srv *mcpserver.MCPServer, mgr *plugin.Manager, collector *stats.Collector) {
	for _, manifest := range mgr.Manifests() {
		registerPluginContextResources(srv, manifest, collector)
	}
}

func registerPluginContextResources(srv *mcpserver.MCPServer, manifest *plugin.Manifest, collector *stats.Collector) {
	plugName := manifest.Name
	for _, ctxFile := range manifest.ContextFiles {
		uri := pluginctx.ResourceURI(plugName, ctxFile)
		dir := manifest.Dir
		file := ctxFile
		srv.AddResource(
			mcp.NewResource(uri, plugName+" context: "+file,
				mcp.WithResourceDescription(fmt.Sprintf("Context instructions for %s plugin", plugName)),
				mcp.WithMIMEType("text/markdown"),
			),
			func(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				content, err := pluginctx.LoadFile(dir, file)
				if err != nil {
					return nil, err
				}
				if collector != nil {
					collector.RecordResourceRead(uri, plugName, "context", content)
				}
				return []mcp.ResourceContents{
					mcp.TextResourceContents{
						URI:      uri,
						MIMEType: "text/markdown",
						Text:     content,
					},
				}, nil
			},
		)
	}
}

// processToolActions handles side effects declared in tool results.
func processToolActions(srv *mcpserver.MCPServer, mgr *plugin.Manager, pluginName string, actions []protocol.Action, collector *stats.Collector) {
	for _, action := range actions {
		switch action.Type {
		case "invalidate_resources":
			invalidatePluginResources(srv, mgr, pluginName, collector)
		default:
			log.Printf("[%s] unknown tool action: %s", pluginName, action.Type)
		}
	}
}

// invalidatePluginResources re-queries a resource provider and updates
// MCP registrations by diffing old vs new resource URIs.
func invalidatePluginResources(srv *mcpserver.MCPServer, mgr *plugin.Manager, pluginName string, collector *stats.Collector) {
	manifest, ok := mgr.Manifests()[pluginName]
	if !ok || !manifest.ProvidesResources() {
		return
	}
	handle := mgr.Handle(pluginName)
	if handle == nil {
		return
	}

	oldResources := handle.InitialResources()
	oldURIs := make(map[string]bool, len(oldResources))
	for _, r := range oldResources {
		oldURIs[r.URI] = true
	}

	newResources, err := handle.ListResources(context.Background())
	if err != nil {
		log.Printf("[%s] invalidate_resources failed: %v", pluginName, err)
		return
	}
	handle.SetResources(newResources)

	newURIs := make(map[string]bool, len(newResources))
	for _, r := range newResources {
		newURIs[r.URI] = true
	}
	var toRemove []string
	for uri := range oldURIs {
		if !newURIs[uri] {
			toRemove = append(toRemove, uri)
		}
	}
	if len(toRemove) > 0 {
		srv.DeleteResources(toRemove...)
	}

	registerHandleResources(srv, pluginName, handle, collector)

	log.Printf("[%s] invalidate_resources: %d resources (%d removed)",
		pluginName, len(newResources), len(toRemove))
}

// RegisterPluginResources registers resources from plugins that
// declare provides.resources: true. Called both during initial server
// setup and after background plugin loading completes.
func RegisterPluginResources(srv *mcpserver.MCPServer, mgr *plugin.Manager, collector *stats.Collector) {
	for name, manifest := range mgr.Manifests() {
		if !manifest.ProvidesResources() {
			continue
		}
		handle := mgr.Handle(name)
		if handle == nil {
			continue
		}
		registerHandleResources(srv, name, handle, collector)
	}
}

func registerHandleResources(srv *mcpserver.MCPServer, pluginName string, handle *plugin.Handle, collector *stats.Collector) {
	for _, res := range handle.InitialResources() {
		uri := res.URI
		mimeType := res.MIMEType
		if mimeType == "" {
			mimeType = "text/plain"
		}
		srv.AddResource(
			mcp.NewResource(uri, res.Name,
				mcp.WithResourceDescription(res.Description),
				mcp.WithMIMEType(mimeType),
			),
			func(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				content, actualMIME, err := handle.ReadResource(ctx, uri)
				if err != nil {
					return nil, fmt.Errorf("read resource %s: %w", uri, err)
				}
				if collector != nil {
					collector.RecordResourceRead(uri, pluginName, "provided", content)
				}
				return []mcp.ResourceContents{
					mcp.TextResourceContents{
						URI:      uri,
						MIMEType: actualMIME,
						Text:     content,
					},
				}, nil
			},
		)
	}
}

// isPluginError checks if the error is a protocol.Error using errors.As.
func isPluginError(err error, target **protocol.Error) bool {
	for {
		if pe, ok := err.(*protocol.Error); ok { //nolint:errorlint // checking concrete type intentionally
			*target = pe
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
}
