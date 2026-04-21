// Package handler provides helpers for writing Go plugin handlers
// that communicate with wtmcp via the JSON-lines protocol.
//
// A Go plugin handler reads messages from stdin, processes tool calls,
// and writes responses to stdout. Logging goes to stderr.
package handler

import "encoding/json"

// Message is the wire format for communication with the core.
// Fields are selectively populated based on Type.
type Message struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Protocol string `json:"protocol,omitempty"`

	// tool_call fields
	Tool   string          `json:"tool,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Config json.RawMessage `json:"config,omitempty"`

	// tool_result fields
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	Actions []Action        `json:"actions,omitempty"`

	// init_ok fields
	Domains []string `json:"domains,omitempty"`

	// resource provider fields
	URI       string        `json:"uri,omitempty"`
	Resources []ResourceDef `json:"resources,omitempty"`
	Content   string        `json:"content,omitempty"`
	MIMEType  string        `json:"mime_type,omitempty"`

	// http_request / http_response fields
	NoAuth       bool              `json:"no_auth,omitempty"`
	Method       string            `json:"method,omitempty"`
	Path         string            `json:"path,omitempty"`
	URL          string            `json:"url,omitempty"`
	Query        map[string]any    `json:"query,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         json.RawMessage   `json:"body,omitempty"`
	BodyEncoding string            `json:"body_encoding,omitempty"`
	Status       int               `json:"status,omitempty"`

	// cache fields
	Key     string          `json:"key,omitempty"`
	Value   json.RawMessage `json:"value,omitempty"`
	TTL     *int            `json:"ttl,omitempty"`
	Hit     *bool           `json:"hit,omitempty"`
	OK      *bool           `json:"ok,omitempty"`
	Deleted *bool           `json:"deleted,omitempty"`
	Keys    []string        `json:"keys,omitempty"`
	Pattern string          `json:"pattern,omitempty"`
	Count   *int            `json:"count,omitempty"`
}

// Error is a structured error from a plugin handler.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return "[" + e.Code + "] " + e.Message
}

// Message type constants (wire-compatible with core protocol).
const (
	TypeInit            = "init"
	TypeInitOK          = "init_ok"
	TypeInitError       = "init_error"
	TypeShutdown        = "shutdown"
	TypeShutdownOK      = "shutdown_ok"
	TypeToolCall        = "tool_call"
	TypeToolResult      = "tool_result"
	TypeHTTPRequest     = "http_request"
	TypeHTTPResponse    = "http_response"
	TypeCacheGet        = "cache_get"
	TypeCacheSet        = "cache_set"
	TypeCacheDel        = "cache_del"
	TypeCacheList       = "cache_list"
	TypeCacheFlush      = "cache_flush"
	TypeListResources   = "list_resources"
	TypeListResourcesOK = "list_resources_ok"
	TypeReadResource    = "read_resource"
	TypeReadResourceOK  = "read_resource_ok"
)

// ResourceDef describes a resource provided by a plugin handler.
// Must be kept in sync with internal/protocol.ResourceDef.
type ResourceDef struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mime_type,omitempty"`
}

// Action describes a side effect that should happen after a tool result.
// Must be kept in sync with internal/protocol.Action.
type Action struct {
	Type string `json:"type"`
}
