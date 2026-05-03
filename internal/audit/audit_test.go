package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestWithCorrelationID(t *testing.T) {
	ctx := context.Background()
	if id := CorrelationID(ctx); id != "" {
		t.Fatalf("expected empty, got %q", id)
	}

	ctx = WithCorrelationID(ctx)
	id := CorrelationID(ctx)
	if id == "" {
		t.Fatal("expected non-empty correlation ID")
	}
	if len(id) != 36 {
		t.Fatalf("expected UUID length 36, got %d: %q", len(id), id)
	}

	ctx2 := WithCorrelationID(ctx)
	id2 := CorrelationID(ctx2)
	if id2 == id {
		t.Fatal("expected different correlation IDs")
	}
}

func TestScrubberFieldNames(t *testing.T) {
	s := NewScrubber(DefaultScrubFields)

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "scrub password",
			input: `{"username":"alice","password":"s3cret"}`,
			want:  `{"password":"[REDACTED]","username":"alice"}`,
		},
		{
			name:  "scrub api_key",
			input: `{"api_key":"abc123","query":"test"}`,
			want:  `{"api_key":"[REDACTED]","query":"test"}`,
		},
		{
			name:  "case insensitive",
			input: `{"API_KEY":"abc123","Password":"test"}`,
			want:  `{"API_KEY":"[REDACTED]","Password":"[REDACTED]"}`,
		},
		{
			name:  "substring match",
			input: `{"jira_token_id":"tok123","name":"test"}`,
			want:  `{"jira_token_id":"[REDACTED]","name":"test"}`,
		},
		{
			name:  "nested object",
			input: `{"config":{"secret":"val"},"name":"test"}`,
			want:  `{"config":{"secret":"[REDACTED]"},"name":"test"}`,
		},
		{
			name:  "no sensitive fields",
			input: `{"name":"alice","age":30}`,
			want:  `{"name":"alice","age":30}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.ScrubJSON(json.RawMessage(tt.input))
			var gotMap, wantMap map[string]any
			if err := json.Unmarshal(got, &gotMap); err != nil {
				t.Fatalf("unmarshal got: %v", err)
			}
			if err := json.Unmarshal([]byte(tt.want), &wantMap); err != nil {
				t.Fatalf("unmarshal want: %v", err)
			}
			gotJSON, _ := json.Marshal(gotMap)
			wantJSON, _ := json.Marshal(wantMap)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("got  %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestScrubberValueHeuristics(t *testing.T) {
	s := NewScrubber(DefaultScrubFields)

	tests := []struct {
		name     string
		input    string
		redacted bool
	}{
		{
			name:     "JWT prefix",
			input:    `{"data":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"}`,
			redacted: true,
		},
		{
			name:     "high entropy base64",
			input:    `{"data":"aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw=="}`,
			redacted: true,
		},
		{
			name:     "short value not redacted",
			input:    `{"data":"hello"}`,
			redacted: false,
		},
		{
			name:     "normal text not redacted",
			input:    `{"data":"this is a normal sentence with spaces and punctuation!"}`,
			redacted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.ScrubJSON(json.RawMessage(tt.input))
			var obj map[string]any
			_ = json.Unmarshal(got, &obj)
			isRedacted := obj["data"] == "[REDACTED]"
			if isRedacted != tt.redacted {
				t.Errorf("redacted=%v, want %v (output: %s)", isRedacted, tt.redacted, got)
			}
		})
	}
}

func TestScrubberArrays(t *testing.T) {
	s := NewScrubber(DefaultScrubFields)

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "array of objects with sensitive fields",
			input: `[{"password":"s3cret","name":"alice"},{"token":"tok123","name":"bob"}]`,
			want:  `[{"password":"[REDACTED]","name":"alice"},{"token":"[REDACTED]","name":"bob"}]`,
		},
		{
			name:  "nested array in object",
			input: `{"users":[{"password":"s3cret"}]}`,
			want:  `{"users":[{"password":"[REDACTED]"}]}`,
		},
		{
			name:  "array without sensitive fields",
			input: `[{"name":"alice"},{"name":"bob"}]`,
			want:  `[{"name":"alice"},{"name":"bob"}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.ScrubJSON(json.RawMessage(tt.input))
			var gotAny, wantAny any
			_ = json.Unmarshal(got, &gotAny)
			_ = json.Unmarshal([]byte(tt.want), &wantAny)
			gotJSON, _ := json.Marshal(gotAny)
			wantJSON, _ := json.Marshal(wantAny)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("got  %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestScrubString(t *testing.T) {
	s := NewScrubber(DefaultScrubFields)

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "JWT in error message",
			input: "auth failed for token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
			want:  "auth failed for token [REDACTED]",
		},
		{
			name:  "high entropy string in error",
			input: "connection failed with key abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
			want:  "connection failed with key [REDACTED]",
		},
		{
			name:  "normal error message unchanged",
			input: "plugin jira not loaded",
			want:  "plugin jira not loaded",
		},
		{
			name:  "entire string is JWT",
			input: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
			want:  "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.ScrubString(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScrubberInvalidJSON(t *testing.T) {
	s := NewScrubber(DefaultScrubFields)
	input := json.RawMessage(`not json`)
	got := s.ScrubJSON(input)
	if string(got) != string(input) {
		t.Errorf("expected passthrough for invalid JSON, got %s", got)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("got %q", got)
	}
	if got := truncate("this is a longer string", 10); got != "this is a ..." {
		t.Errorf("got %q", got)
	}
}

func TestNewDisabled(t *testing.T) {
	l, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	// Should not panic on disabled logger.
	l.ToolCall(context.Background(), "test", "tool", nil, 0, "")
	l.HTTPRequest(context.Background(), "test", "GET", "example.com", "/api", 200, 100)
}

func TestIsHighEntropy(t *testing.T) {
	if isHighEntropy("hello") {
		t.Error("short string should not be high entropy")
	}
	if !isHighEntropy("abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Error("alnum string should be high entropy")
	}
	if isHighEntropy("this has spaces and punctuation!!!???") {
		t.Error("natural text should not be high entropy")
	}
}

func TestFieldScrubber_SkipsValueHeuristics(t *testing.T) {
	s := NewFieldScrubber([]string{"password", "api_key"})

	// JWT-shaped value in a non-sensitive field should NOT be redacted.
	jwt := `{"data":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}`
	result := s.ScrubJSON(json.RawMessage(jwt))
	if string(result) != jwt {
		t.Errorf("field scrubber should not redact JWT in non-sensitive field, got: %s", result)
	}

	// High-entropy value in a non-sensitive field should NOT be redacted.
	entropy := `{"request_id":"550e8400e29b41d4a716446655440000aabbccdd"}`
	result = s.ScrubJSON(json.RawMessage(entropy))
	if string(result) != entropy {
		t.Errorf("field scrubber should not redact high-entropy non-sensitive field, got: %s", result)
	}

	// Sensitive field name should still be redacted.
	sensitive := `{"password":"hunter2","api_key":"sk-live-abc123"}`
	result = s.ScrubJSON(json.RawMessage(sensitive))
	var obj map[string]string
	if err := json.Unmarshal(result, &obj); err != nil {
		t.Fatalf("failed to unmarshal scrubbed result: %v", err)
	}
	if obj["password"] != "[REDACTED]" {
		t.Errorf("password should be redacted, got: %s", obj["password"])
	}
	if obj["api_key"] != "[REDACTED]" {
		t.Errorf("api_key should be redacted, got: %s", obj["api_key"])
	}
}

func TestNewScrubber_StillScrubbsValues(t *testing.T) {
	s := NewScrubber([]string{"password"})

	// JWT in non-sensitive field SHOULD be redacted by NewScrubber.
	jwt := `{"data":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}`
	result := s.ScrubJSON(json.RawMessage(jwt))
	var obj map[string]string
	if err := json.Unmarshal(result, &obj); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if obj["data"] != "[REDACTED]" {
		t.Errorf("NewScrubber should redact JWT values, got: %s", obj["data"])
	}
}

func TestScrubberArrayStringValues(t *testing.T) {
	s := NewScrubber([]string{"password"})
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

	t.Run("bare JWT in array", func(t *testing.T) {
		input := json.RawMessage(fmt.Sprintf(`["%s"]`, jwt))
		result := s.ScrubJSON(input)
		var arr []string
		if err := json.Unmarshal(result, &arr); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if arr[0] != "[REDACTED]" {
			t.Errorf("expected [REDACTED], got %s", arr[0])
		}
	})

	t.Run("mixed safe and sensitive", func(t *testing.T) {
		input := json.RawMessage(fmt.Sprintf(`["hello", "%s", "world"]`, jwt))
		result := s.ScrubJSON(input)
		var arr []string
		if err := json.Unmarshal(result, &arr); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if arr[0] != "hello" {
			t.Errorf("safe value changed: %s", arr[0])
		}
		if arr[1] != "[REDACTED]" {
			t.Errorf("JWT not redacted: %s", arr[1])
		}
		if arr[2] != "world" {
			t.Errorf("safe value changed: %s", arr[2])
		}
	})

	t.Run("nested array in object", func(t *testing.T) {
		input := json.RawMessage(fmt.Sprintf(`{"tokens":["%s"]}`, jwt))
		result := s.ScrubJSON(input)
		var obj map[string][]string
		if err := json.Unmarshal(result, &obj); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if obj["tokens"][0] != "[REDACTED]" {
			t.Errorf("nested JWT not redacted: %s", obj["tokens"][0])
		}
	})
}
