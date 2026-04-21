package handler

import (
	"encoding/json"
	"testing"
)

func TestDecodeResponseBody_RawJSON(t *testing.T) {
	raw := json.RawMessage(`{"key":"value"}`)
	body, err := decodeResponseBody(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"key":"value"}` {
		t.Errorf("got %q", body)
	}
}

func TestDecodeResponseBody_QuotedText(t *testing.T) {
	raw := json.RawMessage(`"hello world"`)
	body, err := decodeResponseBody(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello world" {
		t.Errorf("got %q", body)
	}
}

func TestDecodeResponseBody_Base64(t *testing.T) {
	raw := json.RawMessage(`"aGVsbG8="`) // base64("hello")
	body, err := decodeResponseBody(raw, "base64")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Errorf("got %q", body)
	}
}

func TestDecodeResponseBody_Empty(t *testing.T) {
	body, err := decodeResponseBody(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		t.Errorf("expected nil, got %q", body)
	}
}

func TestDecodeResponseBody_InvalidBase64(t *testing.T) {
	raw := json.RawMessage(`"not-valid-base64!!!"`)
	_, err := decodeResponseBody(raw, "base64")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}
