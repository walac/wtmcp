package auth

import (
	"context"
	"net/http"
	"testing"
)

func TestDomainProviderRouting(t *testing.T) {
	p1, _ := NewBearerProvider("token-a", "PRIVATE-TOKEN", "none")
	p2, _ := NewBearerProvider("token-b", "PRIVATE-TOKEN", "none")

	dp, err := NewDomainProvider(map[string]Provider{
		"gitlab.com":            p1,
		"gitlab.cee.redhat.com": p2,
	})
	if err != nil {
		t.Fatal(err)
	}

	req1, _ := http.NewRequestWithContext(context.Background(), "GET", "https://gitlab.com/api/v4/projects", nil)
	h1, err := dp.Authenticate(context.Background(), req1)
	if err != nil {
		t.Fatalf("Authenticate gitlab.com: %v", err)
	}
	if got := h1.Get("PRIVATE-TOKEN"); got != "token-a" {
		t.Errorf("gitlab.com token = %q, want token-a", got)
	}

	req2, _ := http.NewRequestWithContext(context.Background(), "GET", "https://gitlab.cee.redhat.com/api/v4/projects", nil)
	h2, err := dp.Authenticate(context.Background(), req2)
	if err != nil {
		t.Fatalf("Authenticate gitlab.cee.redhat.com: %v", err)
	}
	if got := h2.Get("PRIVATE-TOKEN"); got != "token-b" {
		t.Errorf("gitlab.cee.redhat.com token = %q, want token-b", got)
	}
}

func TestDomainProviderUnknownDomain(t *testing.T) {
	p, _ := NewBearerProvider("tok", "PRIVATE-TOKEN", "none")
	dp, _ := NewDomainProvider(map[string]Provider{"gitlab.com": p})

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://evil.com/api", nil)
	_, err := dp.Authenticate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for unknown domain")
	}
}

func TestDomainProviderCaseInsensitive(t *testing.T) {
	p, _ := NewBearerProvider("tok", "PRIVATE-TOKEN", "none")
	dp, _ := NewDomainProvider(map[string]Provider{"GitLab.COM": p})

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://gitlab.com/api", nil)
	h, err := dp.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got := h.Get("PRIVATE-TOKEN"); got != "tok" {
		t.Errorf("token = %q, want tok", got)
	}
}

func TestDomainProviderEmptyBindings(t *testing.T) {
	_, err := NewDomainProvider(map[string]Provider{})
	if err == nil {
		t.Fatal("expected error for empty bindings")
	}
}

func TestDomainProviderNameAvailable(t *testing.T) {
	p, _ := NewBearerProvider("tok", "PRIVATE-TOKEN", "none")
	dp, _ := NewDomainProvider(map[string]Provider{"gitlab.com": p})

	if dp.Name() != "domain" {
		t.Errorf("Name() = %q, want domain", dp.Name())
	}
	if !dp.Available() {
		t.Error("Available() should be true")
	}
}
