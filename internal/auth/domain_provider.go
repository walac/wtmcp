package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// DomainProvider routes auth to per-domain sub-providers based on
// the request's target hostname. Used for multi-instance plugins
// where different domains require different tokens (e.g., GitLab
// with gitlab.com and gitlab.internal.example.com).
//
// Bearer-only: each sub-provider is a BearerProvider sharing the
// same header and prefix but with a domain-specific token.
type DomainProvider struct {
	bindings map[string]Provider
}

// NewDomainProvider creates a provider that dispatches auth based
// on request domain. The bindings map lowercase domain names to
// their auth providers. Returns an error if bindings is empty.
func NewDomainProvider(bindings map[string]Provider) (*DomainProvider, error) {
	if len(bindings) == 0 {
		return nil, fmt.Errorf("domain provider requires at least one binding")
	}
	lower := make(map[string]Provider, len(bindings))
	for domain, provider := range bindings {
		lower[strings.ToLower(domain)] = provider
	}
	return &DomainProvider{bindings: lower}, nil
}

// Name returns "domain".
func (d *DomainProvider) Name() string { return "domain" }

// Available reports whether any bindings are configured.
func (d *DomainProvider) Available() bool { return len(d.bindings) > 0 }

// Authenticate selects the sub-provider matching the request's
// target domain and delegates to it. Returns an error if no
// binding exists for the domain.
func (d *DomainProvider) Authenticate(ctx context.Context, req *http.Request) (http.Header, error) {
	host := strings.ToLower(req.URL.Hostname())
	provider, ok := d.bindings[host]
	if !ok {
		return nil, fmt.Errorf("no auth binding for domain %q", host)
	}
	return provider.Authenticate(ctx, req)
}
