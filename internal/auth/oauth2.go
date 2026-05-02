package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// OAuth2Provider manages OAuth2 tokens with automatic refresh.
// Tokens are loaded from a file, refreshed when expired, and
// saved back with restrictive permissions (0600).
type OAuth2Provider struct {
	mu             sync.Mutex
	token          *oauth2.Token
	tokenFile      string
	credentialsDir string
	scopes         []string
	config         *oauth2.Config
	transport      http.RoundTripper
}

// NewOAuth2Provider creates an OAuth2 auth provider.
//
// tokenFile is the path to the cached token JSON file.
// credentialsFile is the path to the OAuth2 client credentials
// (client_id, client_secret, etc.).
// scopes are the OAuth2 scopes to request.
func NewOAuth2Provider(tokenFile, credentialsFile string, scopes []string, credentialsDir string, transport http.RoundTripper) (*OAuth2Provider, error) {
	if transport == nil {
		return nil, fmt.Errorf("oauth2: transport must not be nil")
	}
	resolvedToken, err := resolveCredentialPath(tokenFile, credentialsDir)
	if err != nil {
		return nil, fmt.Errorf("oauth2: token_file: %w", err)
	}
	p := &OAuth2Provider{
		tokenFile:      resolvedToken,
		credentialsDir: credentialsDir,
		scopes:         scopes,
		transport:      transport,
	}

	// Load OAuth2 client config from credentials file
	credPath, err := resolveCredentialPath(credentialsFile, credentialsDir)
	if err != nil {
		return nil, fmt.Errorf("oauth2: credentials_file: %w", err)
	}
	if cfg, loadErr := loadOAuth2Config(credPath, scopes); loadErr == nil {
		p.config = cfg
	} else {
		log.Printf("oauth2: cannot load credentials from %s: %v", credPath, loadErr)
	}

	// Load cached token
	if tok, err := loadToken(p.tokenFile); err == nil {
		p.token = tok
	}

	return p, nil
}

// Name returns "oauth2".
func (o *OAuth2Provider) Name() string { return "oauth2" }

// Available reports whether a valid or refreshable token exists.
func (o *OAuth2Provider) Available() bool {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.token == nil {
		return false
	}
	// Token is available if it's valid or has a refresh token
	return o.token.Valid() || o.token.RefreshToken != ""
}

// Authenticate returns a Bearer authorization header.
// If the token is expired and a refresh token is available, it
// refreshes automatically and saves the new token.
func (o *OAuth2Provider) Authenticate(ctx context.Context, _ *http.Request) (http.Header, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.token == nil {
		return nil, fmt.Errorf("oauth2: no token available — run the auth tool to authenticate")
	}

	// Refresh if expired
	if !o.token.Valid() {
		if err := o.refreshLocked(ctx); err != nil {
			return nil, fmt.Errorf("oauth2: token refresh failed: %w", err)
		}
	}

	h := make(http.Header)
	h.Set("Authorization", "Bearer "+o.token.AccessToken)
	return h, nil
}

func (o *OAuth2Provider) refreshLocked(ctx context.Context) error {
	if o.token.RefreshToken == "" {
		return fmt.Errorf("token expired and no refresh token — re-authenticate")
	}
	if o.config == nil {
		return fmt.Errorf("no OAuth2 client config — cannot refresh")
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient,
		&http.Client{Transport: o.transport, Timeout: 30 * time.Second})
	src := o.config.TokenSource(ctx, o.token)
	newToken, err := src.Token()
	if err != nil {
		return fmt.Errorf("refresh: %w", err)
	}

	o.token = newToken

	if err := saveToken(o.tokenFile, newToken); err != nil {
		log.Printf("oauth2: failed to save refreshed token: %v", err)
	}

	return nil
}

// tokenJSON is the on-disk format for cached OAuth2 tokens.
// Compatible with Google's token.json format used by the
// existing Python version.
type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Expiry       string `json:"expiry"`

	// Google-specific fields (for compatibility)
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

func loadToken(path string) (*oauth2.Token, error) {
	data, err := os.ReadFile(path) //nolint:gosec // credential file path from config
	if err != nil {
		return nil, err
	}

	var tj tokenJSON
	if err := json.Unmarshal(data, &tj); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	tok := &oauth2.Token{
		AccessToken:  tj.AccessToken,
		TokenType:    tj.TokenType,
		RefreshToken: tj.RefreshToken,
	}

	if tj.Expiry != "" {
		expiry, err := time.Parse(time.RFC3339, tj.Expiry)
		if err != nil {
			// Try alternative formats
			expiry, err = time.Parse("2006-01-02T15:04:05.999999", tj.Expiry)
			if err != nil {
				log.Printf("oauth2: cannot parse token expiry %q", tj.Expiry)
			}
		}
		if err == nil {
			tok.Expiry = expiry
		}
	}

	return tok, nil
}

func saveToken(path string, tok *oauth2.Token) error {
	tj := tokenJSON{
		AccessToken:  tok.AccessToken,
		TokenType:    tok.TokenType,
		RefreshToken: tok.RefreshToken,
	}
	if !tok.Expiry.IsZero() {
		tj.Expiry = tok.Expiry.Format(time.RFC3339)
	}

	data, err := json.MarshalIndent(tj, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create token dir: %w", err)
	}

	return os.WriteFile(path, data, 0o600)
}

// credentialsJSON represents the Google OAuth2 client credentials file.
type credentialsJSON struct {
	Installed *credentialsData `json:"installed"`
	Web       *credentialsData `json:"web"`
}

type credentialsData struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AuthURI      string   `json:"auth_uri"`
	TokenURI     string   `json:"token_uri"`
	RedirectURIs []string `json:"redirect_uris"`
}

func loadOAuth2Config(path string, scopes []string) (*oauth2.Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // credential file path from config
	if err != nil {
		return nil, err
	}

	var creds credentialsJSON
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}

	cd := creds.Installed
	if cd == nil {
		cd = creds.Web
	}
	if cd == nil {
		return nil, fmt.Errorf("no 'installed' or 'web' credentials found")
	}

	redirectURI := "urn:ietf:wg:oauth:2.0:oob"
	if len(cd.RedirectURIs) > 0 {
		redirectURI = cd.RedirectURIs[0]
	}

	return &oauth2.Config{
		ClientID:     cd.ClientID,
		ClientSecret: cd.ClientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cd.AuthURI,
			TokenURL: cd.TokenURI,
		},
		RedirectURL: redirectURI,
	}, nil
}

func resolveCredentialPath(path, credentialsDir string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("credential file path is required")
	}
	base := credentialsDir
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		base = filepath.Join(home, ".config", "wtmcp", "credentials")
	}
	var resolved string
	if filepath.IsAbs(path) {
		resolved = filepath.Clean(path)
	} else {
		resolved = filepath.Clean(filepath.Join(base, path))
	}
	cleanBase := filepath.Clean(base)
	if resolved != cleanBase &&
		!strings.HasPrefix(resolved, cleanBase+string(os.PathSeparator)) {
		return "", fmt.Errorf("credential path escapes credentials directory: %s", path)
	}
	return resolved, nil
}
