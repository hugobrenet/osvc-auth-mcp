package mcpauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OAuthConfig describes the MCP resource server, not a target audience or a
// token-exchange client. No client secret is needed to verify incoming JWTs.
type OAuthConfig struct {
	ResourceURL  string
	ResourceName string
	Issuer       string
	CAFile       string
}

// DefaultResourceName is published when OAuthConfig.ResourceName is empty.
const DefaultResourceName = "OpenSVC MCP"

func (c OAuthConfig) Validate() error {
	u, err := httpsURL(c.ResourceURL)
	if err != nil || u.Path != "/mcp" || u.RawPath != "" {
		return errors.New("OAuth resource must be an absolute HTTPS URL ending in /mcp without credentials, query or fragment")
	}
	if _, err := httpsURL(c.Issuer); err != nil {
		return errors.New("OAuth issuer must be an absolute HTTPS URL without credentials, query or fragment")
	}
	if c.CAFile != "" && !filepath.IsAbs(c.CAFile) {
		return errors.New("OAuth CA file must be an absolute path")
	}
	if c.ResourceName != "" && !ValidClaimText(c.ResourceName) {
		return errors.New("OAuth resource name must contain 1 to 256 bytes of text without surrounding whitespace or control characters")
	}
	return nil
}

func httpsURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || strings.TrimSpace(value) != value || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(value, "#") || u.Opaque != "" {
		return nil, errors.New("invalid HTTPS URL")
	}
	return u, nil
}

// OAuthIdentity is authenticated locally. It is deliberately separate from
// delegated tokens: an MCP access token must never reach a target.
type OAuthIdentity struct {
	Issuer    string
	Subject   string
	ClientID  string // client_id (RFC 9068) or azp claim, for audit only; may be empty
	ExpiresAt time.Time
	Resource  string
}

type oauthContextKey struct{}
type oauthCredential struct {
	identity OAuthIdentity
	token    string
}

// OAuthFromContext exposes the incoming credential only to server-side code:
// the token exchange consumes it; tools must never return it.
func OAuthFromContext(ctx context.Context) (OAuthIdentity, string, bool) {
	c, ok := ctx.Value(oauthContextKey{}).(oauthCredential)
	if !ok || ctx.Err() != nil || !time.Now().Before(c.identity.ExpiresAt) {
		return OAuthIdentity{}, "", false
	}
	return c.identity, c.token, true
}

type OAuthVerifier struct {
	config      OAuthConfig
	metadataURL string
	keys        *oauthKeys
}

// NewOAuthVerifier validates local trust only. Discovery and JWKS are fetched
// lazily; health and resource metadata remain available when the SSO is down.
func NewOAuthVerifier(cfg OAuthConfig) (*OAuthVerifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.ResourceName == "" {
		cfg.ResourceName = DefaultResourceName
	}
	client, err := oauthHTTPClient(cfg.CAFile, 5*time.Second)
	if err != nil {
		return nil, err
	}

	u, _ := url.Parse(cfg.ResourceURL)
	u.Path = "/.well-known/oauth-protected-resource/mcp"
	return &OAuthVerifier{config: cfg, metadataURL: u.String(), keys: &oauthKeys{issuer: cfg.Issuer, client: client}}, nil
}

// oauthHTTPClient never follows redirects or environment proxies.
func oauthHTTPClient(caFile string, timeout time.Duration) (*http.Client, error) {
	var roots *x509.CertPool
	if caFile != "" {
		f, err := os.Open(caFile)
		if err != nil {
			return nil, errors.New("read OAuth CA file")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxOAuthDocumentBytes {
			return nil, errors.New("OAuth CA file must be a regular PEM file of at most 1 MiB")
		}
		data, err := io.ReadAll(io.LimitReader(f, maxOAuthDocumentBytes+1))
		roots = x509.NewCertPool()
		if err != nil || len(data) > maxOAuthDocumentBytes || !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("OAuth CA file must contain trusted PEM certificates")
		}
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: timeout,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        2, MaxIdleConnsPerHost: 2,
		// No environment proxy and no caller headers on discovery/JWKS requests.
	}
	client := &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client, nil
}

// Metadata serves RFC 9728 metadata. Scopes are intentionally not advertised:
// business authorization belongs to the SSO and the target.
func (v *OAuthVerifier) Metadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		Resource             string   `json:"resource"`
		ResourceName         string   `json:"resource_name"`
		AuthorizationServers []string `json:"authorization_servers"`
		BearerMethods        []string `json:"bearer_methods_supported"`
	}{v.config.ResourceURL, v.config.ResourceName, []string{v.config.Issuer}, []string{"header"}})
}

var errOAuthUnavailable = errors.New("OAuth signing keys unavailable")

func (v *OAuthVerifier) verify(ctx context.Context, raw string) (OAuthIdentity, error) {
	claims, err := verifyJWT(ctx, raw, v.config.Issuer, v.config.ResourceURL, v.keys)
	if err != nil {
		return OAuthIdentity{}, err
	}
	return OAuthIdentity{Issuer: claims.Issuer, Subject: claims.Subject, ClientID: claims.ClientID, ExpiresAt: claims.ExpiresAt, Resource: v.config.ResourceURL}, nil
}

func (v *OAuthVerifier) Middleware(next http.Handler, stripHeaders ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Authorization")
		var raw string
		if len(values) == 1 {
			parts := strings.Fields(values[0])
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				raw = parts[1]
			}
		}
		if len(values) != 1 || raw == "" || r.URL.Query().Has("access_token") {
			v.unauthorized(w, len(values) != 0 || r.URL.Query().Has("access_token"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		identity, err := v.verify(ctx, raw)
		cancel()
		if err != nil {
			if errors.Is(err, errOAuthUnavailable) {
				w.Header().Set("Retry-After", "30")
				writeOAuthProblem(w, http.StatusServiceUnavailable, "Authentication temporarily unavailable", "The authorization server signing keys could not be loaded.")
			} else {
				v.unauthorized(w, true)
			}
			return
		}
		ctx, cancel = context.WithDeadline(r.Context(), identity.ExpiresAt)
		defer cancel()
		ctx = context.WithValue(ctx, oauthContextKey{}, oauthCredential{identity: identity, token: raw})
		request := r.Clone(ctx)
		request.Header.Del("Authorization")
		for _, name := range stripHeaders {
			request.Header.Del(name)
		}
		request.Body = http.MaxBytesReader(w, request.Body, maxMCPBodyBytes)
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, request)
	})
}

func (v *OAuthVerifier) unauthorized(w http.ResponseWriter, invalid bool) {
	challenge := fmt.Sprintf("Bearer resource_metadata=%q", v.metadataURL)
	if invalid {
		challenge += `, error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	writeOAuthProblem(w, http.StatusUnauthorized, "Unauthorized", "A valid access JWT intended for this MCP resource is required.")
}

func writeOAuthProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}{"about:blank", title, status, detail})
}
