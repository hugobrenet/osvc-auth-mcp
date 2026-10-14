package mcpauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/opensvc/osvc-auth-mcp/mcpauthtest"
)

const testResource = "https://mcp.example.test:8443/mcp"

func newTestVerifier(t *testing.T, p *mcpauthtest.OAuthProvider) *OAuthVerifier {
	t.Helper()
	v, err := NewOAuthVerifier(OAuthConfig{ResourceURL: testResource, Issuer: p.Issuer, CAFile: p.CAFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.keys.client.CloseIdleConnections)
	return v
}

func oauthRequest(handler http.Handler, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestOAuthMetadataAndChallengesArePublicAndCanonical(t *testing.T) {
	v, err := NewOAuthVerifier(OAuthConfig{ResourceURL: testResource, ResourceName: "OpenSVC lab MCP", Issuer: "https://sso.example.test/issuer/"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "https://attacker.test/.well-known/oauth-protected-resource/mcp", nil)
	request.Header.Set("X-Forwarded-Host", "attacker.test")
	w := httptest.NewRecorder()
	v.Metadata(w, request)
	var metadata map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || metadata["resource"] != testResource || metadata["resource_name"] != "OpenSVC lab MCP" || metadata["resource_documentation"] != nil || metadata["scopes_supported"] != nil || strings.Contains(w.Body.String(), "attacker") {
		t.Fatalf("incorrect metadata: %s", w.Body.String())
	}
	handler := v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unauthenticated request reached handler") }))
	for _, token := range []string{"", "malformed"} {
		w := oauthRequest(handler, token)
		challenge := w.Header().Get("WWW-Authenticate")
		if w.Code != 401 || !strings.Contains(challenge, `resource_metadata="https://mcp.example.test:8443/.well-known/oauth-protected-resource/mcp"`) || strings.Contains(challenge, "scope=") {
			t.Fatalf("incorrect challenge: status=%d header=%s", w.Code, challenge)
		}
		if (token != "") != strings.Contains(challenge, `error="invalid_token"`) {
			t.Error("incorrect invalid_token challenge")
		}
	}
}

func TestOAuthVerifiesIdentityAndStripsConfiguredHeaders(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	v := newTestVerifier(t, p)
	var saved context.Context
	called := 0
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		saved = r.Context()
		identity, token, ok := OAuthFromContext(r.Context())
		if !ok || identity.Issuer != p.Issuer || identity.Subject != "alice" || token == "" {
			t.Error("missing authenticated identity")
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Test-Target") != "" || r.Header.Get("X-Test-Kept") != "kept" {
			t.Error("credentials leaked into protocol headers")
		}
		deadline, ok := r.Context().Deadline()
		if !ok || !deadline.Equal(identity.ExpiresAt) {
			t.Error("missing token expiry deadline")
		}
		w.WriteHeader(204)
	}), "X-Test-Target")
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+p.Token(t, testResource, "alice", nil))
	r.Header.Set("X-Test-Target", "untrusted-target")
	r.Header.Set("X-Test-Kept", "kept")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 204 || called != 1 {
		t.Fatalf("valid token rejected: %d", w.Code)
	}
	if _, _, ok := OAuthFromContext(saved); ok {
		t.Error("credential remained usable after request completion")
	}
	if p.KeyCalls.Load() != 1 || p.MetadataCalls.Load() != 1 {
		t.Error("expected one discovery and one key fetch")
	}
}

func TestOAuthRejectsInvalidTokensAndAmbiguousCredentials(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	v := newTestVerifier(t, p)
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		name   string
		change func(jwt.MapClaims)
	}{
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "https://other.test" }},
		{"daemon audience", func(c jwt.MapClaims) { c["aud"] = "om3-dev5" }},
		{"missing audience", func(c jwt.MapClaims) { delete(c, "aud") }},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"missing expiry", func(c jwt.MapClaims) { delete(c, "exp") }},
		{"future nbf", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
		{"future iat", func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Hour).Unix() }},
		{"missing subject", func(c jwt.MapClaims) { delete(c, "sub") }},
		{"blank subject", func(c jwt.MapClaims) { c["sub"] = " " }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := oauthRequest(handler, p.Token(t, testResource, "alice", tc.change)); w.Code != 401 {
				t.Fatalf("got %d", w.Code)
			}
		})
	}
	if p.MetadataCalls.Load() != 0 {
		t.Error("invalid claims caused issuer requests")
	}
	valid := p.Token(t, testResource, "alice", nil)
	parsed, _, _ := jwt.NewParser().ParseUnverified(valid, jwt.MapClaims{})
	wrongSignature, _ := parsed.SignedString(mcpauthtest.NewJWTKey(t))
	if w := oauthRequest(handler, wrongSignature); w.Code != 401 {
		t.Fatalf("forged signature accepted: %d", w.Code)
	}
	if w := oauthRequest(handler, valid); w.Code != 204 {
		t.Fatalf("valid signature rejected: %d", w.Code)
	}
	for _, header := range []map[string]any{
		{"kid": "missing-key"}, {"kid": ""}, {"kid": "test-key", "alg": "HS256"},
	} {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, parsed.Claims)
		for k, value := range header {
			token.Header[k] = value
		}
		raw, _ := token.SignedString(p.Key)
		if w := oauthRequest(handler, raw); w.Code != 401 {
			t.Errorf("invalid key or algorithm accepted: %d", w.Code)
		}
	}
	for _, test := range []string{"duplicate", "query", "cookie", "basic", "oversized"} {
		r := httptest.NewRequest("POST", "/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+valid)
		switch test {
		case "duplicate":
			r.Header.Add("Authorization", "Bearer "+valid)
		case "query":
			r.URL.RawQuery = "access_token=forbidden"
		case "cookie":
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "access_token", Value: valid})
		case "basic":
			r.SetBasicAuth("alice", "password")
		case "oversized":
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", MaxTokenBytes+1))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Errorf("%s accepted: %d", test, w.Code)
		}
		if strings.Contains(w.Body.String(), valid) {
			t.Error("credential leaked in error")
		}
	}
}

func TestOAuthCachesKeysRotatesAndBoundsUnknownKeyRefresh(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	v := newTestVerifier(t, p)
	valid := p.Token(t, testResource, "alice", nil)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if _, err := v.verify(t.Context(), valid); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if p.KeyCalls.Load() != 1 {
		t.Fatalf("concurrent requests fetched keys %d times", p.KeyCalls.Load())
	}
	claims := jwt.MapClaims{"iss": p.Issuer, "aud": testResource, "sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}
	rotated := mcpauthtest.NewJWTKey(t)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "rotated"
	raw, _ := token.SignedString(rotated)
	p.JWKS = map[string]any{"keys": []any{mcpauthtest.RSAJWK(rotated, "rotated")}}
	v.keys.lastAttempt = time.Now().Add(-oauthRefreshInterval)
	if _, err := v.verify(t.Context(), raw); err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	for range 10 {
		if _, err := v.verify(t.Context(), valid); err == nil {
			t.Error("removed key accepted")
		}
	}
	if p.KeyCalls.Load() != 2 {
		t.Error("unknown key requests bypassed refresh cooldown")
	}
	// Cached signing keys may serve requests during an outage until their TTL.
	p.Status = 503
	if _, err := v.verify(t.Context(), raw); err != nil {
		t.Fatal("unexpired cached key unavailable")
	}
	v.keys.expires = time.Now().Add(-time.Second)
	v.keys.lastAttempt = time.Now().Add(-oauthRefreshInterval)
	w := oauthRequest(v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("stale keys used") })), raw)
	if w.Code != 503 || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("outage should not trigger a login loop: %d", w.Code)
	}
}

func TestOAuthRejectsUntrustedDiscoveryAndTLS(t *testing.T) {
	for _, mode := range []string{"wrong issuer", "http keys", "invalid keys", "duplicate keys", "untrusted TLS"} {
		t.Run(mode, func(t *testing.T) {
			p := mcpauthtest.NewOAuthProvider(t)
			switch mode {
			case "wrong issuer":
				p.Metadata["issuer"] = "https://other.test"
			case "http keys":
				p.Metadata["jwks_uri"] = "http://other.test/keys"
			case "invalid keys":
				p.JWKS = map[string]any{"keys": []any{map[string]any{"kty": "oct", "kid": "test-key", "k": "secret"}}}
			case "duplicate keys":
				p.JWKS = map[string]any{"keys": []any{mcpauthtest.RSAJWK(p.Key, "test-key"), mcpauthtest.RSAJWK(p.Key, "test-key")}}
			}
			cfg := OAuthConfig{ResourceURL: testResource, Issuer: p.Issuer, CAFile: p.CAFile}
			if mode == "untrusted TLS" {
				cfg.CAFile = ""
			}
			v, err := NewOAuthVerifier(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer v.keys.client.CloseIdleConnections()
			if _, err := v.verify(t.Context(), p.Token(t, testResource, "alice", nil)); err == nil {
				t.Fatal("untrusted signing configuration accepted")
			}
		})
	}
}

func TestOAuthAcceptsECAndAudienceArrays(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.JWKS = map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "ec", "use": "sig", "key_ops": []string{"verify"}, "x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}}}
	claims := jwt.MapClaims{"iss": p.Issuer, "aud": []string{testResource, "mcp-backend"}, "sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "ec"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	v := newTestVerifier(t, p)
	if _, err := v.verify(t.Context(), raw); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthDiscoveryNeverFollowsRedirectsOrTokenKeyURLs(t *testing.T) {
	var calls atomic.Int32
	destination := mcpauthtest.NewTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	p := mcpauthtest.NewOAuthProvider(t)
	v := newTestVerifier(t, p)
	// Embedded URLs are untrusted, even on a correctly signed token.
	valid := p.Token(t, testResource, "alice", nil)
	parsed, _, _ := jwt.NewParser().ParseUnverified(valid, jwt.MapClaims{})
	parsed.Header["jku"] = destination.Server.URL
	parsed.Header["x5u"] = destination.Server.URL
	raw, _ := parsed.SignedString(p.Key)
	if _, err := v.verify(t.Context(), raw); err != nil {
		t.Fatal(err)
	}
	redirect := mcpauthtest.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.Server.URL, http.StatusFound)
	}))
	other, err := NewOAuthVerifier(OAuthConfig{ResourceURL: testResource, Issuer: redirect.Server.URL, CAFile: redirect.CAFile})
	if err != nil {
		t.Fatal(err)
	}
	defer other.keys.client.CloseIdleConnections()
	if _, err := other.keys.load(t.Context()); err == nil {
		t.Error("redirect followed")
	}
	if calls.Load() != 0 {
		t.Error("untrusted destination contacted")
	}
}

func TestOAuthFallsBackToAuthorizationServerMetadata(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	p.OIDCNotFound = true
	v := newTestVerifier(t, p)
	if _, err := v.verify(t.Context(), p.Token(t, testResource, "alice", nil)); err != nil {
		t.Fatal(err)
	}
	if p.MetadataCalls.Load() != 2 || p.KeyCalls.Load() != 1 {
		t.Fatal("expected OIDC 404 followed by OAuth metadata and JWKS")
	}
}

func TestOAuthIsolatesConcurrentUsers(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	v := newTestVerifier(t, p)
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _, ok := OAuthFromContext(r.Context())
		if !ok {
			t.Error("missing identity")
		}
		_, _ = w.Write([]byte(identity.Subject))
	}))
	var wg sync.WaitGroup
	for _, subject := range []string{"alice", "bob", "carol"} {
		token := p.Token(t, testResource, subject, nil)
		wg.Go(func() {
			for range 4 {
				w := oauthRequest(handler, token)
				if w.Code != 200 || w.Body.String() != subject {
					t.Error("request used another user's identity")
				}
			}
		})
	}
	wg.Wait()
}

func TestJWKECPublicKeyRequiresAPointOnTheCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value *big.Int, size int) string {
		return base64.RawURLEncoding.EncodeToString(value.FillBytes(make([]byte, size)))
	}
	x, y := encode(key.X, 32), encode(key.Y, 32)
	parsed, err := oauthJWK{Kty: "EC", Crv: "P-256", X: x, Y: y}.publicKey()
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := parsed.(*ecdsa.PublicKey); !ok || !got.Equal(&key.PublicKey) {
		t.Fatalf("parsed key = %#v", parsed)
	}
	// A coordinate without its leading zero bytes is the same point.
	short := base64.RawURLEncoding.EncodeToString(key.X.Bytes())
	if _, err := (oauthJWK{Kty: "EC", Crv: "P-256", X: short, Y: y}).publicKey(); err != nil {
		t.Fatalf("coordinate without leading zeros refused: %v", err)
	}
	offCurve := encode(new(big.Int).Add(key.Y, big.NewInt(1)), 32)
	for name, jwk := range map[string]oauthJWK{
		"point off the curve": {Kty: "EC", Crv: "P-256", X: x, Y: offCurve},
		"oversized x":         {Kty: "EC", Crv: "P-256", X: encode(key.X, 33), Y: y},
		"empty y":             {Kty: "EC", Crv: "P-256", X: x, Y: ""},
		"unsupported curve":   {Kty: "EC", Crv: "secp256k1", X: x, Y: y},
	} {
		if _, err := jwk.publicKey(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
