package mcpauth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/opensvc/osvc-auth-mcp/mcpauthtest"
)

// bundle writes the CA files of the providers in one trust bundle.
func bundle(t *testing.T, providers ...*mcpauthtest.OAuthProvider) string {
	t.Helper()
	var pem []byte
	for _, p := range providers {
		data, err := os.ReadFile(p.CAFile)
		if err != nil {
			t.Fatal(err)
		}
		pem = append(pem, data...)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestJWTVerifierVerifiesForTheIssuerAndAudienceAsked(t *testing.T) {
	a, b := mcpauthtest.NewOAuthProvider(t), mcpauthtest.NewOAuthProvider(t)
	v, err := NewJWTVerifier(bundle(t, a, b))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.client.CloseIdleConnections)
	tokenA := a.Token(t, "cluster-a", "alice", func(c jwt.MapClaims) { c["azp"] = "webapp" })
	claims, err := v.Verify(t.Context(), tokenA, a.Issuer, "cluster-a")
	if err != nil || claims.Issuer != a.Issuer || claims.Subject != "alice" || claims.ClientID != "webapp" || claims.ExpiresAt.IsZero() {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	if _, err := v.Verify(t.Context(), b.Token(t, "cluster-b", "bob", nil), b.Issuer, "cluster-b"); err != nil {
		t.Fatalf("second issuer refused: %v", err)
	}
	for name, tc := range map[string]struct{ raw, issuer, audience string }{
		"other audience":    {tokenA, a.Issuer, "cluster-b"},
		"other issuer":      {tokenA, b.Issuer, "cluster-a"},
		"signed by another": {b.Token(t, "cluster-a", "alice", func(c jwt.MapClaims) { c["iss"] = a.Issuer }), a.Issuer, "cluster-a"},
		"issuer not HTTPS":  {tokenA, "http://idp.example.test/", "cluster-a"},
		"invalid audience":  {tokenA, a.Issuer, ""},
		"malformed":         {"not-a-token", a.Issuer, "cluster-a"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(t.Context(), tc.raw, tc.issuer, tc.audience); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if a.KeyCalls.Load() != 1 || b.KeyCalls.Load() != 1 {
		t.Fatalf("keys fetched %d and %d times, want once per issuer", a.KeyCalls.Load(), b.KeyCalls.Load())
	}
}

func TestJWTVerifierReportsAnUnavailableIssuer(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	v, err := NewJWTVerifier(p.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.client.CloseIdleConnections)
	p.Status = 503
	if _, err := v.Verify(t.Context(), p.Token(t, "cluster-a", "alice", nil), p.Issuer, "cluster-a"); !errors.Is(err, ErrVerificationUnavailable) {
		t.Fatalf("err=%v", err)
	}
}
