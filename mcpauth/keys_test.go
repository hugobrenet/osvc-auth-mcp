package mcpauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/opensvc/osvc-auth-mcp/mcpauthtest"
)

// TestKeyRefreshServesKnownKeysMeanwhile: a refresh for an unknown key ID,
// slow at the issuer, never stalls the tokens of a known key.
func TestKeyRefreshServesKnownKeysMeanwhile(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	v := newTestVerifier(t, p)
	known := p.Token(t, testResource, "alice", nil)
	if _, err := v.verify(t.Context(), known); err != nil {
		t.Fatal(err)
	}
	p.KeysGate = make(chan struct{})
	v.keys.mu.Lock()
	v.keys.lastAttempt = time.Now().Add(-oauthRefreshInterval)
	v.keys.mu.Unlock()
	unknown := tokenWithKeyID(t, p, "rotated")
	refreshed := make(chan error, 1)
	go func() {
		_, err := v.verify(t.Context(), unknown)
		refreshed <- err
	}()
	for p.KeyCalls.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	started := time.Now()
	if _, err := v.verify(t.Context(), known); err != nil || time.Since(started) > time.Second {
		t.Fatalf("known key stalled by the refresh: %v after %v", err, time.Since(started))
	}
	close(p.KeysGate)
	if err := <-refreshed; !errors.Is(err, errUnauthorized) {
		t.Fatalf("unknown key: %v", err)
	}
}

// TestKeyRefreshCancelledByItsCallerIsNotRecorded: a caller that gives up
// during a refresh leaves no failure for the others.
func TestKeyRefreshCancelledByItsCallerIsNotRecorded(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	v := newTestVerifier(t, p)
	p.KeysGate = make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := v.verify(ctx, p.Token(t, testResource, "alice", nil))
		done <- err
	}()
	for p.KeyCalls.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, errOAuthUnavailable) {
		t.Fatalf("cancelled caller: %v", err)
	}
	close(p.KeysGate)
	if _, err := v.verify(t.Context(), p.Token(t, testResource, "bob", nil)); err != nil {
		t.Fatalf("the cancellation of another caller was recorded: %v", err)
	}
	if p.KeyCalls.Load() != 2 {
		t.Fatalf("%d key requests, want a new one after the cancellation", p.KeyCalls.Load())
	}
}

// TestClockSkewOnIssueTimesOnly: an issuer whose clock is a little ahead is
// tolerated; an expired token never is.
func TestClockSkewOnIssueTimesOnly(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	v := newTestVerifier(t, p)
	now := time.Now()
	for name, tc := range map[string]struct {
		change func(jwt.MapClaims)
		ok     bool
	}{
		"issued 20 s ahead":  {func(c jwt.MapClaims) { c["iat"] = now.Add(20 * time.Second).Unix() }, true},
		"valid in 20 s":      {func(c jwt.MapClaims) { c["nbf"] = now.Add(20 * time.Second).Unix() }, true},
		"issued 2 min ahead": {func(c jwt.MapClaims) { c["iat"] = now.Add(2 * time.Minute).Unix() }, false},
		"expired 5 s ago":    {func(c jwt.MapClaims) { c["exp"] = now.Add(-5 * time.Second).Unix() }, false},
		"no expiry":          {func(c jwt.MapClaims) { delete(c, "exp") }, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.verify(t.Context(), p.Token(t, testResource, "alice", tc.change))
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// tokenWithKeyID signs a token of p with its key, naming another key ID.
func tokenWithKeyID(t *testing.T, p *mcpauthtest.OAuthProvider, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": p.Issuer, "aud": testResource, "sub": "alice", "exp": time.Now().Add(time.Hour).Unix()})
	token.Header["kid"] = kid
	raw, err := token.SignedString(p.Key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
