package mcpauthtest

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OAuthProvider is an independent HTTPS issuer for integration tests. Documents
// may be changed between completed requests to simulate rotation and outages.
type OAuthProvider struct {
	TLSServer
	Key           *rsa.PrivateKey
	Issuer        string
	Metadata      map[string]any
	JWKS          map[string]any
	Status        int
	OIDCNotFound  bool
	MetadataCalls atomic.Int32
	KeyCalls      atomic.Int32
	TokenHandler  http.HandlerFunc
	// KeysGate, when set, holds every JWKS request until it is closed or the
	// request ends, to test callers waiting for a key refresh.
	KeysGate chan struct{}
}

func NewOAuthProvider(t testing.TB) *OAuthProvider {
	t.Helper()
	p := &OAuthProvider{Key: NewJWTKey(t)}
	p.TLSServer = NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" && r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credential leaked to public OAuth metadata")
		}
		var data map[string]any
		if p.OIDCNotFound && r.URL.Path == "/issuer/.well-known/openid-configuration" {
			p.MetadataCalls.Add(1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.URL.Path {
		case "/issuer/.well-known/openid-configuration", "/.well-known/oauth-authorization-server/issuer":
			p.MetadataCalls.Add(1)
			data = p.Metadata
		case "/keys":
			p.KeyCalls.Add(1)
			if p.KeysGate != nil {
				select {
				case <-p.KeysGate:
				case <-r.Context().Done():
					return
				}
			}
			data = p.JWKS
		case "/token":
			if p.TokenHandler != nil {
				p.TokenHandler(w, r)
				return
			}
			w.WriteHeader(http.StatusNotImplemented)
			return
		default:
			w.WriteHeader(404)
			return
		}
		if p.Status != 0 {
			w.WriteHeader(p.Status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(data)
	}))
	p.Issuer = p.Server.URL + "/issuer/"
	p.Metadata = map[string]any{"issuer": p.Issuer, "jwks_uri": p.Server.URL + "/keys"}
	p.JWKS = map[string]any{"keys": []any{RSAJWK(p.Key, "test-key")}}
	return p
}

func RSAJWK(key *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func (p *OAuthProvider) Token(t testing.TB, resource, subject string, change func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": p.Issuer, "aud": resource, "sub": subject, "exp": time.Now().Add(time.Hour).Unix()}
	if change != nil {
		change(claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	raw, err := token.SignedString(p.Key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
