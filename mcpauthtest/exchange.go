package mcpauthtest

import (
	"go.yaml.in/yaml/v2"
	"os"
	"path/filepath"
	"testing"
)

func WriteYAML(t testing.TB, doc any) string {
	t.Helper()
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func WriteExchangeProfiles(t testing.TB, p *OAuthProvider, method string) string {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("test-secret&+\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return WriteYAML(t, map[string]any{"version": 1, "profiles": map[string]any{"test-sso": map[string]any{
		"issuer": p.Issuer, "client_id": "test-exchange", "client_secret_file": secret, "token_endpoint_auth_method": method,
		"scopes": []string{"openid", "profile"}, "request_timeout": "2s", "tls": map[string]string{"ca_file": p.CAFile},
	}}})
}
