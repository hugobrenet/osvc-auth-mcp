// Package mcpauth authenticates the external clients of the OpenSVC MCP
// servers and prepares the credentials of their targets. OAuth access JWTs
// intended for the MCP resource are verified locally; each tool call then
// exchanges them (RFC 8693) for a token intended for the target, which verifies
// it independently. An MCP access token never reaches a target.
package mcpauth

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxTokenBytes bounds every access token the MCP servers accept.
	MaxTokenBytes   = 32 << 10
	maxMCPBodyBytes = 1 << 20
)

var errUnauthorized = errors.New("invalid OAuth access token")

// OpenIDSigningMethod reports whether algorithm is an asymmetric JWS algorithm
// accepted for OpenID Connect access tokens.
func OpenIDSigningMethod(algorithm string) bool {
	switch algorithm {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
		return true
	default:
		return false
	}
}

// ValidClaimText reports whether s is 1 to 256 bytes of UTF-8 text without
// surrounding whitespace or control characters.
func ValidClaimText(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s && utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.In(r, unicode.Cf) })
}
