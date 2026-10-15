// Package mcpauth authenticates the external clients of the OpenSVC MCP
// servers and prepares the credentials of their targets. OAuth access JWTs
// intended for the MCP resource are verified locally; each tool call then
// exchanges them (RFC 8693) for a token intended for the target, which verifies
// it independently. An MCP access token never reaches a target.
package mcpauth

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// MaxTokenBytes bounds every access token the MCP servers accept.
	MaxTokenBytes   = 32 << 10
	maxMCPBodyBytes = 1 << 20
)

var errUnauthorized = errors.New("invalid access token")

// ClockSkew is the tolerance on the issue and not-before times of a token,
// for an issuer whose clock is a little ahead. The expiry gets none: it bounds
// the requests of the token.
const ClockSkew = 30 * time.Second

// ValidateLifetime validates the registered claims of a token with options,
// such as its issuer and audience: its expiry, required and not passed, and
// its issue and not-before times, if any, with ClockSkew of tolerance.
func ValidateLifetime(claims jwt.Claims, options ...jwt.ParserOption) error {
	options = append(options, jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(ClockSkew))
	if err := jwt.NewValidator(options...).Validate(claims); err != nil {
		return err
	}
	expires, err := claims.GetExpirationTime()
	if err != nil || expires == nil || !time.Now().Before(expires.Time) {
		return errors.New("token expired")
	}
	return nil
}

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
