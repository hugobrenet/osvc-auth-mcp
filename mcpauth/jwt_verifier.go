package mcpauth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// maxVerifierIssuers bounds the issuers a JWTVerifier keeps keys of.
const maxVerifierIssuers = 4096

var (
	// ErrInvalidToken is the error of a token a verifier refuses.
	ErrInvalidToken = errUnauthorized
	// ErrVerificationUnavailable is the error of a token that cannot be
	// verified now, the keys of its issuer being unavailable.
	ErrVerificationUnavailable = errOAuthUnavailable
)

// VerifiedClaims are the claims of an access JWT whose signature, issuer,
// audience and lifetime were verified.
type VerifiedClaims struct {
	Issuer   string
	Subject  string
	ClientID string // client_id (RFC 9068) or azp claim; may be empty
	// ExpiresAt is the exp claim.
	ExpiresAt time.Time
}

// JWTVerifier verifies access JWTs locally, for an issuer and an audience
// its caller names, such as the ones a target trusts: with the public keys
// the issuer publishes, discovered and cached per issuer as OAuthVerifier
// does. Unverified claims never select an issuer or a key URL.
type JWTVerifier struct {
	client  *http.Client
	mu      sync.Mutex
	issuers map[string]*oauthKeys
}

// NewJWTVerifier trusts the system roots, or the PEM certificates of caFile,
// for the issuers. It contacts no issuer.
func NewJWTVerifier(caFile string) (*JWTVerifier, error) {
	client, err := oauthHTTPClient(caFile, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &JWTVerifier{client: client, issuers: make(map[string]*oauthKeys)}, nil
}

// Verify verifies raw for issuer and audience. It returns an error wrapping
// ErrInvalidToken for a refused token, and ErrVerificationUnavailable when
// the keys of the issuer cannot be loaded.
func (v *JWTVerifier) Verify(ctx context.Context, raw, issuer, audience string) (VerifiedClaims, error) {
	if _, err := httpsURL(issuer); err != nil || !ValidClaimText(audience) {
		return VerifiedClaims{}, errUnauthorized
	}
	v.mu.Lock()
	keys := v.issuers[issuer]
	if keys == nil {
		if len(v.issuers) >= maxVerifierIssuers {
			v.mu.Unlock()
			return VerifiedClaims{}, errors.Join(errOAuthUnavailable, errors.New("too many issuers"))
		}
		keys = &oauthKeys{issuer: issuer, client: v.client}
		v.issuers[issuer] = keys
	}
	v.mu.Unlock()
	return verifyJWT(ctx, raw, issuer, audience, keys)
}

// verifyJWT verifies raw with the keys of issuer: an asymmetric signature by
// a key of its JWKS, the issuer, an audience containing audience, and the
// lifetime. Unverified claims never select an issuer or a key URL.
func verifyJWT(ctx context.Context, raw, issuer, audience string, keys *oauthKeys) (VerifiedClaims, error) {
	if raw == "" || len(raw) > MaxTokenBytes {
		return VerifiedClaims{}, errUnauthorized
	}
	// Reject obviously invalid claims before contacting the issuer. Unverified
	// claims never establish an identity or select an issuer, key URL or target.
	var claims struct {
		jwt.RegisteredClaims
		ClientID string `json:"client_id"`
		AZP      string `json:"azp"`
	}
	token, _, err := jwt.NewParser().ParseUnverified(raw, &claims)
	if err != nil || token == nil {
		return VerifiedClaims{}, errUnauthorized
	}
	if !OpenIDSigningMethod(token.Method.Alg()) {
		return VerifiedClaims{}, errUnauthorized
	}
	if !ValidClaimText(claims.Subject) {
		return VerifiedClaims{}, errUnauthorized
	}
	options := []jwt.ParserOption{jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt()}
	if err := jwt.NewValidator(options...).Validate(&claims); err != nil {
		return VerifiedClaims{}, errUnauthorized
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || !ValidClaimText(kid) {
		return VerifiedClaims{}, errUnauthorized
	}
	key, err := keys.get(ctx, kid)
	if err != nil {
		return VerifiedClaims{}, err
	}
	if key.algorithm != "" && key.algorithm != token.Method.Alg() {
		return VerifiedClaims{}, errUnauthorized
	}
	options = append(options, jwt.WithValidMethods([]string{token.Method.Alg()}))
	if _, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		return key.public, nil
	}, options...); err != nil {
		return VerifiedClaims{}, errUnauthorized
	}
	clientID := claims.ClientID
	if clientID == "" {
		clientID = claims.AZP
	}
	if !ValidClaimText(clientID) {
		clientID = ""
	}
	return VerifiedClaims{Issuer: claims.Issuer, Subject: claims.Subject, ClientID: clientID, ExpiresAt: claims.ExpiresAt.Time}, nil
}

// Middleware authenticates each request and removes its Authorization header
// and stripHeaders, so that headers meant for another listener, such as the
// target selection of delegated tokens, never reach next.
