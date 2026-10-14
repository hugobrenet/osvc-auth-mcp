package mcpauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	maxOAuthDocumentBytes = 1 << 20
	oauthKeysLifetime     = 5 * time.Minute
	oauthRefreshInterval  = 30 * time.Second
)

type oauthKey struct {
	public    crypto.PublicKey
	algorithm string
}

// Only public signing keys are cached. Unknown kids trigger a refresh at most
// every 30 seconds, shared across callers, to bound issuer load during rotation
// or an attack. Expired keys are never used after a failed refresh.
type oauthKeys struct {
	issuer      string
	client      *http.Client
	mu          sync.Mutex
	keys        map[string]oauthKey
	expires     time.Time
	lastAttempt time.Time
	lastErr     error
}

func (k *oauthKeys) get(ctx context.Context, kid string) (oauthKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if ctx.Err() != nil {
		return oauthKey{}, errOAuthUnavailable
	}
	now := time.Now()
	if key, ok := k.keys[kid]; ok && now.Before(k.expires) {
		return key, nil
	}
	if now.Sub(k.lastAttempt) < oauthRefreshInterval {
		if k.lastErr != nil || !now.Before(k.expires) {
			return oauthKey{}, errOAuthUnavailable
		}
		return oauthKey{}, errUnauthorized
	}
	k.lastAttempt = now
	keys, err := k.load(ctx)
	k.lastErr = err
	if err != nil {
		return oauthKey{}, errOAuthUnavailable
	}
	k.keys, k.expires = keys, time.Now().Add(oauthKeysLifetime)
	key, ok := k.keys[kid]
	if !ok {
		return oauthKey{}, errUnauthorized
	}
	return key, nil
}

func (k *oauthKeys) load(ctx context.Context) (map[string]oauthKey, error) {
	// OIDC discovery is tried first. RFC 8414 is a fallback for
	// OAuth-only issuers. Only administrator-configured issuer URLs are used.
	u, _ := url.Parse(k.issuer)
	u.Path = "/.well-known/oauth-authorization-server" + strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	locations := []string{strings.TrimRight(k.issuer, "/") + "/.well-known/openid-configuration", u.String()}
	var metadata struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	for i, location := range locations {
		status, err := k.getJSON(ctx, location, &metadata)
		if status == http.StatusNotFound && i == 0 {
			continue
		}
		if err != nil {
			return nil, errOAuthUnavailable
		}
		break
	}
	if metadata.Issuer != k.issuer {
		return nil, errOAuthUnavailable
	}
	if _, err := httpsURL(metadata.JWKSURI); err != nil {
		return nil, errOAuthUnavailable
	}
	var set struct {
		Keys []oauthJWK `json:"keys"`
	}
	if _, err := k.getJSON(ctx, metadata.JWKSURI, &set); err != nil || len(set.Keys) > 128 {
		return nil, errOAuthUnavailable
	}
	keys := make(map[string]oauthKey)
	for _, jwk := range set.Keys {
		if !ValidClaimText(jwk.Kid) || (jwk.Use != "" && jwk.Use != "sig") || (len(jwk.KeyOps) > 0 && !slices.Contains(jwk.KeyOps, "verify")) || (jwk.Alg != "" && !OpenIDSigningMethod(jwk.Alg)) {
			continue
		}
		public, err := jwk.publicKey()
		if err != nil {
			continue
		}
		if _, duplicate := keys[jwk.Kid]; duplicate {
			return nil, errOAuthUnavailable
		}
		keys[jwk.Kid] = oauthKey{public: public, algorithm: jwk.Alg}
	}
	if len(keys) == 0 {
		return nil, errOAuthUnavailable
	}
	return keys, nil
}

func (k *oauthKeys) getJSON(ctx context.Context, address string, result any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return 0, errOAuthUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := k.client.Do(request)
	if err != nil {
		return 0, errOAuthUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, errOAuthUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxOAuthDocumentBytes+1))
	if err != nil || len(data) > maxOAuthDocumentBytes || json.Unmarshal(data, result) != nil {
		return response.StatusCode, errOAuthUnavailable
	}
	return response.StatusCode, nil
}

type oauthJWK struct {
	Kid    string   `json:"kid"`
	Kty    string   `json:"kty"`
	Alg    string   `json:"alg"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
}

func (k oauthJWK) publicKey() (crypto.PublicKey, error) {
	decode := func(value string) (*big.Int, error) {
		data, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(data) == 0 {
			return nil, errors.New("invalid JWK integer")
		}
		return new(big.Int).SetBytes(data), nil
	}
	switch k.Kty {
	case "RSA":
		n, err := decode(k.N)
		if err != nil || n.BitLen() < 2048 || n.BitLen() > 8192 {
			return nil, errors.New("invalid RSA modulus")
		}
		e, err := decode(k.E)
		if err != nil || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Bit(0) == 0 {
			return nil, errors.New("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsupported EC curve")
		}
		// The coordinates form an uncompressed SEC 1 point, which the
		// standard parser rejects unless it is on the curve and not the point
		// at infinity.
		size := (curve.Params().BitSize + 7) / 8
		point := make([]byte, 1+2*size)
		point[0] = 4
		for i, value := range []string{k.X, k.Y} {
			coordinate, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil || len(coordinate) == 0 || len(coordinate) > size {
				return nil, errors.New("invalid EC point")
			}
			copy(point[1+(i+1)*size-len(coordinate):1+(i+1)*size], coordinate)
		}
		key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, errors.New("invalid EC point")
		}
		return key, nil
	default:
		return nil, errors.New("unsupported signing key")
	}
}
