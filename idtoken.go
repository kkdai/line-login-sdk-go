package social

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwksCacheTTL is how long a fetched JWKS is reused before being refreshed.
const jwksCacheTTL = time.Hour

// jwksMinRefetch limits how often an unknown "kid" can trigger a JWKS refetch, so
// forged tokens can't make the client hit the JWKS endpoint on every request.
var jwksMinRefetch = time.Minute

// JWK is a JSON Web Key (EC public key) published by LINE.
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksResponse struct {
	Keys []JWK `json:"keys"`
}

type jwksCache struct {
	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}

func (j JWK) publicKey() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported key type %s/%s", j.Kty, j.Crv)
	}
	xb, err := b64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("invalid jwk x: %w", err)
	}
	yb, err := b64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid jwk y: %w", err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("jwk point is not on curve")
	}
	return pub, nil
}

// VerifyIDTokenLocalOptions configures VerifyIDTokenLocal.
type VerifyIDTokenLocalOptions struct {
	// Nonce: if not empty, the "nonce" claim must match it.
	Nonce string

	// Now overrides the current time used for the "exp" check (default time.Now).
	Now func() time.Time
}

// VerifyIDTokenLocalCall type
type VerifyIDTokenLocalCall struct {
	c   *Client
	ctx context.Context

	idToken string
	options VerifyIDTokenLocalOptions
}

// VerifyIDTokenLocal verifies an ID token without calling the verify API.
// It checks the signature (ES256 with the key from LINE's JWKS selected by "kid",
// or HS256 with the channel secret), then "iss", "aud", "exp" and, if given, "nonce".
// The JWKS is fetched lazily and cached for an hour.
// https://developers.line.biz/en/docs/line-login/verify-id-token/#verify-id-token-on-your-server
func (client *Client) VerifyIDTokenLocal(idToken string, options VerifyIDTokenLocalOptions) *VerifyIDTokenLocalCall {
	return &VerifyIDTokenLocalCall{c: client, idToken: idToken, options: options}
}

// WithContext method
func (call *VerifyIDTokenLocalCall) WithContext(ctx context.Context) *VerifyIDTokenLocalCall {
	call.ctx = ctx
	return call
}

// Do method
func (call *VerifyIDTokenLocalCall) Do() (*BasicPayload, error) {
	parts := strings.Split(call.idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("idToken size is wrong")
	}

	headerBytes, err := b64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("base64url decode error: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("json unmarshal error: %w", err)
	}
	sig, err := b64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("base64url decode error: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])

	switch header.Alg {
	case "ES256":
		if err := call.verifyES256(header.Kid, signingInput, sig); err != nil {
			return nil, err
		}
	case "HS256":
		mac := hmac.New(sha256.New, []byte(call.c.channelSecret))
		mac.Write(signingInput)
		if !hmac.Equal(mac.Sum(nil), sig) {
			return nil, ErrInvalidSignature
		}
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", header.Alg)
	}

	payload := &BasicPayload{}
	if err := decodeIDTokenPayload(call.idToken, payload); err != nil {
		return nil, err
	}
	if err := payload.validate(call.c.channelID, DecodePayloadOptions{
		Nonce:       call.options.Nonce,
		CheckExpiry: true,
		Now:         call.options.Now,
	}); err != nil {
		return nil, err
	}
	return payload, nil
}

func (call *VerifyIDTokenLocalCall) verifyES256(kid string, signingInput, sig []byte) error {
	if len(sig) != 64 {
		return ErrInvalidSignature
	}
	key, err := call.c.jwksKey(call.ctx, kid)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(signingInput)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return ErrInvalidSignature
	}
	return nil
}

// jwksKey returns the public key for kid, fetching the JWKS when the cache is empty,
// stale, or does not contain kid (key rotation).
func (client *Client) jwksKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	c := &client.jwks
	c.mu.Lock()
	defer c.mu.Unlock()

	fresh := c.keys != nil && time.Since(c.fetchedAt) < jwksCacheTTL
	if fresh {
		if key, ok := c.keys[kid]; ok {
			return key, nil
		}
	}

	if c.keys != nil && time.Since(c.fetchedAt) < jwksMinRefetch {
		return nil, fmt.Errorf("no jwk found for kid %q", kid)
	}

	keys, err := client.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	c.keys = keys
	c.fetchedAt = time.Now()

	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("no jwk found for kid %q", kid)
	}
	return key, nil
}

func (client *Client) fetchJWKS(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequest("GET", client.url(APIEndpointJWKS), nil)
	if err != nil {
		return nil, err
	}
	res, err := client.do(ctx, req)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if err := checkResponse(res); err != nil {
		return nil, err
	}
	var doc jwksResponse
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return nil, err
	}
	keys := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := k.publicKey()
		if err != nil {
			continue // skip keys we can't use
		}
		keys[k.Kid] = pub
	}
	return keys, nil
}
