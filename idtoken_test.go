package social

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func enc(b []byte) string { return b64.RawURLEncoding.EncodeToString(b) }

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid})
	p, _ := json.Marshal(claims)
	input := enc(h) + "." + enc(p)
	d := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + enc(append(pad32(r.Bytes()), pad32(s.Bytes())...))
}

func signHS256(secret string, claims map[string]interface{}) string {
	h, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	input := enc(h) + "." + enc(p)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(input))
	return input + "." + enc(m.Sum(nil))
}

func jwkFor(key *ecdsa.PrivateKey, kid string) JWK {
	return JWK{Kty: "EC", Alg: "ES256", Use: "sig", Kid: kid, Crv: "P-256",
		X: enc(pad32(key.X.Bytes())), Y: enc(pad32(key.Y.Bytes()))}
}

func claims(exp int64) map[string]interface{} {
	return map[string]interface{}{"iss": "https://access.line.me", "sub": "U1", "aud": "cid", "exp": exp, "nonce": "n1"}
}

func TestVerifyIDTokenLocalES256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path != APIEndpointJWKS {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(jwksResponse{Keys: []JWK{jwkFor(key, "k1")}})
	}))
	defer srv.Close()
	client, _ := New("cid", "secret", WithEndpointBase(srv.URL))

	now := time.Unix(1000, 0)
	opts := VerifyIDTokenLocalOptions{Nonce: "n1", Now: func() time.Time { return now }}

	good := signES256(t, key, "k1", claims(2000))
	p, err := client.VerifyIDTokenLocal(good, opts).Do()
	if err != nil || p.Sub != "U1" {
		t.Fatalf("good token: %v %+v", err, p)
	}
	// second verification should use the cache
	if _, err := client.VerifyIDTokenLocal(good, opts).Do(); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Errorf("JWKS fetched %d times, want 1", hits)
	}

	cases := map[string]struct {
		token   string
		opts    VerifyIDTokenLocalOptions
		wantErr string
	}{
		"wrong key":   {signES256(t, other, "k1", claims(2000)), opts, "invalid signature"},
		"tampered":    {strings.Replace(good, good[strings.Index(good, ".")+1:strings.Index(good, ".")+5], "AAAA", 1), opts, ""},
		"expired":     {signES256(t, key, "k1", claims(500)), opts, "expired"},
		"bad nonce":   {good, VerifyIDTokenLocalOptions{Nonce: "zzz", Now: opts.Now}, "nonce"},
		"unknown kid": {signES256(t, key, "nope", claims(2000)), opts, "no jwk"},
		"malformed":   {"a.b", opts, "size"},
		"unsupported": {enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{}`)) + ".", opts, "unsupported"},
	}
	for name, c := range cases {
		_, err := client.VerifyIDTokenLocal(c.token, c.opts).Do()
		if err == nil {
			t.Errorf("%s: expected error", name)
			continue
		}
		if c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: error %q, want containing %q", name, err, c.wantErr)
		}
	}
	if _, err := client.VerifyIDTokenLocal(cases["wrong key"].token, opts).Do(); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerifyIDTokenLocalHS256(t *testing.T) {
	client, _ := New("cid", "secret")
	opts := VerifyIDTokenLocalOptions{Now: func() time.Time { return time.Unix(1000, 0) }}

	if _, err := client.VerifyIDTokenLocal(signHS256("secret", claims(2000)), opts).Do(); err != nil {
		t.Errorf("valid HS256 rejected: %v", err)
	}
	if _, err := client.VerifyIDTokenLocal(signHS256("wrong", claims(2000)), opts).Do(); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerifyIDTokenLocalRefetchesOnKeyRotation(t *testing.T) {
	old := jwksMinRefetch
	jwksMinRefetch = 0
	defer func() { jwksMinRefetch = old }()
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		keys := []JWK{jwkFor(k1, "k1")}
		if n > 1 {
			keys = append(keys, jwkFor(k2, "k2"))
		}
		json.NewEncoder(w).Encode(jwksResponse{Keys: keys})
	}))
	defer srv.Close()
	client, _ := New("cid", "secret", WithEndpointBase(srv.URL))
	opts := VerifyIDTokenLocalOptions{Now: func() time.Time { return time.Unix(1000, 0) }}

	if _, err := client.VerifyIDTokenLocal(signES256(t, k1, "k1", claims(2000)), opts).Do(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyIDTokenLocal(signES256(t, k2, "k2", claims(2000)), opts).Do(); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
	if hits != 2 {
		t.Errorf("JWKS fetched %d times, want 2", hits)
	}
}

func TestVerifyIDTokenLocalUnknownKidIsRateLimited(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		json.NewEncoder(w).Encode(jwksResponse{Keys: []JWK{jwkFor(key, "k1")}})
	}))
	defer srv.Close()
	client, _ := New("cid", "secret", WithEndpointBase(srv.URL))
	tok := signES256(t, key, "forged", claims(2000))
	for i := 0; i < 5; i++ {
		client.VerifyIDTokenLocal(tok, VerifyIDTokenLocalOptions{}).Do()
	}
	if hits != 1 {
		t.Errorf("JWKS fetched %d times for repeated unknown kid, want 1", hits)
	}
}
