package social

import (
	b64 "encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func makeIDToken(t *testing.T, claims map[string]interface{}) TokenResponse {
	t.Helper()
	b, _ := json.Marshal(claims)
	return TokenResponse{IDToken: "h." + b64.RawURLEncoding.EncodeToString(b) + ".s"}
}

func TestDecodePayloadChecks(t *testing.T) {
	now := time.Unix(1000, 0)
	base := func() map[string]interface{} {
		return map[string]interface{}{"iss": "https://access.line.me", "aud": "cid", "exp": 2000, "nonce": "n1"}
	}
	cases := []struct {
		name    string
		mutate  func(map[string]interface{})
		opts    DecodePayloadOptions
		wantErr string
	}{
		{"ok default", nil, DecodePayloadOptions{}, ""},
		{"ok strict", nil, DecodePayloadOptions{Nonce: "n1", CheckExpiry: true, Now: func() time.Time { return now }}, ""},
		{"bad issuer", func(m map[string]interface{}) { m["iss"] = "x" }, DecodePayloadOptions{}, "issuer"},
		{"bad audience", func(m map[string]interface{}) { m["aud"] = "x" }, DecodePayloadOptions{}, "audience"},
		{"bad nonce", nil, DecodePayloadOptions{Nonce: "other"}, "nonce"},
		{"expired", func(m map[string]interface{}) { m["exp"] = 500 }, DecodePayloadOptions{CheckExpiry: true, Now: func() time.Time { return now }}, "expired"},
		{"expired ignored by default", func(m map[string]interface{}) { m["exp"] = 500 }, DecodePayloadOptions{}, ""},
	}
	for _, c := range cases {
		m := base()
		if c.mutate != nil {
			c.mutate(m)
		}
		tok := makeIDToken(t, m)
		_, err := tok.DecodePayloadWithOptions("cid", c.opts)
		_, err2 := tok.DecodeLineProfilePlusPayloadWithOptions("cid", c.opts)
		for _, e := range []error{err, err2} {
			if c.wantErr == "" && e != nil {
				t.Errorf("%s: unexpected error %v", c.name, e)
			}
			if c.wantErr != "" && (e == nil || !strings.Contains(e.Error(), c.wantErr)) {
				t.Errorf("%s: error %v, want containing %q", c.name, e, c.wantErr)
			}
		}
	}

	if _, err := (TokenResponse{IDToken: "a.b"}).DecodePayload("cid"); err == nil {
		t.Error("expected error for malformed token")
	}
	if _, err := (TokenResponse{IDToken: "a.b.c.d"}).DecodeLineProfilePlusPayload("cid"); err == nil {
		t.Error("expected error for 4-segment token")
	}
}

func TestTokenVerifyHonorsEndpointBase(t *testing.T) {
	var gotPath, gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotToken = r.URL.Query().Get("access_token")
		io.WriteString(w, `{"scope":"profile","client_id":"cid","expires_in":100}`)
	}))
	defer srv.Close()

	client, _ := New("cid", "secret", WithEndpointBase(srv.URL))
	if _, err := client.TokenVerify("tok").Do(); err != nil {
		t.Fatal(err)
	}
	if gotPath != APIEndpointTokenVerify || gotToken != "tok" {
		t.Errorf("path=%q token=%q", gotPath, gotToken)
	}
}

func TestWithAuthEndpointBase(t *testing.T) {
	client, _ := New("cid", "secret", WithAuthEndpointBase("http://localhost:1234"))
	raw, err := client.GetWebLoginURL("https://example.com/cb", "s", "profile", AuthRequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	if u.Host != "localhost:1234" || u.Path != APIEndpointAuthorize {
		t.Errorf("unexpected url %s", raw)
	}
	raw, _ = client.GetPKCEWebLoginURL("https://example.com/cb", "s", "profile", "c", AuthRequestOptions{})
	if u, _ := url.Parse(raw); u.Host != "localhost:1234" {
		t.Errorf("pkce url ignores auth base: %s", raw)
	}

	if _, err := New("cid", "secret", WithAuthEndpointBase("::bad")); err == nil {
		t.Error("expected error for invalid auth base")
	}
}
