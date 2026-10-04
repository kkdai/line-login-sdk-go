package social

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAuthURLOptions(t *testing.T) {
	client, _ := New("cid", "secret")
	opts := AuthRequestOptions{Nonce: "n", Prompt: "consent", UILocales: "zh-TW", BotPrompt: "normal", MaxAge: 60}

	u1, err := client.GetWebLoginURL("https://example.com/cb", "s", "profile", opts)
	if err != nil {
		t.Fatal(err)
	}
	u2, err := client.GetPKCEWebLoginURL("https://example.com/cb", "s", "profile", "chal", opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{u1, u2} {
		q, _ := url.Parse(raw)
		v := q.Query()
		for k, want := range map[string]string{"nonce": "n", "prompt": "consent", "ui_locales": "zh-TW", "bot_prompt": "normal", "max_age": "60"} {
			if v.Get(k) != want {
				t.Errorf("%s = %q, want %q", k, v.Get(k), want)
			}
		}
	}

	u3, _ := client.GetWebLoginURL("https://example.com/cb", "s", "profile", AuthRequestOptions{})
	if q, _ := url.Parse(u3); q.Query().Has("max_age") {
		t.Error("max_age should be omitted when zero")
	}
}

func TestVerifyIDTokenSendsOptions(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"iss":"https://access.line.me","sub":"U1"}`))
	}))
	defer srv.Close()

	client, _ := New("cid", "secret", WithEndpointBase(srv.URL))
	_, err := client.VerifyIDToken("tok", VerifyIDTokenRequestOptions{Nonce: "n1", UserID: "U1"}).Do()
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("nonce") != "n1" || got.Get("user_id") != "U1" || got.Get("client_id") != "cid" {
		t.Errorf("unexpected form: %v", got)
	}
}

func TestAuthURLExtraOptions(t *testing.T) {
	client, _ := New("cid", "secret")
	off := false
	raw, err := client.GetWebLoginURL("https://example.com/cb", "s", "profile", AuthRequestOptions{
		InitialAMRDisplay: "lineqr", SwitchAMR: &off, DisableAutoLogin: true, DisableIOSAutoLogin: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	v := u.Query()
	for k, want := range map[string]string{"initial_amr_display": "lineqr", "switch_amr": "false", "disable_auto_login": "true", "disable_ios_auto_login": "true"} {
		if v.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, v.Get(k), want)
		}
	}

	raw, _ = client.GetWebLoginURL("https://example.com/cb", "s", "profile", AuthRequestOptions{})
	u, _ = url.Parse(raw)
	for _, k := range []string{"initial_amr_display", "switch_amr", "disable_auto_login", "disable_ios_auto_login"} {
		if u.Query().Has(k) {
			t.Errorf("%s should be omitted by default", k)
		}
	}
}

func TestDeprecatedNamesStillWork(t *testing.T) {
	client, _ := New("cid", "secret")
	a, _ := client.GetWebLoinURL("https://example.com/cb", "s", "profile", AuthRequestOptions{})
	b, _ := client.GetWebLoginURL("https://example.com/cb", "s", "profile", AuthRequestOptions{})
	if a != b {
		t.Errorf("deprecated GetWebLoinURL differs: %s vs %s", a, b)
	}
	a, _ = client.GetPKCEWebLoinURL("https://example.com/cb", "s", "profile", "c", AuthRequestOptions{})
	b, _ = client.GetPKCEWebLoginURL("https://example.com/cb", "s", "profile", "c", AuthRequestOptions{})
	if a != b {
		t.Errorf("deprecated GetPKCEWebLoinURL differs: %s vs %s", a, b)
	}
	if APIEndpointGetFriendshipStratus != APIEndpointGetFriendshipStatus {
		t.Error("deprecated constant differs")
	}
}
