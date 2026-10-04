package social

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type captured struct {
	method string
	path   string
	auth   string
	query  url.Values
	form   url.Values
}

// newMockClient starts a server answering every request with status/body and
// recording the last request into the returned *captured.
func newMockClient(t *testing.T, status int, body string) (*Client, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method = r.Method
		got.path = r.URL.Path
		got.auth = r.Header.Get("Authorization")
		got.query = r.URL.Query()
		got.form, _ = url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	client, err := New("cid", "secret", WithEndpointBase(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return client, got
}

func checkForm(t *testing.T, got url.Values, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got.Get(k) != v {
			t.Errorf("form %s = %q, want %q (form: %v)", k, got.Get(k), v, got)
		}
	}
}

func TestOfflineGetAccessToken(t *testing.T) {
	client, got := newMockClient(t, 200, `{"access_token":"at","expires_in":10,"refresh_token":"rt","token_type":"Bearer","scope":"profile"}`)
	res, err := client.GetAccessToken("https://example.com/cb", "code1").Do()
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken != "at" || res.RefreshToken != "rt" || res.ExpiresIn != 10 {
		t.Errorf("unexpected response %+v", res)
	}
	if got.method != "POST" || got.path != APIEndpointToken {
		t.Errorf("request %s %s", got.method, got.path)
	}
	checkForm(t, got.form, map[string]string{
		"grant_type": "authorization_code", "code": "code1", "redirect_uri": "https://example.com/cb",
		"client_id": "cid", "client_secret": "secret",
	})
}

func TestOfflineGetAccessTokenPKCE(t *testing.T) {
	client, got := newMockClient(t, 200, `{"access_token":"at"}`)
	res, err := client.GetAccessTokenPKCE("https://example.com/cb", "code1", "verifier1").Do()
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken != "at" {
		t.Errorf("unexpected response %+v", res)
	}
	if got.method != "POST" || got.path != APIEndpointToken {
		t.Errorf("request %s %s", got.method, got.path)
	}
	checkForm(t, got.form, map[string]string{
		"grant_type": "authorization_code", "code": "code1", "code_verifier": "verifier1", "client_id": "cid",
	})
}

func TestOfflineRefreshToken(t *testing.T) {
	client, got := newMockClient(t, 200, `{"access_token":"new","refresh_token":"rt2","expires_in":5,"token_type":"Bearer","scope":"profile"}`)
	res, err := client.RefreshToken("rt1").Do()
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken != "new" || res.RefreshToken != "rt2" {
		t.Errorf("unexpected response %+v", res)
	}
	if got.method != "POST" || got.path != APIEndpointToken {
		t.Errorf("request %s %s", got.method, got.path)
	}
	checkForm(t, got.form, map[string]string{
		"grant_type": "refresh_token", "refresh_token": "rt1", "client_id": "cid", "client_secret": "secret",
	})
}

func TestOfflineRevokeToken(t *testing.T) {
	client, got := newMockClient(t, 200, ``)
	if _, err := client.RevokeToken("at1").Do(); err != nil {
		t.Fatal(err)
	}
	if got.method != "POST" || got.path != APIEndpointRevokeToken {
		t.Errorf("request %s %s", got.method, got.path)
	}
	checkForm(t, got.form, map[string]string{"access_token": "at1", "client_id": "cid", "client_secret": "secret"})
}

func TestOfflineGetUserProfile(t *testing.T) {
	client, got := newMockClient(t, 200, `{"userId":"U1","displayName":"Evan","pictureUrl":"https://p","statusMessage":"hi"}`)
	res, err := client.GetUserProfile("at1").Do()
	if err != nil {
		t.Fatal(err)
	}
	if res.UserID != "U1" || res.DisplayName != "Evan" || res.StatusMessage != "hi" {
		t.Errorf("unexpected response %+v", res)
	}
	if got.method != "GET" || got.path != APIEndpointGetUserProfile || got.auth != "Bearer at1" {
		t.Errorf("request %s %s auth=%q", got.method, got.path, got.auth)
	}
}

func TestOfflineGetFriendshipStatus(t *testing.T) {
	client, got := newMockClient(t, 200, `{"friendFlag":true}`)
	res, err := client.GetFriendshipStatus("at1").Do()
	if err != nil {
		t.Fatal(err)
	}
	if !res.FriendFlag {
		t.Errorf("unexpected response %+v", res)
	}
	if got.method != "GET" || got.path != APIEndpointGetFriendshipStratus || got.auth != "Bearer at1" {
		t.Errorf("request %s %s auth=%q", got.method, got.path, got.auth)
	}
}

func TestOfflineGetUserInfo(t *testing.T) {
	client, got := newMockClient(t, 200, `{"sub":"U1","name":"Evan","picture":"https://p"}`)
	res, err := client.GetUserInfo("at1").Do()
	if err != nil {
		t.Fatal(err)
	}
	if res.Sub != "U1" || res.Name != "Evan" || res.Picture != "https://p" {
		t.Errorf("unexpected response %+v", res)
	}
	if got.method != "GET" || got.path != APIEndpointUserInfo || got.auth != "Bearer at1" {
		t.Errorf("request %s %s auth=%q", got.method, got.path, got.auth)
	}
}

func TestOfflineDeauthorize(t *testing.T) {
	client, got := newMockClient(t, 204, ``)
	if _, err := client.Deauthorize("cat", "uat").Do(); err != nil {
		t.Fatal(err)
	}
	if got.method != "POST" || got.path != APIEndpointDeauthorize || got.auth != "Bearer cat" {
		t.Errorf("request %s %s auth=%q", got.method, got.path, got.auth)
	}
	checkForm(t, got.form, map[string]string{"userAccessToken": "uat"})
}

func TestOfflineDeauthorizeNon204IsError(t *testing.T) {
	client, _ := newMockClient(t, 200, ``)
	_, err := client.Deauthorize("cat", "uat").Do()
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 200 {
		t.Errorf("expected APIError with code 200, got %v", err)
	}
}

func TestOfflineAPIErrors(t *testing.T) {
	body := `{"message":"The access token expired","details":[{"message":"bad","property":"access_token"}]}`
	calls := map[string]func(c *Client) error{
		"GetAccessToken":      func(c *Client) error { _, err := c.GetAccessToken("u", "c").Do(); return err },
		"GetAccessTokenPKCE":  func(c *Client) error { _, err := c.GetAccessTokenPKCE("u", "c", "v").Do(); return err },
		"RefreshToken":        func(c *Client) error { _, err := c.RefreshToken("r").Do(); return err },
		"RevokeToken":         func(c *Client) error { _, err := c.RevokeToken("a").Do(); return err },
		"TokenVerify":         func(c *Client) error { _, err := c.TokenVerify("a").Do(); return err },
		"VerifyIDToken":       func(c *Client) error { _, err := c.VerifyIDToken("i", VerifyIDTokenRequestOptions{}).Do(); return err },
		"GetUserProfile":      func(c *Client) error { _, err := c.GetUserProfile("a").Do(); return err },
		"GetFriendshipStatus": func(c *Client) error { _, err := c.GetFriendshipStatus("a").Do(); return err },
		"GetUserInfo":         func(c *Client) error { _, err := c.GetUserInfo("a").Do(); return err },
		"Deauthorize":         func(c *Client) error { _, err := c.Deauthorize("c", "u").Do(); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			client, _ := newMockClient(t, 400, body)
			err := call(client)
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected *APIError, got %v", err)
			}
			if apiErr.Code != 400 || apiErr.Response == nil || apiErr.Response.Message != "The access token expired" {
				t.Errorf("unexpected APIError %+v", apiErr)
			}
			if len(apiErr.Response.Details) != 1 || apiErr.Response.Details[0].Property != "access_token" {
				t.Errorf("details not decoded: %+v", apiErr.Response)
			}
		})
	}
}

func TestOfflineAPIErrorNonJSONBody(t *testing.T) {
	client, _ := newMockClient(t, 500, `<html>oops</html>`)
	_, err := client.GetUserProfile("a").Do()
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 500 || apiErr.Response != nil {
		t.Errorf("expected APIError{500, nil response}, got %v", err)
	}
}

func TestOfflineContextCanceled(t *testing.T) {
	client, _ := newMockClient(t, 200, `{}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.GetUserProfile("a").WithContext(ctx).Do()
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}
