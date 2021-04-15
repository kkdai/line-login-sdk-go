package social

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
)

type AuthRequestOptions struct {
	Nonce     string
	Prompt    string
	MaxAge    int
	UILocales string
	BotPrompt string
}

// GetAcceessToken: Issues access token.
func (client *Client) GetAccessToken(redirectURL, code string) *GetAccessTokenCall {
	return &GetAccessTokenCall{
		c:           client,
		redirectURL: redirectURL,
		code:        code,
	}
}

// GetAccessTokenCall type
type GetAccessTokenCall struct {
	c   *Client
	ctx context.Context

	redirectURL string
	code        string
}

// WithContext method
func (call *GetAccessTokenCall) WithContext(ctx context.Context) *GetAccessTokenCall {
	call.ctx = ctx
	return call
}

// Do method
func (call *GetAccessTokenCall) Do() (*TokenResponse, error) {
	data := url.Values{}
	// authorization_code. Specifies the grant type.
	data.Set("grant_type", "authorization_code")
	// Authorization code. Code returned in the authorization request.
	data.Set("code", call.code)
	data.Set("redirect_uri", call.redirectURL)
	data.Set("client_id", call.c.channelID)
	data.Set("client_secret", call.c.channelSecret)

	res, err := call.c.post(call.ctx, APIEndpointToken, strings.NewReader(data.Encode()))
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToTokenResponse(res)
}

// GetWebLoinURL - LINE LOGIN 2.1 get LINE Login  authorization request URL
func (client *Client) GetWebLoinURL(redirectURL string, state string, scope string, options AuthRequestOptions) string {
	u, err := url.Parse(APIEndpointAuthBase)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	u.Path = path.Join(u.Path, APIEndpointAuthorize)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	q := req.URL.Query()
	q.Add("response_type", "code")
	q.Add("redirect_uri", redirectURL)
	q.Add("client_id", client.channelID)
	q.Add("state", state)
	q.Add("scope", scope)

	if len(options.Nonce) > 0 {
		q.Add("nonce", options.Nonce)
	}

	if len(options.Prompt) > 0 {
		q.Add("prompt", options.Prompt)
	}

	if len(options.UILocales) > 0 {
		q.Add("ui_locales", options.UILocales)
	}

	if len(options.BotPrompt) > 0 {
		q.Add("bot_prompt", options.BotPrompt)
	}

	req.URL.RawQuery = q.Encode()
	return req.URL.String()
}

// GetPKCEWebLoinURL - LINE LOGIN 2.1 get LINE Login authorization request URL by PKCE
func (client *Client) GetPKCEWebLoinURL(redirectURL string, state string, scope string, codeChallenge string, options AuthRequestOptions) string {
	u, err := url.Parse(APIEndpointAuthBase)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	u.Path = path.Join(u.Path, APIEndpointAuthorize)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	q := req.URL.Query()
	q.Add("response_type", "code")
	q.Add("redirect_uri", redirectURL)
	q.Add("client_id", client.channelID)
	q.Add("state", state)
	q.Add("scope", scope)
	q.Add("code_challenge", codeChallenge)
	q.Add("code_challenge_method", "S256")

	if len(options.Nonce) > 0 {
		q.Add("nonce", options.Nonce)
	}

	if len(options.Prompt) > 0 {
		q.Add("prompt", options.Prompt)
	}

	if len(options.UILocales) > 0 {
		q.Add("ui_locales", options.UILocales)
	}

	if len(options.BotPrompt) > 0 {
		q.Add("bot_prompt", options.BotPrompt)
	}

	req.URL.RawQuery = q.Encode()
	return req.URL.String()
}

// TokenVerify: Verifies the access token.
// Note: This is the reference for the v2.1 endpoint. For the v2 reference, see Verify access token v2 (https://developers.line.biz/en/reference/social-api-v2/#verify-access-token)
func (client *Client) TokenVerify(accessToken string) *TokenVerifyCall {
	return &TokenVerifyCall{
		c:           client,
		accessToken: accessToken,
	}
}

// Client type
type TokenVerifyCall struct {
	c   *Client
	ctx context.Context

	accessToken string
}

// WithContext method
func (call *TokenVerifyCall) WithContext(ctx context.Context) *TokenVerifyCall {
	call.ctx = ctx
	return call
}

// Do method
func (call *TokenVerifyCall) Do() (*TokenVerifyResponse, error) {
	u, err := url.Parse(APIEndpointBase)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	u.Path = path.Join(u.Path, APIEndpointTokenVerify)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("access_token", call.accessToken)
	req.URL.RawQuery = q.Encode()

	res, err := call.c.do(call.ctx, req)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToTokenVerifyResponse(res)
}

// Refresh Token: Gets a new access token using a refresh token. Refresh tokens are returned with the access token when the user authorizes your app.
//Note: This is the reference for the v2.1 endpoint. For the v2 reference, see Refresh access token v2.
//Note: Cannot be used to refresh channel access tokens which are used for the Messaging API.
func (client *Client) RefreshToken(refreshToken string) *RefreshTokenCall {
	return &RefreshTokenCall{
		c:            client,
		refreshToken: refreshToken,
	}
}

// RefreshTokenCall type
type RefreshTokenCall struct {
	c   *Client
	ctx context.Context

	refreshToken string
}

// WithContext method
func (call *RefreshTokenCall) WithContext(ctx context.Context) *RefreshTokenCall {
	call.ctx = ctx
	return call
}

// Do method
func (call *RefreshTokenCall) Do() (*TokenRefreshResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", call.refreshToken)
	data.Set("client_id", call.c.channelID)
	data.Set("client_secret", call.c.channelSecret)

	res, err := call.c.post(call.ctx, APIEndpointToken, strings.NewReader(data.Encode()))
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToTokenRefreshResponse(res)
}

// RevokeToken: Invalidates the access token.
//Note: This is the reference for the v2.1 endpoint. For the v2 reference, see Revoke access token v2.
//Note: Cannot be used to invalidate channel access tokens which are used for the Messaging API.
func (client *Client) RevokeToken(accessToken string) *RevokeTokenCall {
	return &RevokeTokenCall{
		c:           client,
		accessToken: accessToken,
	}
}

// RefreshTokenCall type
type RevokeTokenCall struct {
	c   *Client
	ctx context.Context

	accessToken string
}

// WithContext method
func (call *RevokeTokenCall) WithContext(ctx context.Context) *RevokeTokenCall {
	call.ctx = ctx
	return call
}

// Do method
func (call *RevokeTokenCall) Do() (*BasicResponse, error) {
	data := url.Values{}
	data.Set("access_token", call.accessToken)
	data.Set("client_id", call.c.channelID)
	data.Set("client_secret", call.c.channelSecret)

	res, err := call.c.post(call.ctx, APIEndpointRevokeToken, strings.NewReader(data.Encode()))
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToBasicResponse(res)
}

// GetUserProfile: Gets a user's display name, profile image, and status message.
//Note: Requires an access token with the profile scope. For more information, see Making an authorization request and Scopes.
func (client *Client) GetUserProfile(accessToken string) *GetUserProfileCall {
	return &GetUserProfileCall{
		c:           client,
		accessToken: accessToken,
	}
}

// GetUserProfileCall type
type GetUserProfileCall struct {
	c   *Client
	ctx context.Context

	accessToken string
}

// WithContext method
func (call *GetUserProfileCall) WithContext(ctx context.Context) *GetUserProfileCall {
	call.ctx = ctx
	return call
}

// Do method
func (call *GetUserProfileCall) Do() (*GetUserProfileResponse, error) {
	urlQuery := url.Values{}
	urlQuery.Set("access_token", call.accessToken)
	res, err := call.c.getHeaderAuth(call.ctx, APIEndpointGetUserProfile, urlQuery)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToGetUserProfileResponse(res)
}

// GetFriendshipStatus: Gets the friendship status of the user and the bot linked to your LINE Login channel.
//Note: Requires an access token with the profile scope. For more information, see Making an authorization request and Scopes.
//Note: You must have a bot linked with your channel. For more information, see Linking a bot with your LINE Login channel.
func (client *Client) GetFriendshipStatus(accessToken string) *GetFriendshipStatusCall {
	return &GetFriendshipStatusCall{
		c:           client,
		accessToken: accessToken,
	}
}

// GetUserProfileCall type
type GetFriendshipStatusCall struct {
	c   *Client
	ctx context.Context

	accessToken string
}

// WithContext method
func (call *GetFriendshipStatusCall) WithContext(ctx context.Context) *GetFriendshipStatusCall {
	call.ctx = ctx
	return call
}

// Do method
func (call *GetFriendshipStatusCall) Do() (*GetFriendshipStatusResponse, error) {
	var urlQuery url.Values
	urlQuery.Set("access_token", call.accessToken)
	res, err := call.c.getHeaderAuth(call.ctx, APIEndpointGetFriendshipStratus, urlQuery)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToGetFriendshipStatusResponse(res)
}

// GetAccessTokenPKCECall: Issues access token by PKCE.
func (client *Client) GetAccessTokenPKCE(redirectURL, code, codeVerifier string) *GetAccessTokenPKCECall {
	return &GetAccessTokenPKCECall{
		c:            client,
		redirectURL:  redirectURL,
		code:         code,
		codeVerifier: codeVerifier,
	}
}

type GetAccessTokenPKCECall struct {
	c   *Client
	ctx context.Context

	codeVerifier string
	redirectURL  string
	code         string
}

// WithContext method
func (call *GetAccessTokenPKCECall) WithContext(ctx context.Context) *GetAccessTokenPKCECall {
	call.ctx = ctx
	return call
}

// Do method
func (call *GetAccessTokenPKCECall) Do() (*TokenResponse, error) {
	data := url.Values{}
	// authorization_code. Specifies the grant type.
	data.Set("grant_type", "client_credentials")
	// Authorization code. Code returned in the authorization request.
	data.Set("code", call.code)
	data.Set("redirect_uri", call.redirectURL)
	data.Set("client_id", call.c.channelID)
	data.Set("client_secret", call.c.channelSecret)
	data.Set("code_verifier", call.codeVerifier)

	res, err := call.c.post(call.ctx, APIEndpointToken, strings.NewReader(data.Encode()))
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToTokenResponse(res)
}
