package social

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
)

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
	buf := strings.NewReader(fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&client_secret=%s", call.code, call.redirectURL, call.c.channelID, call.c.channelSecret))
	res, err := call.c.post(call.ctx, APIEndpointToken, buf)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToTokenResponse(res)
}

// GetWebLoinURL - LINE LOGIN 2.1 get LINE Login URL
func (client *Client) GetWebLoinURL(redirectURL, state, scope, nounce, chatbotPrompt string) string {
	req, err := http.NewRequest("GET", path.Join(APIEndpointBase, APIEndpointAuthorize), nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	q := req.URL.Query()
	q.Add("response_type", "code")
	q.Add("client_id", client.channelID)
	q.Add("state", state)
	q.Add("scope", scope)
	q.Add("nounce", nounce)
	q.Add("redirect_uri", redirectURL)
	if len(chatbotPrompt) > 0 {
		q.Add("bot_prompt", chatbotPrompt)
	}
	q.Add("prompt", "consent")
	req.URL.RawQuery = q.Encode()
	log.Println(req.URL.String())
	return req.URL.String()
}

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
	var urlQuery url.Values
	urlQuery.Set("access_token", call.accessToken)
	res, err := call.c.get(call.ctx, APIEndpointTokenVerify, urlQuery)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToTokenVerifyResponse(res)
}

// Refresh Token
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

// Revoke Token
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

	res, err := call.c.post(call.ctx, APIEndpointToken, strings.NewReader(data.Encode()))
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToBasicResponse(res)
}

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
	var urlQuery url.Values
	urlQuery.Set("access_token", call.accessToken)
	res, err := call.c.get(call.ctx, APIEndpointGetUserProfile, urlQuery)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToGetUserProfileResponse(res)
}

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
	res, err := call.c.get(call.ctx, APIEndpointGetFriendshipStratus, urlQuery)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToGetFriendshipStatusResponse(res)
}
