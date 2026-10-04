package social

import (
	"context"
	"net/url"
	"strings"
)

// APIEndpointChannelTokenV3 is the endpoint that issues stateless channel access tokens.
const APIEndpointChannelTokenV3 = "/oauth2/v3/token"

// ChannelAccessTokenResponse type
type ChannelAccessTokenResponse struct {
	// AccessToken: A stateless channel access token. Treat it as an opaque string.
	AccessToken string `json:"access_token"`

	// ExpiresIn: Duration in seconds after which the token expires (15 minutes).
	ExpiresIn int `json:"expires_in"`

	// TokenType: Always "Bearer".
	TokenType string `json:"token_type"`
}

// IssueStatelessChannelAccessToken issues a stateless channel access token using the
// client's channel ID and channel secret (grant_type=client_credentials).
// The token is valid for 15 minutes and cannot be revoked, but there is no limit on how many
// can be issued. Use it as the channel access token for Deauthorize.
// https://developers.line.biz/en/docs/basics/channel-access-token/#stateless-channel-access-tokens
func (client *Client) IssueStatelessChannelAccessToken() *IssueStatelessChannelAccessTokenCall {
	return &IssueStatelessChannelAccessTokenCall{c: client}
}

// IssueStatelessChannelAccessTokenCall type
type IssueStatelessChannelAccessTokenCall struct {
	c   *Client
	ctx context.Context
}

// WithContext method
func (call *IssueStatelessChannelAccessTokenCall) WithContext(ctx context.Context) *IssueStatelessChannelAccessTokenCall {
	call.ctx = ctx
	return call
}

// Do method
func (call *IssueStatelessChannelAccessTokenCall) Do() (*ChannelAccessTokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", call.c.channelID)
	data.Set("client_secret", call.c.channelSecret)

	res, err := call.c.post(call.ctx, APIEndpointChannelTokenV3, strings.NewReader(data.Encode()))
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return decodeToChannelAccessTokenResponse(res)
}
