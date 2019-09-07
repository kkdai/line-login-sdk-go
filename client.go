package social

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
)

// APIEndpoint constants
const (
	APIEndpointAuthBase  = "https://access.line.me"
	APIEndpointAuthorize = "/oauth2/v2.1/authorize"

	APIEndpointBase                 = "https://api.line.me"
	APIEndpointToken                = "/oauth2/v2.1/token"
	APIEndpointTokenVerify          = "/oauth2/v2.1/verify"
	APIEndpointRevokeToken          = "/oauth2/v2.1/revoke"
	APIEndpointGetUserProfile       = "/v2/profile"
	APIEndpointGetFriendshipStratus = "/friendship/v1/status"
)

// Client type
type Client struct {
	channelID     string
	channelSecret string
	channelToken  string
	endpointBase  *url.URL     // default APIEndpointBase
	httpClient    *http.Client // default http.DefaultClient
}

// ClientOption type
type ClientOption func(*Client) error

// New returns a new bot client instance.
func New(channelID, channelSecret string, options ...ClientOption) (*Client, error) {
	if channelID == "" {
		return nil, errors.New("missing channel ID")
	}
	if channelSecret == "" {
		return nil, errors.New("missing channel secret")
	}
	c := &Client{
		channelID:     channelID,
		channelSecret: channelSecret,
		httpClient:    http.DefaultClient,
	}
	for _, option := range options {
		err := option(c)
		if err != nil {
			return nil, err
		}
	}
	if c.endpointBase == nil {
		u, err := url.ParseRequestURI(APIEndpointBase)
		if err != nil {
			return nil, err
		}
		c.endpointBase = u
	}
	return c, nil
}

// WithHTTPClient function
func WithHTTPClient(c *http.Client) ClientOption {
	return func(client *Client) error {
		client.httpClient = c
		return nil
	}
}

// WithEndpointBase function
func WithEndpointBase(endpointBase string) ClientOption {
	return func(client *Client) error {
		u, err := url.ParseRequestURI(endpointBase)
		if err != nil {
			return err
		}
		client.endpointBase = u
		return nil
	}
}

func (client *Client) url(endpoint string) string {
	u := *client.endpointBase
	u.Path = path.Join(u.Path, endpoint)
	return u.String()
}

func (client *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "API-Service-Go/"+version)
	if ctx != nil {
		res, err := client.httpClient.Do(req.WithContext(ctx))
		if err != nil {
			select {
			case <-ctx.Done():
				err = ctx.Err()
			default:
			}
		}

		return res, err
	}
	return client.httpClient.Do(req)

}

func (client *Client) getHeaderAuth(ctx context.Context, endpoint string, query url.Values) (*http.Response, error) {
	req, err := http.NewRequest("GET", client.url(endpoint), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", query.Get("access_token")))
	return client.do(ctx, req)
}

func (client *Client) post(ctx context.Context, endpoint string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", client.url(endpoint), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return client.do(ctx, req)
}

func (client *Client) delete(ctx context.Context, endpoint string) (*http.Response, error) {
	req, err := http.NewRequest("DELETE", client.url(endpoint), nil)
	if err != nil {
		return nil, err
	}
	return client.do(ctx, req)
}
