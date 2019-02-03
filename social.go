package apiservice

import (
	"context"
	"fmt"
	"log"
	"net/http"
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
