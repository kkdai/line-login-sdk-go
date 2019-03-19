package social

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

//Provide those data for testing.

const (
	accessToken  string = ""
	cID          string = ""
	cSecret      string = ""
	qURL         string = ""
	refreshToken string = ""
)

func RequestLoginToken(code, redirectURL, clientID, clientSecret string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	req, err := http.NewRequest("POST", "https://api.line.me/oauth2/v2.1/token", strings.NewReader(data.Encode()))
	if err != nil {
		// handle err
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// handle err
		return nil, err
	}
	if resp.StatusCode != 200 {
		log.Println("http error:", resp.StatusCode)
		return nil, err
	}
	defer resp.Body.Close()

	retBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("err:", err)
		return nil, err
	}
	log.Println("body:", string(retBody))
	retToken := TokenResponse{}
	if err := json.Unmarshal(retBody, &retToken); err != nil {
		return nil, err
	}

	return &retToken, nil
}

func TestGetAccessToken(t *testing.T) {
	code := "MhpPbGJMoPLQekqpKEX5"
	client, _ := New(cID, cSecret)
	ret, err := client.GetAccessToken(qURL, code).Do()
	if err != nil {
		t.Errorf("err: %v", err)
	}

	t.Logf(" data:= %v", ret)
}

func TestGetUserProfile(t *testing.T) {
	client, _ := New(cID, cSecret)
	ret, err := client.GetUserProfile(accessToken).Do()
	if err != nil {
		log.Println("err:", err)
	}

	log.Println("ret:", ret)
}

func TestGetURLCode(t *testing.T) {
	scope := "profile openid" //profile | openid | email
	state := GenerateNounce()
	nounce := GenerateNounce()

	client, _ := New(cID, cSecret)
	url := client.GetWebLoinURL(qURL, state, scope, nounce, "normal")
	log.Println("url: ", url)
}

func TestVerifyToken(t *testing.T) {
	client, _ := New(cID, cSecret)
	ret, err := client.TokenVerify(accessToken).Do()
	if err != nil {
		log.Println("err:", err)
	}

	log.Println("ret:", ret)
}

func TestRefreshToken(t *testing.T) {
	client, _ := New(cID, cSecret)
	ret, err := client.RefreshToken(refreshToken).Do()
	if err != nil {
		log.Println("err:", err)
	}

	log.Println("ret:", ret)
}
