package social

import (
	"log"
	"os"
	"testing"
)

var (
	accessToken  string
	refreshToken string
	cID          string
	cSecret      string
	qURL         string
	code         string
)

//Provide those data for testing.
func init() {
	accessToken = os.Getenv("LINE_ACCESS_TOKEN")
	refreshToken = os.Getenv("LINE_REFRESH_TOKEN")
	cID = os.Getenv("LINE_CLIENT_ID")
	cSecret = os.Getenv("LINE_CLIENT_SECRET")
	qURL = os.Getenv("LINE_SERVER_URL")
	code = os.Getenv("LINE_LOGIN_CODE")
}

func checkEnvVariables(t *testing.T) {
	if len(cID) == 0 || len(cSecret) == 0 {
		log.Println("Please set environment variables for your LINE setting")
		t.Skip("Please set environment variables for your LINE setting")
	}
}

func TestGetAccessToken(t *testing.T) {
	checkEnvVariables(t)

	if len(code) == 0 {
		t.Skip("Skip it since don't exist LINE login code.")
	}

	client, _ := New(cID, cSecret)
	ret, err := client.GetAccessToken(qURL, code).Do()
	if err != nil {
		t.Errorf("err: %v", err)
	}

	t.Logf(" data:= %v", ret)
}

func TestGetUserProfile(t *testing.T) {
	checkEnvVariables(t)

	client, _ := New(cID, cSecret)
	ret, err := client.GetUserProfile(accessToken).Do()
	if err != nil {
		log.Println("err:", err)
	}

	log.Println("ret:", ret)
}

func TestGetURLCode(t *testing.T) {
	checkEnvVariables(t)

	scope := "profile openid" //profile | openid | email
	state := GenerateNonce()
	nonce := GenerateNonce()

	client, _ := New(cID, cSecret)
	url := client.GetWebLoinURL(qURL, state, scope, AuthRequestOptions{Nonce: nonce, BotPrompt: "normal", Prompt: "consent"})
	log.Println("url: ", url)
}

func TestVerifyToken(t *testing.T) {
	checkEnvVariables(t)

	client, _ := New(cID, cSecret)
	ret, err := client.TokenVerify(accessToken).Do()
	if err != nil {
		log.Println("err:", err)
	}

	log.Println("ret:", ret)
}

func TestRefreshToken(t *testing.T) {
	checkEnvVariables(t)

	client, _ := New(cID, cSecret)
	ret, err := client.RefreshToken(refreshToken).Do()
	if err != nil {
		log.Println("err:", err)
	}

	log.Println("ret:", ret)
}

func TestRevokeToken(t *testing.T) {
	checkEnvVariables(t)

	client, _ := New(cID, cSecret)
	ret, err := client.RevokeToken(accessToken).Do()
	if err != nil {
		log.Println("err:", err)
	}

	log.Println("ret:", ret)
}
