package social

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"log"
	"math/rand"
	"time"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")

func init() {
	rand.Seed(time.Now().UnixNano())
}

// PkceChallenge: base64-URL-encoded SHA256 hash of verifier, per rfc 7636
func PkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	challenge := b64.URLEncoding.WithPadding(b64.NoPadding).EncodeToString(sum[:])
	return (challenge)
}

// GenerateCodeVerifier: Generate code verifier (length 43~128) for PKCE.
func GenerateCodeVerifier(length int) string {
	if length > 128 {
		length = 128
	}
	if length < 43 {
		length = 43
	}
	return b64.StdEncoding.EncodeToString([]byte(randStringRunes(length)))
}

func GenerateNonce() string {
	return b64.StdEncoding.EncodeToString([]byte(randStringRunes(8)))
}

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func base64Decode(payload string) string {
	rem := len(payload) % 4
	log.Println("rem of payload=", rem)
	if rem > 0 {
		i := 4 - rem
		for ; i > 0; i-- {
			payload = payload + "="
		}
	}
	return payload
}
