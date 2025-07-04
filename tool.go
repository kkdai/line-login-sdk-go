package social

import (
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")

// PkceChallenge: base64-URL-encoded SHA256 hash of verifier, per rfc 7636
func PkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	challenge := b64.URLEncoding.WithPadding(b64.NoPadding).EncodeToString(sum[:])
	return (challenge)
}

// GenerateCodeVerifier: Generate code verifier (length 43~128) for PKCE.
func GenerateCodeVerifier(length int) (string, error) {
	if length > 128 {
		length = 128
	}
	if length < 43 {
		length = 43
	}
	return randStringRunes(length)
}

func GenerateNonce() (string, error) {
	randomStr, err := randStringRunes(8)
	if err != nil {
		return "", err
	}
	return b64.StdEncoding.EncodeToString([]byte(randomStr)), nil
}

func randStringRunes(n int) (string, error) {
	var result []rune
	letterRunesLen := len(letterRunes)
	for range n {
		var randomBytes [1]byte
		_, err := rand.Read(randomBytes[:])
		if err != nil {
			return "", err
		}
		index := int(randomBytes[0]) % letterRunesLen
		result = append(result, letterRunes[index])
	}
	return string(result), nil
}
