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

// GenerateNonce: Generate a random, URL-safe string with 128 bits of entropy.
// Suitable for the OAuth "state" and OIDC "nonce" parameters.
func GenerateNonce() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return b64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func randStringRunes(n int) (string, error) {
	var result []rune
	letterRunesLen := len(letterRunes)
	for range n {
		var randomBytes [1]byte
		for {
			_, err := rand.Read(randomBytes[:])
			if err != nil {
				return "", err
			}
			// reject values that would make the modulo biased
			if int(randomBytes[0]) < 256-256%letterRunesLen {
				break
			}
		}
		result = append(result, letterRunes[int(randomBytes[0])%letterRunesLen])
	}
	return string(result), nil
}
