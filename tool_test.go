package social

import (
	"strings"
	"testing"
)

// TestCodeChallenge: Test the codeChallenge func.
func TestCodeChallenge(t *testing.T) {
	codeVerifier := "wJKN8qz5t8SSI9lMFhBB6qwNkQBkuPZoCxzRhwLRUo1"
	wantChan := "BSCQwo_m8Wf0fpjmwkIKmPAJ1A7tiuRSNDnXzODS7QI"
	codeChanllege := PkceChallenge(codeVerifier)
	if codeChanllege != wantChan {
		t.Errorf("CodeChannlege Error: \ncodeChan=%s\nwantChan=%s\n", codeChanllege, wantChan)
	}
}

func TestCodeVerifier(t *testing.T) {

	cv1, err := GenerateCodeVerifier(0)
	if err != nil {
		t.Errorf("GenerateCodeVerifier Error: %v", err)
		return
	}
	if len(cv1) != 43 {
		t.Errorf("CodeVerifier Error: \ncodeVer=%s\n", cv1)
	}

	if strings.Contains(cv1, "=") {
		t.Errorf("CodeVerifier Error: \ncodeVer=%s\n", cv1)
	}
}

func TestGenerateNonceIsRandomAndURLSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := GenerateNonce()
		if err != nil {
			t.Fatal(err)
		}
		if len(n) != 22 { // 16 bytes, base64url without padding
			t.Fatalf("len(%q) = %d, want 22", n, len(n))
		}
		if strings.ContainsAny(n, "+/=") {
			t.Fatalf("nonce %q is not URL safe", n)
		}
		if seen[n] {
			t.Fatalf("duplicate nonce %q", n)
		}
		seen[n] = true
	}
}
