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

	cv1 := GenerateCodeVerifier(0)
	if len(cv1) != 43 {
		t.Errorf("CodeVerifier Error: \ncodeVer=%s\n", cv1)
	}

	if strings.Contains(cv1, "=") {
		t.Errorf("CodeVerifier Error: \ncodeVer=%s\n", cv1)
	}
}
