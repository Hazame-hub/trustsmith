package testpki_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

// The embedded key is the committed RFC 9500 vector, byte for byte.
func TestRFC9500KeyMatchesVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fingerprint", "testdata", "vectors", "ecdsa-p256", "pkcs8.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(data), "\r\n", "\n") != testpki.RFC9500TestECCP256 {
		t.Fatal("RFC9500TestECCP256 differs from the committed vector")
	}
	key := testpki.RFC9500P256Key(t)
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "fingerprint", "testdata", "vectors", "ecdsa-p256", "spki.der"))
	if err != nil {
		t.Fatal(err)
	}
	if string(spki) != string(want) {
		t.Error("public key differs from the vector SPKI")
	}
}
