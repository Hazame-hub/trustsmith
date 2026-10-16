package keyfacts_test

import (
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/keyfacts"
)

var vectors = filepath.Join("..", "fingerprint", "testdata", "vectors")

func read(t *testing.T, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{vectors}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The key identity of every ADR-0002 vector key equals the identity of the
// vector's SPKI, whichever encoding the key file uses.
func TestKeyIdentityMatchesTheVectorSPKI(t *testing.T) {
	for _, tc := range []struct {
		vector, file string
		format       keyfacts.Format
		algorithm    string
	}{
		{"ecdsa-p256", "key.pem", keyfacts.FormatSEC1, "ECDSA"},
		{"ecdsa-p256", "pkcs8.pem", keyfacts.FormatPKCS8, "ECDSA"},
		{"rsa-2048", "key.pem", keyfacts.FormatPKCS1, "RSA"},
		{"rsa-2048", "pkcs8.pem", keyfacts.FormatPKCS8, "RSA"},
		{"ed25519", "key.pem", keyfacts.FormatPKCS8, "Ed25519"},
		{"ml-dsa-65", "key.pem", keyfacts.FormatPKCS8, "ML-DSA"},
	} {
		k, err := keyfacts.Parse(read(t, tc.vector, tc.file))
		if err != nil {
			t.Errorf("%s/%s: %v", tc.vector, tc.file, err)
			continue
		}
		want, err := fingerprint.KeyIDFromSPKI(read(t, tc.vector, "spki.der"))
		if err != nil {
			t.Fatal(err)
		}
		if k.KeyID != want || k.Format != tc.format || k.Algorithm != tc.algorithm {
			t.Errorf("%s/%s: got %+v, want format %s, algorithm %s, key id %s", tc.vector, tc.file, k, tc.format, tc.algorithm, want)
		}
	}
}

func TestDERPKCS8(t *testing.T) {
	block, _ := pem.Decode(read(t, "ed25519", "pkcs8.pem"))
	k, err := keyfacts.Parse(block.Bytes)
	if err != nil || k.Algorithm != "Ed25519" || k.Label != "" {
		t.Errorf("got %+v, %v", k, err)
	}
}

func TestCompanionBlocksAreSkipped(t *testing.T) {
	cert := read(t, "ecdsa-p256", "cert.pem")
	key := read(t, "ecdsa-p256", "key.pem")
	params := []byte("-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n")
	for name, data := range map[string][]byte{
		"cert then key":   append(append([]byte{}, cert...), key...),
		"params then key": append(append([]byte{}, params...), key...),
	} {
		if _, err := keyfacts.Parse(data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRefusals(t *testing.T) {
	key := read(t, "ecdsa-p256", "key.pem")
	corrupt := strings.Replace(string(key), "M", "!", 1)
	for name, tc := range map[string]struct {
		data string
		want error
	}{
		"pkcs8 encrypted":  {"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMAA=\n-----END ENCRYPTED PRIVATE KEY-----\n", keyfacts.ErrEncrypted},
		"legacy encrypted": {"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00000000000000000000000000000000\n\nMAA=\n-----END RSA PRIVATE KEY-----\n", keyfacts.ErrEncrypted},
		"two keys":         {string(key) + string(read(t, "rsa-2048", "key.pem")), keyfacts.ErrManyKeys},
		"certificate only": {string(read(t, "ecdsa-p256", "cert.pem")), keyfacts.ErrNoKey},
		"empty":            {"", keyfacts.ErrNoKey},
		"not DER":          {"hello", keyfacts.ErrNoKey},
		"public key":       {string(read(t, "ecdsa-p256", "spki.pem")), keyfacts.ErrUnreadable},
		"corrupt armour":   {corrupt, keyfacts.ErrUnreadable},
		"bad contents":     {"-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n", keyfacts.ErrUnreadable},
	} {
		if _, err := keyfacts.Parse([]byte(tc.data)); !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", name, err, tc.want)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, name := range []string{"ecdsa-p256/key.pem", "rsa-2048/key.pem", "ed25519/pkcs8.pem"} {
		data, err := os.ReadFile(filepath.Join(vectors, filepath.FromSlash(name)))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := keyfacts.Parse(data)
		if err == nil && k.KeyID.IsZero() {
			t.Error("a parsed key has no identity")
		}
	})
}
