package testpki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
)

// RFC9500TestECCP256 is the published RFC 9500 section 2.3 testECCP256 key
// (PKCS #8), the same key as internal/fingerprint/testdata/vectors/ecdsa-p256.
// It is public test material: a test TLS server presents committed
// certificates on this key, so no new private key is added to the repository.
const RFC9500TestECCP256 = "-----BEGIN PRIVATE KEY-----\n" +
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5stb3YCqRa6clejB\n" +
	"VHZnn/7JU8FoUecR50OTlYnGT8GhRANCAARCJUj4j7eC/7Xso3REUscqHlWPvW9z\n" +
	"vl5I6TIyzEXFsWxM0QxMuNW4oXE56UiCyJklcpk0JfQUGat+kKQqSUJy\n" +
	"-----END PRIVATE KEY-----\n"

// RFC9500P256Key parses RFC9500TestECCP256.
func RFC9500P256Key(f Fataler) *ecdsa.PrivateKey {
	f.Helper()
	block, _ := pem.Decode([]byte(RFC9500TestECCP256))
	if block == nil {
		f.Fatalf("RFC 9500 test key: no PEM block")
		return nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		f.Fatalf("RFC 9500 test key: %v", err)
		return nil
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		f.Fatalf("RFC 9500 test key is a %T", k)
		return nil
	}
	return key
}
