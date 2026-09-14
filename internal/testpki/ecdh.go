package testpki

import (
	"crypto/ecdh"
	"crypto/rand"
)

func ecdhX25519() (*ecdh.PublicKey, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return k.PublicKey(), nil
}
