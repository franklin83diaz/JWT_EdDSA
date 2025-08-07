package pkg

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
)

// GenerateKeyPair genera un par Ed25519.
func GenerateKeyPair() (pubB64, pkcs8PEM string, err error) {
	//generate seed (32 B)
	seed := make([]byte, ed25519.SeedSize)
	if _, err = rand.Read(seed); err != nil {
		return
	}

	priv := ed25519.NewKeyFromSeed(seed)

	derPriv, err := x509.MarshalPKCS8PrivateKey(priv)
	derPub, _ := x509.MarshalPKIXPublicKey(priv.Public())

	if err != nil {
		return
	}

	return base64.StdEncoding.EncodeToString(derPub), base64.StdEncoding.EncodeToString(derPriv), nil
}
