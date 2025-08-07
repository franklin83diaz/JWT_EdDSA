package pkg

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// GenJWTFromJSON generates a JWT token from JSON claims and a private key in base64 format.
// The private key should be in PKCS#8 format and base64 encoded.
// It returns the signed JWT token as a string or an error if the process fails.
func GenJWTFromJSON(jsonStr, privB64 string) (string, error) {
	// Decode base64 private key
	if len(privB64) == 0 {
		return "", errors.New("private key is empty")
	}
	der, err := base64.StdEncoding.DecodeString(string(privB64))
	if err != nil {
		return "", err
	}

	// Convert DER ➜ ed25519.PrivateKey
	privAny, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", err
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("not a valid ed25519 private key")
	}

	// Unmarshal JSON claims
	var claims jwt.MapClaims
	if err := json.Unmarshal([]byte(jsonStr), &claims); err != nil {
		return "", err
	}

	// Create a new JWT token with the claims and sign it with the private key
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return tok.SignedString(priv)
}

// Verify checks the validity of a JWT token using a public key in base64 format.
// It returns the claims as a JSON string if the token is valid, or an error if verification fails.
// The public key should be in PKIX format and base64 encoded.
// If the token is not valid, it returns an error indicating the failure.
func Verify(tokenStr string, pubB64 string) (r string, e error) {
	// Decode base64 public key
	if pubB64 == "" {
		return "", errors.New("public key is empty")
	}
	der, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return "", err
	}

	// Convert DER ➜ ed25519.PublicKey
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", err
	}
	pubBytes := pubAny.(ed25519.PublicKey)

	// Parse the JWT token
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, errors.New("error")
		}
		return pubBytes, nil
	})
	if err != nil {
		return "", err
	}

	// Check if the token is valid and extract claims
	if claims, ok := tok.Claims.(jwt.MapClaims); ok && tok.Valid {
		claimsJSON, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			fmt.Println("Error claims:", err)
		} else {
			return string(claimsJSON), nil
		}
	}

	return "", errors.New("token not valid")
}
