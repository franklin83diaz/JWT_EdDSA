package pkg

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func GenJWTFromJSON(jsonStr string, privPEM []byte) (string, error) {
	priv, err := jwt.ParseEdPrivateKeyFromPEM(privPEM)
	if err != nil {
		return "", err
	}

	var claims jwt.MapClaims
	if err := json.Unmarshal([]byte(jsonStr), &claims); err != nil {
		return "", err
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return tok.SignedString(priv)
}

// return claims as string
func VerifyJWT(tokenStr string, pubPEM []byte) (r string, e error) {
	pub, err := jwt.ParseEdPublicKeyFromPEM(pubPEM)
	if err != nil {
		return "", err
	}

	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, errors.New("error")
		}
		return pub, nil
	})
	if err != nil {
		return "", err
	}

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
