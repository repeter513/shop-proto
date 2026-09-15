package auth

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Verifier struct {
	PublicKey        ed25519.PublicKey
	ExpectedIssuer   string
	ExpectedAudience string
}

func NewVerifier(publicKey ed25519.PublicKey, issuer, audience string) *Verifier {
	return &Verifier{
		PublicKey:        publicKey,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
	}
}

func (v *Verifier) Parse(token string) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithIssuer(v.ExpectedIssuer), jwt.WithAudience(v.ExpectedAudience))
	t, err := parser.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("unexpected alg: %v", t.Header["alg"])
		}
		return v.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func (v *Verifier) ParseAccess(token string) (*Claims, error) {
	c, err := v.Parse(token)
	if err != nil {
		return nil, err
	}
	if c.Type != "access" {
		return nil, errors.New("not an access token")
	}
	return c, nil
}

func (v *Verifier) ParseRefresh(token string) (*Claims, error) {
	c, err := v.Parse(token)
	if err != nil {
		return nil, err
	}
	if c.Type != "refresh" {
		return nil, errors.New("not a refresh token")
	}
	if c.ID == "" {
		return nil, errors.New("missing jti")
	}
	return c, nil
}

func ParseAccessUserID(token string, v *Verifier) (int64, error) {
	c, err := v.ParseAccess(token)
	if err != nil {
		return 0, err
	}
	return c.UserID, nil
}
