package auth

import (
	"crypto/ed25519"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	PrivateKey ed25519.PrivateKey
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	Issuer     string
	Audience   []string
}

func NewSigner(privateKey ed25519.PrivateKey, accessTTL, refreshTTL time.Duration, issuer string, audience []string) *Signer {
	return &Signer{
		PrivateKey: privateKey,
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
		Issuer:     issuer,
		Audience:   audience,
	}
}

func (s *Signer) IssueAccessToken(userID int64, roles []string) (string, error) {
	return s.issue(userID, "access", s.AccessTTL, roles, s.Audience, false)
}

func (s *Signer) IssueRefreshToken(userID int64) (token, jti string, err error) {
	claims := newClaims(userID, "refresh", s.RefreshTTL, nil, s.Issuer, []string{s.Issuer}, true)
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token, err = t.SignedString(s.PrivateKey)
	if err != nil {
		return "", "", err
	}
	return token, claims.ID, nil
}

func (s *Signer) issue(userID int64, typ string, ttl time.Duration, roles []string, audience []string, withJTI bool) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, newClaims(userID, typ, ttl, roles, s.Issuer, audience, withJTI))
	return t.SignedString(s.PrivateKey)
}

func (s *Signer) AccessTTLSeconds() int64 {
	return int64(s.AccessTTL.Seconds())
}
