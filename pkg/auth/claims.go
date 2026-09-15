package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	Issuer          = "shop-auth"
	AudienceAuth    = "shop-auth"
	AudienceCatalog = "shop-catalog"
	AudienceCart    = "shop-cart"
	AudienceOrder   = "shop-order"
	AudiencePayment = "shop-payment"
)

var AccessAudiences = []string{
	AudienceAuth,
	AudienceCatalog,
	AudienceCart,
	AudienceOrder,
	AudiencePayment,
}

type Claims struct {
	UserID int64    `json:"uid"`
	Type   string   `json:"type"`
	Roles  []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

func newClaims(userID int64, typ string, ttl time.Duration, roles []string, issuer string, audience []string, withJTI bool) Claims {
	now := time.Now()
	rc := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		IssuedAt:  jwt.NewNumericDate(now),
		Issuer:    issuer,
		Audience:  audience,
	}
	if withJTI {
		rc.ID = newJTI()
	}
	return Claims{
		UserID:           userID,
		Type:             typ,
		Roles:            roles,
		RegisteredClaims: rc,
	}
}

func newJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
