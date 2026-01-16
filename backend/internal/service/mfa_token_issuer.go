package service

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var ErrInvalidMFAToken = errors.New("invalid mfa token")

type MFATokenIssuerJWT struct {
	Secret []byte
	Issuer string
	TTL    time.Duration
}

type mfaClaims struct {
	UserID string `json:"sub"`
	Type   string `json:"typ"`
	jwt.RegisteredClaims
}

func (m MFATokenIssuerJWT) IssueMFAToken(userID uuid.UUID) (string, time.Duration, error) {
	ttl := m.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()
	claims := mfaClaims{
		UserID: userID.String(),
		Type:   "mfa",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.Issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.Secret)
	if err != nil {
		return "", 0, err
	}
	return signed, ttl, nil
}

func (m MFATokenIssuerJWT) ParseMFAToken(token string) (uuid.UUID, error) {
	parsed, err := jwt.ParseWithClaims(token, &mfaClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidMFAToken
		}
		return m.Secret, nil
	})
	if err != nil {
		return uuid.Nil, ErrInvalidMFAToken
	}
	claims, ok := parsed.Claims.(*mfaClaims)
	if !ok || !parsed.Valid || claims.Type != "mfa" {
		return uuid.Nil, ErrInvalidMFAToken
	}
	id, err := uuid.Parse(claims.UserID)
	if err != nil {
		return uuid.Nil, ErrInvalidMFAToken
	}
	return id, nil
}
