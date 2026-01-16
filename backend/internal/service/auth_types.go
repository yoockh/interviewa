package service

import (
	"context"
	"time"

	"interviewa/internal/entity"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthConfig struct {
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	VerificationTokenTTL time.Duration
	ResetTokenTTL        time.Duration
	MFATokenTTL          time.Duration
	MFAIssuer            string
}

type EmailSender interface {
	SendVerificationEmail(ctx context.Context, email string, token string) error
	SendPasswordResetEmail(ctx context.Context, email string, token string) error
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hash string, password string) bool
}

type AccessTokenIssuer interface {
	IssueAccessToken(user entity.User, sessionID uuid.UUID) (string, time.Duration, error)
}

type MFATokenIssuer interface {
	IssueMFAToken(userID uuid.UUID) (string, time.Duration, error)
	ParseMFAToken(token string) (uuid.UUID, error)
}

type MFAProvider interface {
	GenerateSecret() (string, error)
	QRCodeURL(email string, issuer string, secret string) (string, error)
	ValidateCode(secret string, code string) bool
}

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}

type BcryptPasswordHasher struct {
	Cost int
}

func (h BcryptPasswordHasher) Hash(password string) (string, error) {
	cost := h.Cost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (h BcryptPasswordHasher) Verify(hash string, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
