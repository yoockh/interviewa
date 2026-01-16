package entity

import (
	"time"

	"github.com/google/uuid"
)

type VerificationType string

const (
	EmailVerify   VerificationType = "email_verify"
	PasswordReset VerificationType = "password_reset"
	MagicLogin    VerificationType = "magic_login"
)

type VerificationToken struct {
	ID     uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	UserID uuid.UUID `gorm:"type:uuid;not null;index"`
	User   User      `gorm:"constraint:OnDelete:CASCADE"`

	TokenHash string           `gorm:"type:text;not null;index"`
	Type      VerificationType `gorm:"type:verification_type;not null"`

	ExpiresAt time.Time
	UsedAt    *time.Time

	CreatedAt time.Time
}
