package entity

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID     uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	UserID uuid.UUID `gorm:"type:uuid;not null;index"`
	User   User      `gorm:"constraint:OnDelete:CASCADE"`

	TokenHash string `gorm:"type:text;not null;index"`

	DeviceName string  `gorm:"type:varchar(100)"`
	DeviceID   string  `gorm:"type:varchar(255);not null"`
	IPAddress  *string `gorm:"type:varchar(45)"`
	UserAgent  *string `gorm:"type:text"`

	ExpiresAt time.Time
	RevokedAt *time.Time

	CreatedAt time.Time
}
