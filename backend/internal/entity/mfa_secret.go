package entity

import (
	"time"

	"github.com/google/uuid"
)

type MFASecret struct {
	ID     uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	UserID uuid.UUID `gorm:"type:uuid;uniqueIndex;not null"`
	User   User      `gorm:"constraint:OnDelete:CASCADE"`

	Secret    string `gorm:"type:text;not null"`
	EnabledAt *time.Time

	CreatedAt time.Time
}
