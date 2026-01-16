package entity

import (
	"time"

	"github.com/google/uuid"
)

type UserRole string

const (
	UserRoleUser  UserRole = "user"
	UserRoleAdmin UserRole = "admin"
)

type User struct {
	ID           uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Email        string    `gorm:"type:varchar(255);uniqueIndex;not null"`
	PasswordHash *string   `gorm:"type:text"`
	Role         UserRole  `gorm:"type:user_role;default:'user';not null"`

	EmailVerifiedAt *time.Time
	IsActive        bool `gorm:"default:true"`

	CreatedAt time.Time
	UpdatedAt time.Time

	Sessions  []Session
	MFASecret *MFASecret
}
