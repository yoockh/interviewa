package entity

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type SecurityAction string

const (
	LoginSuccess   SecurityAction = "login_success"
	LoginFailed    SecurityAction = "login_failed"
	Logout         SecurityAction = "logout"
	Reset          SecurityAction = "password_reset"
	MFAFailed      SecurityAction = "mfa_failed"
	SessionRevoked SecurityAction = "session_revoked"
)

type SecurityLog struct {
	ID uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`

	UserID *uuid.UUID `gorm:"type:uuid;index"`
	User   *User      `gorm:"constraint:OnDelete:SET NULL"`

	IPAddress *string        `gorm:"type:varchar(45)"`
	Action    SecurityAction `gorm:"type:security_action;not null"`

	Metadata datatypes.JSON

	CreatedAt time.Time
}
