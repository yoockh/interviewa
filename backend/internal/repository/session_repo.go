package repository

import (
	"context"
	"errors"
	"interviewa/internal/entity"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SessionRepository interface {
	Create(ctx context.Context, session *entity.Session) error
	FindByTokenHash(ctx context.Context, hash string) (*entity.Session, error)
	Revoke(ctx context.Context, sessionID uuid.UUID) error
	RevokeAllByUser(ctx context.Context, userID uuid.UUID) error
	CleanupExpired(ctx context.Context) error
}

type sessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) SessionRepository {
	return &sessionRepository{db: db}
}

func (r *sessionRepository) Create(ctx context.Context, s *entity.Session) error {
	return r.db.WithContext(ctx).Create(s).Error
}

func (r *sessionRepository) FindByTokenHash(ctx context.Context, hash string) (*entity.Session, error) {
	var session entity.Session
	err := r.db.WithContext(ctx).
		Where("token_hash = ? AND revoked_at IS NULL AND expires_at > NOW()", hash).
		First(&session).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &session, err
}

func (r *sessionRepository) Revoke(ctx context.Context, sessionID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&entity.Session{}).
		Where("id = ?", sessionID).
		Update("revoked_at", &now).
		Error
}

func (r *sessionRepository) RevokeAllByUser(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&entity.Session{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", &now).
		Error
}

func (r *sessionRepository) CleanupExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < NOW()").
		Delete(&entity.Session{}).
		Error
}
