package repository

import (
	"context"
	"errors"
	"interviewa/internal/entity"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type VerificationTokenRepository interface {
	Create(ctx context.Context, token *entity.VerificationToken) error
	FindValid(ctx context.Context, tokenHash string, tokenType entity.VerificationType) (*entity.VerificationToken, error)
	MarkUsed(ctx context.Context, id uuid.UUID) error
}

type verificationTokenRepository struct {
	db *gorm.DB
}

func NewVerificationTokenRepository(db *gorm.DB) VerificationTokenRepository {
	return &verificationTokenRepository{db: db}
}

func (r *verificationTokenRepository) Create(ctx context.Context, t *entity.VerificationToken) error {
	return r.db.WithContext(ctx).Create(t).Error
}

func (r *verificationTokenRepository) FindValid(
	ctx context.Context,
	tokenHash string,
	tokenType entity.VerificationType,
) (*entity.VerificationToken, error) {

	var token entity.VerificationToken
	err := r.db.WithContext(ctx).
		Where(`
			token_hash = ? AND 
			type = ? AND
			used_at IS NULL AND
			expires_at > NOW()
		`, tokenHash, tokenType).
		First(&token).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &token, err
}

func (r *verificationTokenRepository) MarkUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&entity.VerificationToken{}).
		Where("id = ?", id).
		Update("used_at", &now).
		Error
}
