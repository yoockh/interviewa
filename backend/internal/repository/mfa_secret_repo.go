package repository

import (
	"context"
	"errors"
	"interviewa/internal/entity"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type MFASecretRepository interface {
	FindByUserID(ctx context.Context, userID uuid.UUID) (*entity.MFASecret, error)
	Upsert(ctx context.Context, secret *entity.MFASecret) error
	Disable(ctx context.Context, userID uuid.UUID) error
}

type mfaSecretRepository struct {
	db *gorm.DB
}

func NewMFASecretRepository(db *gorm.DB) MFASecretRepository {
	return &mfaSecretRepository{db: db}
}

func (r *mfaSecretRepository) FindByUserID(ctx context.Context, userID uuid.UUID) (*entity.MFASecret, error) {
	var secret entity.MFASecret
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		First(&secret).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &secret, err
}

func (r *mfaSecretRepository) Upsert(ctx context.Context, secret *entity.MFASecret) error {
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"secret", "enabled_at"}),
		}).
		Create(secret).Error
}

func (r *mfaSecretRepository) Disable(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Model(&entity.MFASecret{}).
		Where("user_id = ?", userID).
		Update("enabled_at", nil).
		Error
}
