package repository

import (
	"context"
	"interviewa/internal/entity"

	"gorm.io/gorm"
)

type SecurityLogRepository interface {
	Log(ctx context.Context, log *entity.SecurityLog) error
}

type securityLogRepository struct {
	db *gorm.DB
}

func NewSecurityLogRepository(db *gorm.DB) SecurityLogRepository {
	return &securityLogRepository{db: db}
}

func (r *securityLogRepository) Log(ctx context.Context, log *entity.SecurityLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}
