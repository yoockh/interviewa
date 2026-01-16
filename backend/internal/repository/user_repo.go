package repository

import (
	"context"
	"errors"
	"time"

	"interviewa/internal/entity"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRepository interface {
	Create(ctx context.Context, user *entity.User) error
	FindByID(ctx context.Context, id uuid.UUID) (*entity.User, error)
	FindByEmail(ctx context.Context, email string) (*entity.User, error)
	Update(ctx context.Context, user *entity.User) error
	VerifyEmail(ctx context.Context, userID uuid.UUID) error
	List(ctx context.Context, limit, offset int) ([]entity.User, error)
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *entity.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepository) FindByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	var user entity.User
	err := r.db.WithContext(ctx).
		Where("id = ? AND is_active = true", id).
		First(&user).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, err
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*entity.User, error) {
	var user entity.User
	err := r.db.WithContext(ctx).
		Where("email = ? AND is_active = true", email).
		First(&user).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, err
}

func (r *userRepository) Update(ctx context.Context, user *entity.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *userRepository) VerifyEmail(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&entity.User{}).
		Where("id = ?", userID).
		Update("email_verified_at", &now).
		Error
}

func (r *userRepository) List(ctx context.Context, limit, offset int) ([]entity.User, error) {
	var users []entity.User
	query := r.db.WithContext(ctx).Where("is_active = true").Order("created_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	if err := query.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}
