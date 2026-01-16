package dto

import (
	"time"

	"interviewa/internal/entity"
)

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

type LoginRequest struct {
	Email      string `json:"email" validate:"required,email"`
	Password   string `json:"password" validate:"required"`
	DeviceID   string `json:"device_id" validate:"required"`
	DeviceName string `json:"device_name" validate:"omitempty"`
}

type LoginMFARequest struct {
	MFAToken   string `json:"mfa_token" validate:"required"`
	Code       string `json:"code" validate:"required"`
	DeviceID   string `json:"device_id" validate:"required"`
	DeviceName string `json:"device_name" validate:"omitempty"`
}

type LoginResponse struct {
	AccessToken       string `json:"access_token,omitempty"`
	ExpiresIn         int64  `json:"expires_in,omitempty"`
	RefreshToken      string `json:"refresh_token,omitempty"`
	RefreshExpiresIn  int64  `json:"refresh_expires_in,omitempty"`
	MFARequired       bool   `json:"mfa_required,omitempty"`
	MFAToken          string `json:"mfa_token,omitempty"`
	MFATokenExpiresIn int64  `json:"mfa_token_expires_in,omitempty"`
}

type PasswordForgotRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type PasswordResetRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

type MFAEnableResponse struct {
	QRCode string `json:"qr_code"`
}

type MFAVerifyRequest struct {
	Code string `json:"code" validate:"required"`
}

type UserResponse struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	Role            string     `json:"role"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	IsActive        bool       `json:"is_active"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func UserResponseFromEntity(user *entity.User) UserResponse {
	return UserResponse{
		ID:              user.ID.String(),
		Email:           user.Email,
		Role:            string(user.Role),
		EmailVerifiedAt: user.EmailVerifiedAt,
		IsActive:        user.IsActive,
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
	}
}

func UserResponsesFromEntities(users []entity.User) []UserResponse {
	responses := make([]UserResponse, 0, len(users))
	for i := range users {
		responses = append(responses, UserResponseFromEntity(&users[i]))
	}
	return responses
}
