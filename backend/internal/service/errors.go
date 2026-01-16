package service

import "errors"

var (
	ErrInvalidInput           = errors.New("invalid input")
	ErrEmailAlreadyRegistered = errors.New("email already registered")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrEmailNotVerified       = errors.New("email not verified")
	ErrInvalidToken           = errors.New("invalid or expired token")
	ErrMFARequired            = errors.New("mfa required")
	ErrInvalidMFACode         = errors.New("invalid mfa code")
	ErrMFANotConfigured       = errors.New("mfa not configured")
	ErrUserNotFound           = errors.New("user not found")
)
