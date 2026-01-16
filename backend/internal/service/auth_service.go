package service

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"interviewa/internal/dto"
	"interviewa/internal/entity"
	"interviewa/internal/repository"
	"interviewa/internal/utils"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

const dummyPasswordHash = "$2a$10$CwTycUXWue0Thq9StjUM0uJ8yQbWc1x9uxw2sQ2sXUNx5x9xJ9F2S"

type AuthService struct {
	users         repository.UserRepository
	sessions      repository.SessionRepository
	verifications repository.VerificationTokenRepository
	mfaSecrets    repository.MFASecretRepository
	securityLogs  repository.SecurityLogRepository

	emailSender  EmailSender
	passwordHash PasswordHasher
	accessTokens AccessTokenIssuer
	mfaTokens    MFATokenIssuer
	mfaProvider  MFAProvider
	clock        Clock
	config       AuthConfig
}

func NewAuthService(
	users repository.UserRepository,
	sessions repository.SessionRepository,
	verifications repository.VerificationTokenRepository,
	mfaSecrets repository.MFASecretRepository,
	securityLogs repository.SecurityLogRepository,
	emailSender EmailSender,
	passwordHash PasswordHasher,
	accessTokens AccessTokenIssuer,
	mfaTokens MFATokenIssuer,
	mfaProvider MFAProvider,
	clock Clock,
	config AuthConfig,
) *AuthService {
	return &AuthService{
		users:         users,
		sessions:      sessions,
		verifications: verifications,
		mfaSecrets:    mfaSecrets,
		securityLogs:  securityLogs,
		emailSender:   emailSender,
		passwordHash:  passwordHash,
		accessTokens:  accessTokens,
		mfaTokens:     mfaTokens,
		mfaProvider:   mfaProvider,
		clock:         clock,
		config:        config,
	}
}

func (s *AuthService) Register(ctx context.Context, input dto.RegisterRequest) error {
	if strings.TrimSpace(input.Email) == "" || strings.TrimSpace(input.Password) == "" {
		return ErrInvalidInput
	}

	email := utils.NormalizeEmail(input.Email)
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return err
	}
	if user != nil {
		if user.EmailVerifiedAt != nil {
			return ErrEmailAlreadyRegistered
		}
		return s.sendEmailVerification(ctx, user)
	}

	hash, err := s.passwordHash.Hash(input.Password)
	if err != nil {
		return err
	}

	newUser := &entity.User{
		Email:        email,
		PasswordHash: &hash,
		Role:         entity.UserRoleUser,
		IsActive:     true,
	}
	if err := s.users.Create(ctx, newUser); err != nil {
		return err
	}

	return s.sendEmailVerification(ctx, newUser)
}

func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	verification, err := s.verifications.FindValid(ctx, utils.HashToken(token), entity.EmailVerify)
	if err != nil {
		return err
	}
	if verification == nil {
		return ErrInvalidToken
	}

	if err := s.users.VerifyEmail(ctx, verification.UserID); err != nil {
		return err
	}

	if err := s.verifications.MarkUsed(ctx, verification.ID); err != nil {
		return err
	}
	return nil
}

func (s *AuthService) Login(ctx context.Context, input dto.LoginRequest, ipAddress *string, userAgent *string) (*dto.LoginResponse, error) {
	if strings.TrimSpace(input.Email) == "" || strings.TrimSpace(input.Password) == "" || strings.TrimSpace(input.DeviceID) == "" {
		return nil, ErrInvalidInput
	}

	email := utils.NormalizeEmail(input.Email)
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil || user.PasswordHash == nil {
		_ = s.passwordHash.Verify(dummyPasswordHash, input.Password)
		_ = s.logSecurity(ctx, nil, ipAddress, entity.LoginFailed, map[string]any{"email": email})
		return nil, ErrInvalidCredentials
	}

	if !s.passwordHash.Verify(*user.PasswordHash, input.Password) {
		_ = s.logSecurity(ctx, &user.ID, ipAddress, entity.LoginFailed, map[string]any{"email": email})
		return nil, ErrInvalidCredentials
	}

	if user.EmailVerifiedAt == nil {
		return nil, ErrEmailNotVerified
	}

	if s.mfaProvider != nil && s.mfaSecrets != nil && s.mfaTokens != nil {
		secret, err := s.mfaSecrets.FindByUserID(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		if secret != nil && secret.EnabledAt != nil {
			mfaToken, expiresIn, err := s.mfaTokens.IssueMFAToken(user.ID)
			if err != nil {
				return nil, err
			}
			return &dto.LoginResponse{
				MFARequired:       true,
				MFAToken:          mfaToken,
				MFATokenExpiresIn: int64(expiresIn.Seconds()),
			}, nil
		}
	}

	result, err := s.createSessionAndTokens(ctx, user, input.DeviceID, input.DeviceName, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	_ = s.logSecurity(ctx, &user.ID, ipAddress, entity.LoginSuccess, map[string]any{"device_id": input.DeviceID})
	return result, nil
}

func (s *AuthService) LoginWithMFA(ctx context.Context, input dto.LoginMFARequest, ipAddress *string, userAgent *string) (*dto.LoginResponse, error) {
	if s.mfaProvider == nil || s.mfaTokens == nil || s.mfaSecrets == nil {
		return nil, ErrMFANotConfigured
	}
	if strings.TrimSpace(input.MFAToken) == "" || strings.TrimSpace(input.Code) == "" || strings.TrimSpace(input.DeviceID) == "" {
		return nil, ErrInvalidInput
	}
	userID, err := s.mfaTokens.ParseMFAToken(input.MFAToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	secret, err := s.mfaSecrets.FindByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.EnabledAt == nil {
		return nil, ErrMFARequired
	}
	if !s.mfaProvider.ValidateCode(secret.Secret, input.Code) {
		_ = s.logSecurity(ctx, &user.ID, ipAddress, entity.MFAFailed, map[string]any{"device_id": input.DeviceID})
		return nil, ErrInvalidMFACode
	}

	result, err := s.createSessionAndTokens(ctx, user, input.DeviceID, input.DeviceName, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}
	_ = s.logSecurity(ctx, &user.ID, ipAddress, entity.LoginSuccess, map[string]any{"device_id": input.DeviceID, "mfa": true})
	return result, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*dto.LoginResponse, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, ErrInvalidInput
	}

	session, err := s.sessions.FindByTokenHash(ctx, utils.HashToken(refreshToken))
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrInvalidToken
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	newRefreshToken, newRefreshHash, newRefreshExpiry, err := s.buildRefreshToken()
	if err != nil {
		return nil, err
	}

	if err := s.sessions.RotateToken(ctx, session.ID, newRefreshHash, newRefreshExpiry); err != nil {
		return nil, err
	}

	accessToken, expiresIn, err := s.accessTokens.IssueAccessToken(*user, session.ID)
	if err != nil {
		return nil, err
	}

	return &dto.LoginResponse{
		AccessToken:      accessToken,
		ExpiresIn:        int64(expiresIn.Seconds()),
		RefreshToken:     newRefreshToken,
		RefreshExpiresIn: int64(newRefreshExpiry.Sub(s.now()).Seconds()),
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, sessionID uuid.UUID, userID *uuid.UUID, ipAddress *string) error {
	if err := s.sessions.Revoke(ctx, sessionID); err != nil {
		return err
	}
	_ = s.logSecurity(ctx, userID, ipAddress, entity.Logout, nil)
	return nil
}

func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID, ipAddress *string) error {
	if err := s.sessions.RevokeAllByUser(ctx, userID); err != nil {
		return err
	}
	_ = s.logSecurity(ctx, &userID, ipAddress, entity.SessionRevoked, map[string]any{"scope": "all"})
	return nil
}

func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	if strings.TrimSpace(email) == "" {
		return ErrInvalidInput
	}

	user, err := s.users.FindByEmail(ctx, utils.NormalizeEmail(email))
	if err != nil {
		return err
	}
	if user == nil || user.EmailVerifiedAt == nil {
		return nil
	}

	token, err := s.createVerificationToken(ctx, user.ID, entity.PasswordReset, s.resetTokenTTL())
	if err != nil {
		return err
	}

	if s.emailSender != nil {
		if err := s.emailSender.SendPasswordResetEmail(ctx, user.Email, token); err != nil {
			return err
		}
	}

	_ = s.logSecurity(ctx, &user.ID, nil, entity.Reset, nil)
	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, token string, newPassword string) error {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(newPassword) == "" {
		return ErrInvalidInput
	}

	verification, err := s.verifications.FindValid(ctx, utils.HashToken(token), entity.PasswordReset)
	if err != nil {
		return err
	}
	if verification == nil {
		return ErrInvalidToken
	}

	user, err := s.users.FindByID(ctx, verification.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	hash, err := s.passwordHash.Hash(newPassword)
	if err != nil {
		return err
	}
	user.PasswordHash = &hash
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}

	if err := s.verifications.MarkUsed(ctx, verification.ID); err != nil {
		return err
	}

	_ = s.sessions.RevokeAllByUser(ctx, user.ID)
	_ = s.logSecurity(ctx, &user.ID, nil, entity.Reset, map[string]any{"source": "password_reset"})
	return nil
}

func (s *AuthService) EnableMFA(ctx context.Context, userID uuid.UUID) (string, error) {
	if s.mfaProvider == nil || s.mfaSecrets == nil {
		return "", ErrMFANotConfigured
	}
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", ErrUserNotFound
	}

	secret, err := s.mfaProvider.GenerateSecret()
	if err != nil {
		return "", err
	}

	mfaSecret := &entity.MFASecret{
		UserID:    user.ID,
		Secret:    secret,
		EnabledAt: nil,
	}
	if err := s.mfaSecrets.Upsert(ctx, mfaSecret); err != nil {
		return "", err
	}

	issuer := s.config.MFAIssuer
	if strings.TrimSpace(issuer) == "" {
		issuer = "Interviewa"
	}
	qr, err := s.mfaProvider.QRCodeURL(user.Email, issuer, secret)
	if err != nil {
		return "", err
	}
	return qr, nil
}

func (s *AuthService) VerifyMFA(ctx context.Context, userID uuid.UUID, code string) error {
	if s.mfaProvider == nil || s.mfaSecrets == nil {
		return ErrMFANotConfigured
	}
	if strings.TrimSpace(code) == "" {
		return ErrInvalidInput
	}
	secret, err := s.mfaSecrets.FindByUserID(ctx, userID)
	if err != nil {
		return err
	}
	if secret == nil {
		return ErrMFARequired
	}
	if !s.mfaProvider.ValidateCode(secret.Secret, code) {
		return ErrInvalidMFACode
	}

	now := s.now()
	secret.EnabledAt = &now
	if err := s.mfaSecrets.Upsert(ctx, secret); err != nil {
		return err
	}
	return nil
}

func (s *AuthService) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	if s.mfaSecrets == nil {
		return nil
	}
	return s.mfaSecrets.Disable(ctx, userID)
}

func (s *AuthService) GetCurrentUser(ctx context.Context, userID uuid.UUID) (*entity.User, error) {
	return s.users.FindByID(ctx, userID)
}

func (s *AuthService) ListUsers(ctx context.Context, limit, offset int) ([]entity.User, error) {
	return s.users.List(ctx, limit, offset)
}

func (s *AuthService) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	return s.sessions.RevokeAllByUser(ctx, userID)
}

func (s *AuthService) createSessionAndTokens(
	ctx context.Context,
	user *entity.User,
	deviceID string,
	deviceName string,
	ipAddress *string,
	userAgent *string,
) (*dto.LoginResponse, error) {
	refreshToken, refreshHash, refreshExpiry, err := s.buildRefreshToken()
	if err != nil {
		return nil, err
	}

	session := &entity.Session{
		UserID:     user.ID,
		TokenHash:  refreshHash,
		DeviceID:   deviceID,
		DeviceName: deviceName,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		ExpiresAt:  refreshExpiry,
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, err
	}

	accessToken, expiresIn, err := s.accessTokens.IssueAccessToken(*user, session.ID)
	if err != nil {
		return nil, err
	}

	return &dto.LoginResponse{
		AccessToken:      accessToken,
		ExpiresIn:        int64(expiresIn.Seconds()),
		RefreshToken:     refreshToken,
		RefreshExpiresIn: int64(refreshExpiry.Sub(s.now()).Seconds()),
	}, nil
}

func (s *AuthService) sendEmailVerification(ctx context.Context, user *entity.User) error {
	if s.emailSender == nil {
		return nil
	}
	verificationToken, err := s.createVerificationToken(ctx, user.ID, entity.EmailVerify, s.verificationTokenTTL())
	if err != nil {
		return err
	}
	return s.emailSender.SendVerificationEmail(ctx, user.Email, verificationToken)
}

func (s *AuthService) createVerificationToken(
	ctx context.Context,
	userID uuid.UUID,
	typeValue entity.VerificationType,
	ttl time.Duration,
) (string, error) {
	rawToken, err := utils.GenerateRandomToken(32)
	if err != nil {
		return "", err
	}

	expiresAt := s.now().Add(ttl)
	verification := &entity.VerificationToken{
		UserID:    userID,
		TokenHash: utils.HashToken(rawToken),
		Type:      typeValue,
		ExpiresAt: expiresAt,
	}
	if err := s.verifications.Create(ctx, verification); err != nil {
		return "", err
	}
	return rawToken, nil
}

func (s *AuthService) buildRefreshToken() (string, string, time.Time, error) {
	rawToken, err := utils.GenerateRandomToken(48)
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiresAt := s.now().Add(s.refreshTokenTTL())
	return rawToken, utils.HashToken(rawToken), expiresAt, nil
}

func (s *AuthService) logSecurity(
	ctx context.Context,
	userID *uuid.UUID,
	ipAddress *string,
	action entity.SecurityAction,
	metadata map[string]any,
) error {
	if s.securityLogs == nil {
		return nil
	}
	var payload datatypes.JSON
	if metadata != nil {
		bytes, err := json.Marshal(metadata)
		if err != nil {
			return err
		}
		payload = datatypes.JSON(bytes)
	}

	log := &entity.SecurityLog{
		UserID:    userID,
		IPAddress: ipAddress,
		Action:    action,
		Metadata:  payload,
	}
	return s.securityLogs.Log(ctx, log)
}

func (s *AuthService) now() time.Time {
	if s.clock == nil {
		return time.Now()
	}
	return s.clock.Now()
}

func (s *AuthService) verificationTokenTTL() time.Duration {
	if s.config.VerificationTokenTTL > 0 {
		return s.config.VerificationTokenTTL
	}
	return 24 * time.Hour
}

func (s *AuthService) resetTokenTTL() time.Duration {
	if s.config.ResetTokenTTL > 0 {
		return s.config.ResetTokenTTL
	}
	return 30 * time.Minute
}

func (s *AuthService) refreshTokenTTL() time.Duration {
	if s.config.RefreshTokenTTL > 0 {
		return s.config.RefreshTokenTTL
	}
	return 30 * 24 * time.Hour
}
