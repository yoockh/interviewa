package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"interviewa/api/middleware"
	"interviewa/internal/dto"
	"interviewa/internal/service"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type AuthHandler struct {
	Service           *service.AuthService
	Validate          *validator.Validate
	RefreshCookieName string
	CookieDomain      string
	SecureCookies     bool
	SameSite          http.SameSite
}

func NewAuthHandler(svc *service.AuthService, validate *validator.Validate) *AuthHandler {
	return &AuthHandler{
		Service:           svc,
		Validate:          validate,
		RefreshCookieName: "refresh_token",
		SecureCookies:     true,
		SameSite:          http.SameSiteStrictMode,
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req dto.RegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.validate(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.Service.Register(r.Context(), req); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req dto.VerifyEmailRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.validate(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.Service.VerifyEmail(r.Context(), req.Token); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.validate(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ipAddress := extractIP(r)
	userAgent := r.UserAgent()
	result, err := h.Service.Login(r.Context(), req, stringPtr(ipAddress), stringPtr(userAgent))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if !result.MFARequired {
		h.setRefreshCookie(w, result.RefreshToken, result.RefreshExpiresIn)
		result.RefreshToken = ""
		result.RefreshExpiresIn = 0
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) LoginWithMFA(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginMFARequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.validate(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ipAddress := extractIP(r)
	userAgent := r.UserAgent()
	result, err := h.Service.LoginWithMFA(r.Context(), req, stringPtr(ipAddress), stringPtr(userAgent))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	h.setRefreshCookie(w, result.RefreshToken, result.RefreshExpiresIn)
	result.RefreshToken = ""
	result.RefreshExpiresIn = 0
	writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := h.readRefreshCookie(r)
	if refreshToken == "" {
		writeError(w, http.StatusUnauthorized, errors.New("missing refresh token"))
		return
	}
	result, err := h.Service.Refresh(r.Context(), refreshToken)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	h.setRefreshCookie(w, result.RefreshToken, result.RefreshExpiresIn)
	result.RefreshToken = ""
	result.RefreshExpiresIn = 0
	writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}
	sessionID, ok := middleware.SessionIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}
	ipAddress := extractIP(r)
	if err := h.Service.Logout(r.Context(), sessionID, &userID, stringPtr(ipAddress)); err != nil {
		writeServiceError(w, err)
		return
	}
	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}
	ipAddress := extractIP(r)
	if err := h.Service.LogoutAll(r.Context(), userID, stringPtr(ipAddress)); err != nil {
		writeServiceError(w, err)
		return
	}
	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) PasswordForgot(w http.ResponseWriter, r *http.Request) {
	var req dto.PasswordForgotRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.validate(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.Service.RequestPasswordReset(r.Context(), req.Email); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *AuthHandler) PasswordReset(w http.ResponseWriter, r *http.Request) {
	var req dto.PasswordResetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.validate(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.Service.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) EnableMFA(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}
	qr, err := h.Service.EnableMFA(r.Context(), userID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dto.MFAEnableResponse{QRCode: qr})
}

func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}
	var req dto.MFAVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.validate(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.Service.VerifyMFA(r.Context(), userID, req.Code); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) DisableMFA(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}
	if err := h.Service.DisableMFA(r.Context(), userID); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}
	user, err := h.Service.GetCurrentUser(r.Context(), userID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, errors.New("user not found"))
		return
	}
	writeJSON(w, http.StatusOK, dto.UserResponseFromEntity(user))
}

func (h *AuthHandler) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset := parseLimitOffset(r)
	users, err := h.Service.ListUsers(r.Context(), limit, offset)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dto.UserResponsesFromEntities(users))
}

func (h *AuthHandler) AdminRevokeUserSessions(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
	if err := h.Service.RevokeUserSessions(r.Context(), userID); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) validate(payload any) error {
	if h.Validate == nil {
		return nil
	}
	return h.Validate.Struct(payload)
}

func (h *AuthHandler) setRefreshCookie(w http.ResponseWriter, token string, expiresIn int64) {
	if token == "" {
		return
	}
	maxAge := int(expiresIn)
	if maxAge < 0 {
		maxAge = 0
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.RefreshCookieName,
		Value:    token,
		Path:     "/",
		Domain:   h.CookieDomain,
		MaxAge:   maxAge,
		Expires:  time.Now().Add(time.Duration(expiresIn) * time.Second),
		HttpOnly: true,
		Secure:   h.SecureCookies,
		SameSite: h.SameSite,
	})
}

func (h *AuthHandler) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.RefreshCookieName,
		Value:    "",
		Path:     "/",
		Domain:   h.CookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.SecureCookies,
		SameSite: h.SameSite,
	})
}

func (h *AuthHandler) readRefreshCookie(r *http.Request) string {
	cookie, err := r.Cookie(h.RefreshCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"message": err.Error()})
}

func writeServiceError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, service.ErrInvalidInput):
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrInvalidCredentials), errors.Is(err, service.ErrInvalidToken):
		status = http.StatusUnauthorized
	case errors.Is(err, service.ErrEmailAlreadyRegistered):
		status = http.StatusConflict
	case errors.Is(err, service.ErrEmailNotVerified):
		status = http.StatusForbidden
	case errors.Is(err, service.ErrMFARequired):
		status = http.StatusPreconditionRequired
	case errors.Is(err, service.ErrInvalidMFACode):
		status = http.StatusUnauthorized
	case errors.Is(err, service.ErrMFANotConfigured):
		status = http.StatusFailedDependency
	case errors.Is(err, service.ErrUserNotFound):
		status = http.StatusNotFound
	}
	writeError(w, status, err)
}

func parseLimitOffset(r *http.Request) (int, int) {
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	return limit, offset
}

func extractIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	if host, _, found := strings.Cut(r.RemoteAddr, ":"); found {
		return host
	}
	return r.RemoteAddr
}

func stringPtr(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}
