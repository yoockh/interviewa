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
	"github.com/labstack/echo/v4"
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

func (h *AuthHandler) Register(c echo.Context) error {
	var req dto.RegisterRequest
	if err := decodeJSON(c, &req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.validate(req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	input := service.RegisterInput{Email: req.Email, Password: req.Password}
	if err := h.Service.Register(c.Request().Context(), input); err != nil {
		return writeServiceError(c, err)
	}
	return c.NoContent(http.StatusCreated)
}

func (h *AuthHandler) VerifyEmail(c echo.Context) error {
	var req dto.VerifyEmailRequest
	if err := decodeJSON(c, &req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.validate(req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.Service.VerifyEmail(c.Request().Context(), req.Token); err != nil {
		return writeServiceError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *AuthHandler) Login(c echo.Context) error {
	var req dto.LoginRequest
	if err := decodeJSON(c, &req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.validate(req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	input := service.LoginInput{
		Email:      req.Email,
		Password:   req.Password,
		DeviceID:   req.DeviceID,
		DeviceName: req.DeviceName,
		IPAddress:  stringPtr(c.RealIP()),
		UserAgent:  stringPtr(c.Request().UserAgent()),
	}
	result, err := h.Service.Login(c.Request().Context(), input)
	if err != nil {
		return writeServiceError(c, err)
	}
	response := mapLoginResponse(result)
	if !result.MFARequired {
		h.setRefreshCookie(c, result.RefreshToken, result.RefreshExpiresIn)
		response.RefreshToken = ""
		response.RefreshExpiresIn = 0
	}
	return c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) LoginWithMFA(c echo.Context) error {
	var req dto.LoginMFARequest
	if err := decodeJSON(c, &req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.validate(req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	input := service.LoginMFAInput{
		MFAToken:   req.MFAToken,
		Code:       req.Code,
		DeviceID:   req.DeviceID,
		DeviceName: req.DeviceName,
		IPAddress:  stringPtr(c.RealIP()),
		UserAgent:  stringPtr(c.Request().UserAgent()),
	}
	result, err := h.Service.LoginWithMFA(c.Request().Context(), input)
	if err != nil {
		return writeServiceError(c, err)
	}
	response := mapLoginResponse(result)
	h.setRefreshCookie(c, result.RefreshToken, result.RefreshExpiresIn)
	response.RefreshToken = ""
	response.RefreshExpiresIn = 0
	return c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) Refresh(c echo.Context) error {
	refreshToken := h.readRefreshCookie(c)
	if refreshToken == "" {
		return writeError(c, http.StatusUnauthorized, errors.New("missing refresh token"))
	}
	result, err := h.Service.Refresh(c.Request().Context(), refreshToken)
	if err != nil {
		return writeServiceError(c, err)
	}
	response := mapLoginResponse(result)
	h.setRefreshCookie(c, result.RefreshToken, result.RefreshExpiresIn)
	response.RefreshToken = ""
	response.RefreshExpiresIn = 0
	return c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) Logout(c echo.Context) error {
	userID, ok := middleware.UserIDFromContext(c)
	if !ok {
		return writeError(c, http.StatusUnauthorized, errors.New("unauthorized"))
	}
	sessionID, ok := middleware.SessionIDFromContext(c)
	if !ok {
		return writeError(c, http.StatusUnauthorized, errors.New("unauthorized"))
	}
	if err := h.Service.Logout(c.Request().Context(), sessionID, &userID, stringPtr(c.RealIP())); err != nil {
		return writeServiceError(c, err)
	}
	h.clearRefreshCookie(c)
	return c.NoContent(http.StatusNoContent)
}

func (h *AuthHandler) LogoutAll(c echo.Context) error {
	userID, ok := middleware.UserIDFromContext(c)
	if !ok {
		return writeError(c, http.StatusUnauthorized, errors.New("unauthorized"))
	}
	if err := h.Service.LogoutAll(c.Request().Context(), userID, stringPtr(c.RealIP())); err != nil {
		return writeServiceError(c, err)
	}
	h.clearRefreshCookie(c)
	return c.NoContent(http.StatusNoContent)
}

func (h *AuthHandler) PasswordForgot(c echo.Context) error {
	var req dto.PasswordForgotRequest
	if err := decodeJSON(c, &req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.validate(req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.Service.RequestPasswordReset(c.Request().Context(), req.Email); err != nil {
		return writeServiceError(c, err)
	}
	return c.NoContent(http.StatusAccepted)
}

func (h *AuthHandler) PasswordReset(c echo.Context) error {
	var req dto.PasswordResetRequest
	if err := decodeJSON(c, &req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.validate(req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.Service.ResetPassword(c.Request().Context(), req.Token, req.NewPassword); err != nil {
		return writeServiceError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *AuthHandler) EnableMFA(c echo.Context) error {
	userID, ok := middleware.UserIDFromContext(c)
	if !ok {
		return writeError(c, http.StatusUnauthorized, errors.New("unauthorized"))
	}
	qr, err := h.Service.EnableMFA(c.Request().Context(), userID)
	if err != nil {
		return writeServiceError(c, err)
	}
	return c.JSON(http.StatusOK, dto.MFAEnableResponse{QRCode: qr})
}

func (h *AuthHandler) VerifyMFA(c echo.Context) error {
	userID, ok := middleware.UserIDFromContext(c)
	if !ok {
		return writeError(c, http.StatusUnauthorized, errors.New("unauthorized"))
	}
	var req dto.MFAVerifyRequest
	if err := decodeJSON(c, &req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.validate(req); err != nil {
		return writeError(c, http.StatusBadRequest, err)
	}
	if err := h.Service.VerifyMFA(c.Request().Context(), userID, req.Code); err != nil {
		return writeServiceError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *AuthHandler) DisableMFA(c echo.Context) error {
	userID, ok := middleware.UserIDFromContext(c)
	if !ok {
		return writeError(c, http.StatusUnauthorized, errors.New("unauthorized"))
	}
	if err := h.Service.DisableMFA(c.Request().Context(), userID); err != nil {
		return writeServiceError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *AuthHandler) Me(c echo.Context) error {
	userID, ok := middleware.UserIDFromContext(c)
	if !ok {
		return writeError(c, http.StatusUnauthorized, errors.New("unauthorized"))
	}
	user, err := h.Service.GetCurrentUser(c.Request().Context(), userID)
	if err != nil {
		return writeServiceError(c, err)
	}
	if user == nil {
		return writeError(c, http.StatusNotFound, errors.New("user not found"))
	}
	return c.JSON(http.StatusOK, dto.UserResponseFromEntity(user))
}

func (h *AuthHandler) AdminListUsers(c echo.Context) error {
	limit, offset := parseLimitOffset(c)
	users, err := h.Service.ListUsers(c.Request().Context(), limit, offset)
	if err != nil {
		return writeServiceError(c, err)
	}
	return c.JSON(http.StatusOK, dto.UserResponsesFromEntities(users))
}

func (h *AuthHandler) AdminRevokeUserSessions(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return writeError(c, http.StatusBadRequest, errors.New("invalid user id"))
	}
	if err := h.Service.RevokeUserSessions(c.Request().Context(), userID); err != nil {
		return writeServiceError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *AuthHandler) validate(payload any) error {
	if h.Validate == nil {
		return nil
	}
	return h.Validate.Struct(payload)
}

func (h *AuthHandler) setRefreshCookie(c echo.Context, token string, expiresIn int64) {
	if token == "" {
		return
	}
	maxAge := int(expiresIn)
	if maxAge < 0 {
		maxAge = 0
	}
	c.SetCookie(&http.Cookie{
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

func (h *AuthHandler) clearRefreshCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
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

func (h *AuthHandler) readRefreshCookie(c echo.Context) string {
	cookie, err := c.Cookie(h.RefreshCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func decodeJSON(c echo.Context, target any) error {
	decoder := json.NewDecoder(c.Request().Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func writeError(c echo.Context, status int, err error) error {
	return c.JSON(status, map[string]string{"message": err.Error()})
}

func writeServiceError(c echo.Context, err error) error {
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
	return writeError(c, status, err)
}

func parseLimitOffset(c echo.Context) (int, int) {
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))
	return limit, offset
}

func stringPtr(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

func mapLoginResponse(result *service.LoginResult) *dto.LoginResponse {
	if result == nil {
		return &dto.LoginResponse{}
	}
	return &dto.LoginResponse{
		AccessToken:       result.AccessToken,
		ExpiresIn:         result.ExpiresIn,
		RefreshToken:      result.RefreshToken,
		RefreshExpiresIn:  result.RefreshExpiresIn,
		MFARequired:       result.MFARequired,
		MFAToken:          result.MFAToken,
		MFATokenExpiresIn: result.MFATokenExpiresIn,
	}
}
