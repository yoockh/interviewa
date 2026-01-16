package middleware

import (
	"net/http"
	"strings"

	"interviewa/internal/utils"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type AuthMiddleware struct {
	JWT *utils.JWTManager
}

func (m AuthMiddleware) RequireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if m.JWT == nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
		}
		token := extractBearerToken(c.Request())
		if token == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
		}
		claims, err := m.JWT.ParseAccessToken(token)
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
		}
		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
		}
		sessionID, err := uuid.Parse(claims.SessionID)
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
		}
		SetAuthContext(c, userID, claims.Role, sessionID)
		return next(c)
	}
}

func extractBearerToken(r *http.Request) string {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return ""
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
