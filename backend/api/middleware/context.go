package middleware

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

const (
	contextUserIDKey  = "auth_user_id"
	contextRoleKey    = "auth_role"
	contextSessionKey = "auth_session_id"
)

func SetAuthContext(c echo.Context, userID uuid.UUID, role string, sessionID uuid.UUID) {
	c.Set(contextUserIDKey, userID)
	c.Set(contextRoleKey, role)
	c.Set(contextSessionKey, sessionID)
}

func UserIDFromContext(c echo.Context) (uuid.UUID, bool) {
	value := c.Get(contextUserIDKey)
	userID, ok := value.(uuid.UUID)
	return userID, ok
}

func RoleFromContext(c echo.Context) (string, bool) {
	value := c.Get(contextRoleKey)
	role, ok := value.(string)
	return role, ok
}

func SessionIDFromContext(c echo.Context) (uuid.UUID, bool) {
	value := c.Get(contextSessionKey)
	sessionID, ok := value.(uuid.UUID)
	return sessionID, ok
}
