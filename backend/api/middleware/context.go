package middleware

import (
	"context"

	"github.com/google/uuid"
)

type contextKey string

const (
	contextUserIDKey  contextKey = "auth_user_id"
	contextRoleKey    contextKey = "auth_role"
	contextSessionKey contextKey = "auth_session_id"
)

func WithAuthContext(ctx context.Context, userID uuid.UUID, role string, sessionID uuid.UUID) context.Context {
	ctx = context.WithValue(ctx, contextUserIDKey, userID)
	ctx = context.WithValue(ctx, contextRoleKey, role)
	ctx = context.WithValue(ctx, contextSessionKey, sessionID)
	return ctx
}

func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	value := ctx.Value(contextUserIDKey)
	userID, ok := value.(uuid.UUID)
	return userID, ok
}

func RoleFromContext(ctx context.Context) (string, bool) {
	value := ctx.Value(contextRoleKey)
	role, ok := value.(string)
	return role, ok
}

func SessionIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	value := ctx.Value(contextSessionKey)
	sessionID, ok := value.(uuid.UUID)
	return sessionID, ok
}
