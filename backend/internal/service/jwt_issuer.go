package service

import (
	"interviewa/internal/entity"
	"interviewa/internal/utils"
	"time"

	"github.com/google/uuid"
)

type JWTAccessIssuer struct {
	Manager *utils.JWTManager
}

func (j JWTAccessIssuer) IssueAccessToken(user entity.User, sessionID uuid.UUID) (string, time.Duration, error) {
	if j.Manager == nil {
		return "", 0, ErrInvalidToken
	}
	return j.Manager.IssueAccessToken(user.ID.String(), string(user.Role), sessionID.String())
}
