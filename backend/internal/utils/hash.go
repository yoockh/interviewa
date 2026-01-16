package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func GenerateRandomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
