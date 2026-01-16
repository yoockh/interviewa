package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type ResendEmailSender struct {
	APIKey     string
	HTTPClient *http.Client
	From       string
	AppBaseURL string
	VerifyPath string
	ResetPath  string
}

func NewResendEmailSender(apiKey string, from string, appBaseURL string) *ResendEmailSender {
	if strings.TrimSpace(apiKey) == "" || strings.TrimSpace(from) == "" {
		return &ResendEmailSender{}
	}
	return &ResendEmailSender{
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		From:       from,
		AppBaseURL: strings.TrimRight(appBaseURL, "/"),
		VerifyPath: "/verify-email",
		ResetPath:  "/reset-password",
	}
}

func (s *ResendEmailSender) SendVerificationEmail(ctx context.Context, email string, token string) error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("email sender not configured")
	}
	link := s.buildURL(s.VerifyPath, token)
	subject := "Verify your email"
	html := fmt.Sprintf("<p>Click to verify your email:</p><p><a href=\"%s\">Verify Email</a></p>", link)
	text := fmt.Sprintf("Verify your email: %s", link)
	return s.send(ctx, email, subject, html, text)
}

func (s *ResendEmailSender) SendPasswordResetEmail(ctx context.Context, email string, token string) error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("email sender not configured")
	}
	link := s.buildURL(s.ResetPath, token)
	subject := "Reset your password"
	html := fmt.Sprintf("<p>Click to reset your password:</p><p><a href=\"%s\">Reset Password</a></p>", link)
	text := fmt.Sprintf("Reset your password: %s", link)
	return s.send(ctx, email, subject, html, text)
}

func (s *ResendEmailSender) buildURL(path string, token string) string {
	base := strings.TrimRight(s.AppBaseURL, "/")
	if base == "" {
		return token
	}
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s%s?token=%s", base, path, token)
}

func (s *ResendEmailSender) send(ctx context.Context, to string, subject string, html string, text string) error {
	if s.HTTPClient == nil {
		s.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	payload := map[string]any{
		"from":    s.From,
		"to":      []string{to},
		"subject": subject,
		"html":    html,
		"text":    text,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+s.APIKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("resend email failed with status %d", response.StatusCode)
	}
	return nil
}
