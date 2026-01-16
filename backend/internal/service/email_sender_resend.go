package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/resend/resend-go"
)

type ResendEmailSender struct {
	Client     *resend.Client
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
		Client:     resend.NewClient(apiKey),
		From:       from,
		AppBaseURL: strings.TrimRight(appBaseURL, "/"),
		VerifyPath: "/verify-email",
		ResetPath:  "/reset-password",
	}
}

func (s *ResendEmailSender) SendVerificationEmail(ctx context.Context, email string, token string) error {
	if s.Client == nil {
		return errors.New("email sender not configured")
	}
	link := s.buildURL(s.VerifyPath, token)
	subject := "Verify your email"
	html := fmt.Sprintf("<p>Click to verify your email:</p><p><a href=\"%s\">Verify Email</a></p>", link)
	text := fmt.Sprintf("Verify your email: %s", link)
	_, err := s.Client.Emails.SendWithContext(ctx, &resend.SendEmailRequest{
		From:    s.From,
		To:      []string{email},
		Subject: subject,
		Html:    html,
		Text:    text,
	})
	return err
}

func (s *ResendEmailSender) SendPasswordResetEmail(ctx context.Context, email string, token string) error {
	if s.Client == nil {
		return errors.New("email sender not configured")
	}
	link := s.buildURL(s.ResetPath, token)
	subject := "Reset your password"
	html := fmt.Sprintf("<p>Click to reset your password:</p><p><a href=\"%s\">Reset Password</a></p>", link)
	text := fmt.Sprintf("Reset your password: %s", link)
	_, err := s.Client.Emails.SendWithContext(ctx, &resend.SendEmailRequest{
		From:    s.From,
		To:      []string{email},
		Subject: subject,
		Html:    html,
		Text:    text,
	})
	return err
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
