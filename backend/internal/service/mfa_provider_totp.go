package service

import (
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type TOTPProvider struct {
	Issuer    string
	Period    uint
	Skew      uint
	Digits    otp.Digits
	Algorithm otp.Algorithm
}

func NewTOTPProvider(issuer string) *TOTPProvider {
	return &TOTPProvider{
		Issuer:    issuer,
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
}

func (p *TOTPProvider) GenerateSecret() (string, error) {
	issuer := fallbackIssuer(p.Issuer)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: "pending",
		Period:      p.period(),
		Digits:      p.digits(),
		Algorithm:   p.algorithm(),
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

func (p *TOTPProvider) QRCodeURL(email string, issuer string, secret string) (string, error) {
	finalIssuer := issuer
	if strings.TrimSpace(finalIssuer) == "" {
		finalIssuer = fallbackIssuer(p.Issuer)
	}
	label := url.PathEscape(finalIssuer + ":" + email)
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", finalIssuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", "6")
	query.Set("period", "30")
	return "otpauth://totp/" + label + "?" + query.Encode(), nil
}

func (p *TOTPProvider) ValidateCode(secret string, code string) bool {
	return totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    p.period(),
		Skew:      p.skew(),
		Digits:    p.digits(),
		Algorithm: p.algorithm(),
	})
}

func (p *TOTPProvider) period() uint {
	if p.Period == 0 {
		return 30
	}
	return p.Period
}

func (p *TOTPProvider) skew() uint {
	if p.Skew == 0 {
		return 1
	}
	return p.Skew
}

func (p *TOTPProvider) digits() otp.Digits {
	if p.Digits == 0 {
		return otp.DigitsSix
	}
	return p.Digits
}

func (p *TOTPProvider) algorithm() otp.Algorithm {
	if p.Algorithm == 0 {
		return otp.AlgorithmSHA1
	}
	return p.Algorithm
}

func fallbackIssuer(issuer string) string {
	if strings.TrimSpace(issuer) == "" {
		return "Interviewa"
	}
	return issuer
}
