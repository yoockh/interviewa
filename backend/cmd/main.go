package main

import (
	"net/http"
	"os"
	"time"

	"interviewa/api/handler"
	apiMiddleware "interviewa/api/middleware"
	"interviewa/api/routes"
	"interviewa/config"
	"interviewa/internal/repository"
	"interviewa/internal/service"
	"interviewa/internal/utils"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"
)

func main() {
	db := config.ConnectionDb()
	validate := validator.New()

	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	accessSecret := []byte(os.Getenv("JWT_SECRET"))
	issuer := os.Getenv("JWT_ISSUER")
	if len(accessSecret) == 0 {
		logger.Fatal("JWT_SECRET is required")
	}

	accessManager := utils.JWTManager{
		Secret:         accessSecret,
		Issuer:         issuer,
		AccessTokenTTL: 15 * time.Minute,
	}
	accessIssuer := service.JWTAccessIssuer{Manager: &accessManager}

	mfaSecret := os.Getenv("MFA_JWT_SECRET")
	if mfaSecret == "" {
		mfaSecret = os.Getenv("JWT_SECRET")
	}
	mfaIssuer := service.MFATokenIssuerJWT{
		Secret: []byte(mfaSecret),
		Issuer: issuer,
		TTL:    5 * time.Minute,
	}

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	verificationRepo := repository.NewVerificationTokenRepository(db)
	mfaRepo := repository.NewMFASecretRepository(db)
	securityRepo := repository.NewSecurityLogRepository(db)

	passwordHasher := service.BcryptPasswordHasher{}

	authService := service.NewAuthService(
		userRepo,
		sessionRepo,
		verificationRepo,
		mfaRepo,
		securityRepo,
		nil,
		passwordHasher,
		accessIssuer,
		mfaIssuer,
		nil,
		service.RealClock{},
		service.AuthConfig{
			AccessTokenTTL:       15 * time.Minute,
			RefreshTokenTTL:      30 * 24 * time.Hour,
			VerificationTokenTTL: 24 * time.Hour,
			ResetTokenTTL:        30 * time.Minute,
			MFATokenTTL:          5 * time.Minute,
			MFAIssuer:            issuer,
		},
	)

	authHandler := handler.NewAuthHandler(authService, validate)
	authHandler.CookieDomain = os.Getenv("COOKIE_DOMAIN")
	authHandler.SecureCookies = os.Getenv("COOKIE_SECURE") != "false"

	app := echo.New()
	app.HideBanner = true
	app.HidePort = true
	app.Use(echoMiddleware.Recover())
	app.Use(echoMiddleware.RequestLoggerWithConfig(echoMiddleware.RequestLoggerConfig{
		LogStatus:   true,
		LogMethod:   true,
		LogURI:      true,
		LogRemoteIP: true,
		LogError:    true,
		HandleError: true,
		LogValuesFunc: func(c echo.Context, v echoMiddleware.RequestLoggerValues) error {
			entry := logger.WithFields(logrus.Fields{
				"status": v.Status,
				"method": v.Method,
				"uri":    v.URI,
				"ip":     v.RemoteIP,
			})
			if v.Error != nil {
				entry.WithError(v.Error).Error("request")
				return nil
			}
			entry.Info("request")
			return nil
		},
	}))

	authMiddleware := apiMiddleware.AuthMiddleware{JWT: &accessManager, Sessions: sessionRepo}
	router := routes.NewRouter(app, authHandler, authMiddleware)
	router.RegisterRoutes()

	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.WithField("addr", addr).Info("server started")
	if err := app.StartServer(server); err != nil {
		logger.WithError(err).Fatal("server stopped")
	}
}
