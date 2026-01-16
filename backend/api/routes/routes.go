package routes

import (
	"time"

	"interviewa/api/handler"
	"interviewa/api/middleware"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

type Router struct {
	Echo           *echo.Echo
	Auth           *handler.AuthHandler
	AuthMiddleware middleware.AuthMiddleware
	AuthRate       *middleware.RateLimiter
	LoginRate      *middleware.RateLimiter
}

func NewRouter(e *echo.Echo, authHandler *handler.AuthHandler, authMiddleware middleware.AuthMiddleware) *Router {
	return &Router{
		Echo:           e,
		Auth:           authHandler,
		AuthMiddleware: authMiddleware,
		AuthRate:       middleware.NewRateLimiter(rate.Limit(5), 10, 5*time.Minute),
		LoginRate:      middleware.NewRateLimiter(rate.Limit(2), 4, 10*time.Minute),
	}
}

func (r *Router) RegisterRoutes() {
	e := r.Echo

	e.POST("/auth/register", r.Auth.Register, r.AuthRate.Middleware())
	e.POST("/auth/verify-email", r.Auth.VerifyEmail, r.AuthRate.Middleware())
	e.POST("/auth/login", r.Auth.Login, r.LoginRate.Middleware())
	e.POST("/auth/login/mfa", r.Auth.LoginWithMFA, r.LoginRate.Middleware())
	e.POST("/auth/refresh", r.Auth.Refresh, r.AuthRate.Middleware())
	e.POST("/auth/logout", r.Auth.Logout, r.AuthMiddleware.RequireAuth)
	e.POST("/auth/logout-all", r.Auth.LogoutAll, r.AuthMiddleware.RequireAuth)
	e.POST("/auth/password/forgot", r.Auth.PasswordForgot, r.LoginRate.Middleware())
	e.POST("/auth/password/reset", r.Auth.PasswordReset, r.AuthRate.Middleware())
	e.POST("/auth/mfa/enable", r.Auth.EnableMFA, r.AuthMiddleware.RequireAuth)
	e.POST("/auth/mfa/verify", r.Auth.VerifyMFA, r.AuthMiddleware.RequireAuth)
	e.POST("/auth/mfa/disable", r.Auth.DisableMFA, r.AuthMiddleware.RequireAuth)

	e.GET("/me", r.Auth.Me, r.AuthMiddleware.RequireAuth)
	e.GET("/admin/users", r.Auth.AdminListUsers, r.AuthMiddleware.RequireAuth, middleware.RequireRole("admin"))
	e.POST("/admin/users/:id/revoke-sessions", r.Auth.AdminRevokeUserSessions, r.AuthMiddleware.RequireAuth, middleware.RequireRole("admin"))
}
