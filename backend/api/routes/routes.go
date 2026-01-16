package routes

import (
	"net/http"
	"strings"

	"interviewa/api/handler"
	"interviewa/api/middleware"

	"github.com/google/uuid"
)

type Router struct {
	Mux            *http.ServeMux
	Auth           *handler.AuthHandler
	AuthMiddleware middleware.AuthMiddleware
}

func NewRouter(authHandler *handler.AuthHandler, authMiddleware middleware.AuthMiddleware) *Router {
	return &Router{
		Mux:            http.NewServeMux(),
		Auth:           authHandler,
		AuthMiddleware: authMiddleware,
	}
}

func (r *Router) RegisterRoutes() http.Handler {
	mux := r.Mux

	mux.HandleFunc("/auth/register", r.Auth.Register)
	mux.HandleFunc("/auth/verify-email", r.Auth.VerifyEmail)
	mux.HandleFunc("/auth/login", r.Auth.Login)
	mux.HandleFunc("/auth/login/mfa", r.Auth.LoginWithMFA)
	mux.HandleFunc("/auth/refresh", r.Auth.Refresh)
	mux.Handle("/auth/logout", r.wrap(r.Auth.Logout, r.AuthMiddleware.RequireAuth))
	mux.Handle("/auth/logout-all", r.wrap(r.Auth.LogoutAll, r.AuthMiddleware.RequireAuth))
	mux.HandleFunc("/auth/password/forgot", r.Auth.PasswordForgot)
	mux.HandleFunc("/auth/password/reset", r.Auth.PasswordReset)
	mux.Handle("/auth/mfa/enable", r.wrap(r.Auth.EnableMFA, r.AuthMiddleware.RequireAuth))
	mux.Handle("/auth/mfa/verify", r.wrap(r.Auth.VerifyMFA, r.AuthMiddleware.RequireAuth))
	mux.Handle("/auth/mfa/disable", r.wrap(r.Auth.DisableMFA, r.AuthMiddleware.RequireAuth))
	mux.Handle("/me", r.wrap(r.Auth.Me, r.AuthMiddleware.RequireAuth))
	mux.Handle("/admin/users", r.wrap(r.Auth.AdminListUsers, r.AuthMiddleware.RequireAuth, middleware.RequireRole("admin")))
	mux.Handle("/admin/users/", r.wrap(r.adminUserRoutes, r.AuthMiddleware.RequireAuth, middleware.RequireRole("admin")))

	return mux
}

func (r *Router) adminUserRoutes(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/admin/users/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[1] != "revoke-sessions" {
		http.NotFound(w, req)
		return
	}
	userID, err := uuid.Parse(parts[0])
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	r.Auth.AdminRevokeUserSessions(w, req, userID)
}

func (r *Router) wrap(handlerFunc http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) http.Handler {
	h := http.Handler(handlerFunc)
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
