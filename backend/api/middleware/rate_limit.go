package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mutex    sync.Mutex
	rate     rate.Limit
	burst    int
	ttl      time.Duration
	lastSeen map[string]time.Time
}

func NewRateLimiter(r rate.Limit, burst int, ttl time.Duration) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
		rate:     r,
		burst:    burst,
		ttl:      ttl,
	}
}

func (l *RateLimiter) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()
			limiter := l.getLimiter(ip)
			if !limiter.Allow() {
				return echo.NewHTTPError(http.StatusTooManyRequests, "too many requests")
			}
			return next(c)
		}
	}
}

func (l *RateLimiter) getLimiter(ip string) *rate.Limiter {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if limiter, ok := l.limiters[ip]; ok {
		l.lastSeen[ip] = time.Now()
		return limiter
	}
	limiter := rate.NewLimiter(l.rate, l.burst)
	l.limiters[ip] = limiter
	l.lastSeen[ip] = time.Now()
	l.cleanup()
	return limiter
}

func (l *RateLimiter) cleanup() {
	if l.ttl == 0 {
		return
	}
	cutoff := time.Now().Add(-l.ttl)
	for ip, last := range l.lastSeen {
		if last.Before(cutoff) {
			delete(l.lastSeen, ip)
			delete(l.limiters, ip)
		}
	}
}
