package httpapi

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// maxTrackedClients bounds limiter memory under a flood of distinct IPs.
const maxTrackedClients = 100_000

// ipLimiter is an in-memory, per-IP token bucket that slows down credential
// stuffing on the auth endpoints. It is per instance: with N replicas a
// client gets N times the budget. For strict global limits use a shared
// store (Redis) or the edge proxy / WAF. See docs/security.md.
type ipLimiter struct {
	mu          sync.Mutex
	limit       rate.Limit
	burst       int
	clients     map[string]*client
	lastCleanup time.Time
}

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPLimiter(perMinute, burst int) *ipLimiter {
	return &ipLimiter{
		limit: rate.Limit(float64(perMinute) / 60), burst: burst,
		clients: map[string]*client{}, lastCleanup: time.Now(),
	}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if now.Sub(l.lastCleanup) > time.Minute || len(l.clients) >= maxTrackedClients {
		for k, c := range l.clients {
			if now.Sub(c.lastSeen) > 10*time.Minute {
				delete(l.clients, k)
			}
		}
		l.lastCleanup = now
	}
	c, ok := l.clients[ip]
	if !ok {
		if len(l.clients) >= maxTrackedClients {
			return false // fail closed rather than grow without bound
		}
		c = &client{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.clients[ip] = c
	}
	c.lastSeen = now
	return c.limiter.Allow()
}

func (l *ipLimiter) retryAfter() time.Duration {
	return time.Duration(float64(time.Second) / float64(l.limit))
}
