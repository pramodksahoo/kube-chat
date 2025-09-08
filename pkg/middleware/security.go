// Package middleware provides enhanced security features for authentication
package middleware

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/go-redis/redis/v8"
)

// SecurityConfig holds configuration for security middleware
type SecurityConfig struct {
	// Rate limiting configuration
	RateLimitRequests int           `json:"rate_limit_requests"` // Max requests per window
	RateLimitWindow   time.Duration `json:"rate_limit_window"`   // Rate limit time window
	
	// Brute force protection
	MaxFailedAttempts int           `json:"max_failed_attempts"` // Max failed login attempts
	LockoutDuration   time.Duration `json:"lockout_duration"`    // Account lockout duration
	
	// JWT token rotation
	TokenRotationEnabled bool          `json:"token_rotation_enabled"` // Enable automatic token rotation
	RotationInterval     time.Duration `json:"rotation_interval"`      // How often to rotate tokens
	
	// Redis configuration for distributed security features
	RedisClient redis.UniversalClient `json:"-"` // Redis client for distributed storage
}

// SecurityMiddleware provides enhanced security features
type SecurityMiddleware struct {
	config      SecurityConfig
	rateLimiter *RateLimiter
	bruteForcePrevention *BruteForceProtection
	tokenRotator *TokenRotator
}

// RateLimiter implements distributed rate limiting
type RateLimiter struct {
	config      SecurityConfig
	redisClient redis.UniversalClient
	mu          sync.RWMutex
	localCache  map[string]*RateLimitEntry // Fallback local cache
}

// RateLimitEntry tracks rate limit data for a client
type RateLimitEntry struct {
	Count     int       `json:"count"`
	ResetTime time.Time `json:"reset_time"`
}

// BruteForceProtection implements account lockout after failed attempts
type BruteForceProtection struct {
	config      SecurityConfig
	redisClient redis.UniversalClient
	mu          sync.RWMutex
	localCache  map[string]*BruteForceEntry // Fallback local cache
}

// BruteForceEntry tracks failed attempts for an identifier
type BruteForceEntry struct {
	Attempts     int       `json:"attempts"`
	LastAttempt  time.Time `json:"last_attempt"`
	LockedUntil  time.Time `json:"locked_until"`
	IsLocked     bool      `json:"is_locked"`
}

// TokenRotator manages automatic JWT token rotation
type TokenRotator struct {
	config     SecurityConfig
	jwtService JWTServiceInterface
	ticker     *time.Ticker
	stopChan   chan struct{}
}

// NewSecurityMiddleware creates a new security middleware instance
func NewSecurityMiddleware(config SecurityConfig, jwtService JWTServiceInterface) *SecurityMiddleware {
	// Set default values
	if config.RateLimitRequests == 0 {
		config.RateLimitRequests = 100 // 100 requests per window
	}
	if config.RateLimitWindow == 0 {
		config.RateLimitWindow = time.Minute // 1 minute window
	}
	if config.MaxFailedAttempts == 0 {
		config.MaxFailedAttempts = 5 // 5 failed attempts
	}
	if config.LockoutDuration == 0 {
		config.LockoutDuration = 15 * time.Minute // 15 minutes lockout
	}
	if config.RotationInterval == 0 {
		config.RotationInterval = 4 * time.Hour // Rotate every 4 hours
	}

	security := &SecurityMiddleware{
		config: config,
		rateLimiter: &RateLimiter{
			config:      config,
			redisClient: config.RedisClient,
			localCache:  make(map[string]*RateLimitEntry),
		},
		bruteForcePrevention: &BruteForceProtection{
			config:      config,
			redisClient: config.RedisClient,
			localCache:  make(map[string]*BruteForceEntry),
		},
	}

	// Initialize token rotator if enabled
	if config.TokenRotationEnabled && jwtService != nil {
		security.tokenRotator = &TokenRotator{
			config:     config,
			jwtService: jwtService,
			stopChan:   make(chan struct{}),
		}
		security.tokenRotator.start()
	}

	return security
}

// RateLimitMiddleware returns a Fiber middleware for rate limiting
func (s *SecurityMiddleware) RateLimitMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		clientIP := c.IP()
		allowed, resetTime, err := s.rateLimiter.IsAllowed(clientIP)
		if err != nil {
			// Log error but don't block request on rate limiter failure
			fmt.Printf("Rate limiter error: %v\n", err)
			return c.Next()
		}

		if !allowed {
			c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", s.config.RateLimitRequests))
			c.Set("X-RateLimit-Remaining", "0")
			c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))
			
			return c.Status(429).JSON(fiber.Map{
				"error":   true,
				"code":    "RATE_LIMIT_EXCEEDED",
				"message": "Too many requests. Please try again later.",
				"retry_after": int(resetTime.Sub(time.Now()).Seconds()),
			})
		}

		return c.Next()
	}
}

// BruteForceProtectionMiddleware returns a Fiber middleware for brute force protection
func (s *SecurityMiddleware) BruteForceProtectionMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check if this is an authentication endpoint
		if c.Path() == "/auth/callback" || c.Path() == "/auth/login" {
			clientIP := c.IP()
			userAgent := c.Get("User-Agent")
			identifier := fmt.Sprintf("%s:%s", clientIP, userAgent)

			isLocked, lockedUntil, err := s.bruteForcePrevention.IsLocked(identifier)
			if err != nil {
				// Log error but don't block request on protection failure
				fmt.Printf("Brute force protection error: %v\n", err)
				return c.Next()
			}

			if isLocked {
				return c.Status(423).JSON(fiber.Map{
					"error":      true,
					"code":       "ACCOUNT_LOCKED",
					"message":    "Account temporarily locked due to too many failed attempts",
					"locked_until": lockedUntil.Unix(),
				})
			}
		}

		return c.Next()
	}
}

// TokenRotationMiddleware adds token rotation headers
func (s *SecurityMiddleware) TokenRotationMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Add token rotation information to response headers
		if s.config.TokenRotationEnabled {
			c.Set("X-Token-Rotation-Enabled", "true")
			c.Set("X-Token-Rotation-Interval", s.config.RotationInterval.String())
		}
		return c.Next()
	}
}

// IsAllowed checks if a request is allowed under rate limiting rules
func (rl *RateLimiter) IsAllowed(identifier string) (bool, time.Time, error) {
	ctx := context.Background()
	now := time.Now()
	key := fmt.Sprintf("rate_limit:%s", identifier)

	// Try Redis first if available
	if rl.redisClient != nil {
		pipe := rl.redisClient.Pipeline()
		
		// Get current count and expiry
		getCmd := pipe.Get(ctx, key)
		
		// Increment counter
		incrCmd := pipe.Incr(ctx, key)
		
		// Set expiry for new keys
		expireCmd := pipe.Expire(ctx, key, rl.config.RateLimitWindow)
		
		_, err := pipe.Exec(ctx)
		if err != nil && err != redis.Nil {
			return rl.fallbackLocalRateLimit(identifier, now)
		}

		currentCount := int(incrCmd.Val())
		
		// For new keys, set the expiry
		if getCmd.Err() == redis.Nil {
			expireCmd.Val()
		}

		resetTime := now.Add(rl.config.RateLimitWindow)
		allowed := currentCount <= rl.config.RateLimitRequests

		return allowed, resetTime, nil
	}

	// Fallback to local rate limiting
	return rl.fallbackLocalRateLimit(identifier, now)
}

// fallbackLocalRateLimit provides local rate limiting when Redis is unavailable
func (rl *RateLimiter) fallbackLocalRateLimit(identifier string, now time.Time) (bool, time.Time, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.localCache[identifier]
	if !exists || now.After(entry.ResetTime) {
		// Create new entry
		entry = &RateLimitEntry{
			Count:     1,
			ResetTime: now.Add(rl.config.RateLimitWindow),
		}
		rl.localCache[identifier] = entry
		return true, entry.ResetTime, nil
	}

	// Increment existing entry
	entry.Count++
	allowed := entry.Count <= rl.config.RateLimitRequests

	return allowed, entry.ResetTime, nil
}

// RecordFailedAttempt records a failed authentication attempt
func (bf *BruteForceProtection) RecordFailedAttempt(identifier string) error {
	ctx := context.Background()
	now := time.Now()
	key := fmt.Sprintf("brute_force:%s", identifier)

	// Try Redis first if available
	if bf.redisClient != nil {
		// Get current attempts
		_, err := bf.redisClient.Get(ctx, key).Result()
		var entry BruteForceEntry
		
		if err == redis.Nil {
			// New entry
			entry = BruteForceEntry{
				Attempts:    1,
				LastAttempt: now,
			}
		} else if err != nil {
			return bf.fallbackLocalRecord(identifier, now)
		} else {
			// Parse existing entry
			// In production, would use proper JSON marshaling
			entry.Attempts++
			entry.LastAttempt = now
		}

		// Check if should be locked
		if entry.Attempts >= bf.config.MaxFailedAttempts {
			entry.IsLocked = true
			entry.LockedUntil = now.Add(bf.config.LockoutDuration)
		}

		// Store updated entry with TTL
		ttl := bf.config.LockoutDuration
		if !entry.IsLocked {
			ttl = time.Hour // Keep failed attempts for 1 hour
		}
		
		// In production, would marshal to JSON properly
		return bf.redisClient.Set(ctx, key, fmt.Sprintf("attempts:%d", entry.Attempts), ttl).Err()
	}

	// Fallback to local storage
	return bf.fallbackLocalRecord(identifier, now)
}

// fallbackLocalRecord provides local brute force tracking when Redis is unavailable
func (bf *BruteForceProtection) fallbackLocalRecord(identifier string, now time.Time) error {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	entry, exists := bf.localCache[identifier]
	if !exists {
		entry = &BruteForceEntry{}
		bf.localCache[identifier] = entry
	}

	entry.Attempts++
	entry.LastAttempt = now

	// Check if should be locked
	if entry.Attempts >= bf.config.MaxFailedAttempts {
		entry.IsLocked = true
		entry.LockedUntil = now.Add(bf.config.LockoutDuration)
	}

	return nil
}

// IsLocked checks if an identifier is currently locked due to brute force attempts
func (bf *BruteForceProtection) IsLocked(identifier string) (bool, time.Time, error) {
	ctx := context.Background()
	key := fmt.Sprintf("brute_force:%s", identifier)
	now := time.Now()

	// Try Redis first if available
	if bf.redisClient != nil {
		_, err := bf.redisClient.Get(ctx, key).Result()
		if err == redis.Nil {
			return false, time.Time{}, nil
		}
		if err != nil {
			return bf.fallbackLocalCheck(identifier, now)
		}

		// In production, would properly parse JSON
		// For now, simple check if key exists means locked
		return true, now.Add(bf.config.LockoutDuration), nil
	}

	// Fallback to local check
	return bf.fallbackLocalCheck(identifier, now)
}

// fallbackLocalCheck provides local brute force checking when Redis is unavailable
func (bf *BruteForceProtection) fallbackLocalCheck(identifier string, now time.Time) (bool, time.Time, error) {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	entry, exists := bf.localCache[identifier]
	if !exists {
		return false, time.Time{}, nil
	}

	if entry.IsLocked {
		if now.After(entry.LockedUntil) {
			// Lock has expired, clean up
			delete(bf.localCache, identifier)
			return false, time.Time{}, nil
		}
		return true, entry.LockedUntil, nil
	}

	return false, time.Time{}, nil
}

// ClearFailedAttempts clears failed attempts for an identifier (on successful login)
func (bf *BruteForceProtection) ClearFailedAttempts(identifier string) error {
	ctx := context.Background()
	key := fmt.Sprintf("brute_force:%s", identifier)

	// Clear from Redis if available
	if bf.redisClient != nil {
		bf.redisClient.Del(ctx, key)
	}

	// Clear from local cache
	bf.mu.Lock()
	defer bf.mu.Unlock()
	delete(bf.localCache, identifier)

	return nil
}

// start begins the token rotation process
func (tr *TokenRotator) start() {
	if tr.ticker != nil {
		tr.ticker.Stop()
	}

	tr.ticker = time.NewTicker(tr.config.RotationInterval)
	
	go func() {
		for {
			select {
			case <-tr.ticker.C:
				tr.rotateExpiredTokens()
			case <-tr.stopChan:
				return
			}
		}
	}()
}

// stop stops the token rotation process
func (tr *TokenRotator) Stop() {
	if tr.ticker != nil {
		tr.ticker.Stop()
	}
	close(tr.stopChan)
}

// rotateExpiredTokens rotates tokens that are close to expiration
func (tr *TokenRotator) rotateExpiredTokens() {
	// In production, this would:
	// 1. Query active sessions nearing expiration
	// 2. Generate new tokens for those sessions
	// 3. Update Redis with new token mappings
	// 4. Mark old tokens for cleanup
	
	fmt.Printf("Token rotation cycle executed at %v\n", time.Now())
	
	// This is a placeholder - in production would implement actual rotation logic
	// that works with the JWT service and session storage
}

// GetSecurityMetrics returns current security metrics
func (s *SecurityMiddleware) GetSecurityMetrics() map[string]interface{} {
	metrics := map[string]interface{}{
		"rate_limiter": map[string]interface{}{
			"enabled":        true,
			"requests_limit": s.config.RateLimitRequests,
			"window":         s.config.RateLimitWindow.String(),
		},
		"brute_force_protection": map[string]interface{}{
			"enabled":            true,
			"max_failed_attempts": s.config.MaxFailedAttempts,
			"lockout_duration":   s.config.LockoutDuration.String(),
		},
		"token_rotation": map[string]interface{}{
			"enabled":  s.config.TokenRotationEnabled,
			"interval": s.config.RotationInterval.String(),
		},
	}

	// Add local cache statistics if available
	if s.rateLimiter != nil {
		s.rateLimiter.mu.RLock()
		metrics["rate_limiter"].(map[string]interface{})["local_cache_entries"] = len(s.rateLimiter.localCache)
		s.rateLimiter.mu.RUnlock()
	}

	if s.bruteForcePrevention != nil {
		s.bruteForcePrevention.mu.RLock()
		metrics["brute_force_protection"].(map[string]interface{})["local_cache_entries"] = len(s.bruteForcePrevention.localCache)
		s.bruteForcePrevention.mu.RUnlock()
	}

	return metrics
}

// Cleanup performs cleanup of expired entries and resources
func (s *SecurityMiddleware) Cleanup() {
	now := time.Now()

	// Cleanup rate limiter local cache
	if s.rateLimiter != nil {
		s.rateLimiter.mu.Lock()
		for key, entry := range s.rateLimiter.localCache {
			if now.After(entry.ResetTime) {
				delete(s.rateLimiter.localCache, key)
			}
		}
		s.rateLimiter.mu.Unlock()
	}

	// Cleanup brute force protection local cache
	if s.bruteForcePrevention != nil {
		s.bruteForcePrevention.mu.Lock()
		for key, entry := range s.bruteForcePrevention.localCache {
			if entry.IsLocked && now.After(entry.LockedUntil) {
				delete(s.bruteForcePrevention.localCache, key)
			}
		}
		s.bruteForcePrevention.mu.Unlock()
	}

	// Stop token rotator if needed
	if s.tokenRotator != nil {
		s.tokenRotator.Stop()
	}
}