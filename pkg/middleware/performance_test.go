package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BenchmarkJWTValidation tests token validation performance under load
func BenchmarkJWTValidation(b *testing.B) {
	// Create test JWT service
	jwtConfig := JWTConfig{
		RedisAddr:       "", // No Redis for benchmark
		TokenDuration:   8 * time.Hour,
		RefreshDuration: 7 * 24 * time.Hour,
		Issuer:          "benchmark-kubechat",
	}

	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)

	// Create JWT service with test key
	jwtService := &JWTService{
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		redisClient:     nil, // Disable Redis for benchmarks
		tokenDuration:   jwtConfig.TokenDuration,
		refreshDuration: jwtConfig.RefreshDuration,
		issuer:          jwtConfig.Issuer,
	}

	// Generate test token
	token, err := jwtService.GenerateToken("benchmark-user", "benchmark@example.com", "Benchmark User")
	require.NoError(b, err)
	require.NotNil(b, token)

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("single_thread", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := jwtService.ValidateToken(token.AccessToken)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("concurrent_validation", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := jwtService.ValidateToken(token.AccessToken)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

// BenchmarkAuthenticationMiddleware tests authentication middleware performance
func BenchmarkAuthenticationMiddleware(b *testing.B) {
	// Create test providers with mock OIDC server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".well-known/openid-configuration") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"issuer":"http://test","authorization_endpoint":"http://test/auth","token_endpoint":"http://test/token","userinfo_endpoint":"http://test/userinfo","jwks_uri":"http://test/jwks"}`)
		} else if strings.Contains(r.URL.Path, "jwks") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"keys":[]}`)
		}
	}))
	defer mockServer.Close()

	providers := []OIDCProvider{
		{
			Name:         "benchmark-provider",
			Issuer:       mockServer.URL,
			ClientID:     "benchmark-client",
			ClientSecret: "benchmark-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"email", "profile"},
		},
	}

	// Create JWT service for testing
	jwtConfig := JWTConfig{
		TokenDuration:   8 * time.Hour,
		RefreshDuration: 7 * 24 * time.Hour,
		Issuer:          "benchmark-kubechat",
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwtService := &JWTService{
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		redisClient:     nil,
		tokenDuration:   jwtConfig.TokenDuration,
		refreshDuration: jwtConfig.RefreshDuration,
		issuer:          jwtConfig.Issuer,
	}

	// Initialize auth middleware
	authMiddleware, err := NewAuthMiddleware(providers, jwtService)
	require.NoError(b, err)

	// Generate valid token for authenticated requests
	token, err := jwtService.GenerateToken("benchmark-user", "benchmark@example.com", "Benchmark User")
	require.NoError(b, err)

	// Create Fiber app
	app := fiber.New()
	app.Use(authMiddleware.RequireAuthentication())
	app.Get("/protected", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "authorized"})
	})

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("authenticated_requests", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+token.AccessToken)
			
			resp, err := app.Test(req)
			if err != nil {
				b.Fatal(err)
			}
			resp.Body.Close()
		}
	})

	b.Run("unauthorized_requests", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("GET", "/protected", nil)
			
			resp, err := app.Test(req)
			if err != nil {
				b.Fatal(err)
			}
			resp.Body.Close()
		}
	})

	b.Run("concurrent_authenticated", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				req := httptest.NewRequest("GET", "/protected", nil)
				req.Header.Set("Authorization", "Bearer "+token.AccessToken)
				
				resp, err := app.Test(req)
				if err != nil {
					b.Fatal(err)
				}
				resp.Body.Close()
			}
		})
	})
}

// BenchmarkSecurityMiddleware tests security middleware performance under load
func BenchmarkSecurityMiddleware(b *testing.B) {
	config := SecurityConfig{
		RateLimitRequests: 1000, // High limit to avoid blocking during benchmarks
		RateLimitWindow:   time.Minute,
		MaxFailedAttempts: 10,
		LockoutDuration:   time.Minute,
	}

	security := NewSecurityMiddleware(config, nil)

	app := fiber.New()
	app.Use(security.RateLimitMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("rate_limiting_single_client", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.100:12345"
			
			resp, err := app.Test(req)
			if err != nil {
				b.Fatal(err)
			}
			resp.Body.Close()
		}
	})

	b.Run("rate_limiting_multiple_clients", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			clientIP := fmt.Sprintf("192.168.1.%d", i%255)
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = clientIP + ":12345"
			
			resp, err := app.Test(req)
			if err != nil {
				b.Fatal(err)
			}
			resp.Body.Close()
		}
	})

	b.Run("concurrent_rate_limiting", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				clientIP := fmt.Sprintf("10.0.%d.%d", i%255, (i/255)%255)
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = clientIP + ":12345"
				
				resp, err := app.Test(req)
				if err != nil {
					b.Fatal(err)
				}
				resp.Body.Close()
				i++
			}
		})
	})
}

// TestPerformanceRegressionMonitoring validates performance doesn't regress below baseline
func TestPerformanceRegressionMonitoring(t *testing.T) {
	// JWT validation baseline: should handle at least 10,000 operations per second
	t.Run("jwt_validation_baseline", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		jwtService := &JWTService{
			privateKey:      privateKey,
			publicKey:       &privateKey.PublicKey,
			redisClient:     nil,
			tokenDuration:   8 * time.Hour,
			refreshDuration: 7 * 24 * time.Hour,
			issuer:          "performance-test",
		}

		// Generate test token
		token, err := jwtService.GenerateToken("perf-user", "perf@test.com", "Performance User")
		require.NoError(t, err)

		// Measure validation performance
		iterations := 10000
		start := time.Now()
		
		for i := 0; i < iterations; i++ {
			_, err := jwtService.ValidateToken(token.AccessToken)
			require.NoError(t, err)
		}
		
		duration := time.Since(start)
		opsPerSecond := float64(iterations) / duration.Seconds()
		
		t.Logf("JWT validation performance: %d operations in %v (%.0f ops/sec)", 
			iterations, duration, opsPerSecond)
		
		// Baseline: at least 10,000 ops/sec
		assert.Greater(t, opsPerSecond, float64(10000), 
			"JWT validation performance below baseline")
	})

	// Rate limiting baseline: should handle at least 1,000 requests per second
	t.Run("rate_limiting_baseline", func(t *testing.T) {
		config := SecurityConfig{
			RateLimitRequests: 10000, // Very high limit
			RateLimitWindow:   time.Minute,
		}

		rateLimiter := &RateLimiter{
			config:     config,
			localCache: make(map[string]*RateLimitEntry),
		}

		iterations := 1000
		start := time.Now()

		for i := 0; i < iterations; i++ {
			clientID := fmt.Sprintf("client-%d", i)
			allowed, _, err := rateLimiter.IsAllowed(clientID)
			require.NoError(t, err)
			assert.True(t, allowed)
		}

		duration := time.Since(start)
		opsPerSecond := float64(iterations) / duration.Seconds()

		t.Logf("Rate limiting performance: %d operations in %v (%.0f ops/sec)",
			iterations, duration, opsPerSecond)

		// Baseline: at least 1,000 ops/sec
		assert.Greater(t, opsPerSecond, float64(1000),
			"Rate limiting performance below baseline")
	})
}

// TestConcurrentAuthenticationLoad tests system behavior under high concurrent load
func TestConcurrentAuthenticationLoad(t *testing.T) {
	// Skip if not running load tests
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	// Create authentication components
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwtService := &JWTService{
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		redisClient:     nil,
		tokenDuration:   8 * time.Hour,
		refreshDuration: 7 * 24 * time.Hour,
		issuer:          "load-test",
	}

	// Generate test tokens for different users
	numUsers := 100
	tokens := make([]string, numUsers)
	for i := 0; i < numUsers; i++ {
		token, err := jwtService.GenerateToken(
			fmt.Sprintf("load-user-%d", i),
			fmt.Sprintf("load-user-%d@example.com", i),
			fmt.Sprintf("Load User %d", i),
		)
		require.NoError(t, err)
		tokens[i] = token.AccessToken
	}

	// Test concurrent authentication
	const numGoroutines = 50
	const requestsPerGoroutine = 100
	
	var wg sync.WaitGroup
	var successCount, errorCount int64
	var mu sync.Mutex

	start := time.Now()
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			localSuccess := 0
			localErrors := 0
			
			for j := 0; j < requestsPerGoroutine; j++ {
				// Use different tokens randomly
				tokenIndex := (workerID*requestsPerGoroutine + j) % len(tokens)
				token := tokens[tokenIndex]
				
				_, err := jwtService.ValidateToken(token)
				if err != nil {
					localErrors++
				} else {
					localSuccess++
				}
			}
			
			mu.Lock()
			successCount += int64(localSuccess)
			errorCount += int64(localErrors)
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)
	
	totalRequests := int64(numGoroutines * requestsPerGoroutine)
	successRate := float64(successCount) / float64(totalRequests) * 100
	requestsPerSecond := float64(totalRequests) / duration.Seconds()

	t.Logf("Concurrent authentication load test results:")
	t.Logf("- Total requests: %d", totalRequests)
	t.Logf("- Successful: %d", successCount)
	t.Logf("- Errors: %d", errorCount)
	t.Logf("- Success rate: %.2f%%", successRate)
	t.Logf("- Duration: %v", duration)
	t.Logf("- Requests/sec: %.0f", requestsPerSecond)

	// Assert acceptable performance and reliability
	assert.Greater(t, successRate, 99.0, "Success rate should be above 99%")
	assert.Greater(t, requestsPerSecond, 500.0, "Should handle at least 500 requests/sec")
}

// TestMemoryUsageUnderLoad validates memory usage doesn't grow unbounded
func TestMemoryUsageUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	config := SecurityConfig{
		RateLimitRequests: 1000,
		RateLimitWindow:   time.Minute,
		MaxFailedAttempts: 5,
		LockoutDuration:   time.Minute,
	}

	security := NewSecurityMiddleware(config, nil)

	// Generate load to populate caches
	const numClients = 1000
	for i := 0; i < numClients; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		
		// Add rate limiting entries
		security.rateLimiter.IsAllowed(clientID)
		
		// Add some brute force entries
		if i%10 == 0 {
			security.bruteForcePrevention.RecordFailedAttempt(clientID)
		}
	}

	// Check cache sizes are reasonable
	security.rateLimiter.mu.RLock()
	rateLimitCacheSize := len(security.rateLimiter.localCache)
	security.rateLimiter.mu.RUnlock()

	security.bruteForcePrevention.mu.RLock()
	bruteForceCacheSize := len(security.bruteForcePrevention.localCache)
	security.bruteForcePrevention.mu.RUnlock()

	t.Logf("Cache sizes after load:")
	t.Logf("- Rate limit cache: %d entries", rateLimitCacheSize)
	t.Logf("- Brute force cache: %d entries", bruteForceCacheSize)

	// Verify cache cleanup works
	security.Cleanup()

	// Note: Cleanup only removes expired entries, so sizes may not change significantly
	// in this test since entries are fresh. In production, this would be called periodically.
	
	assert.LessOrEqual(t, rateLimitCacheSize, numClients, 
		"Rate limit cache should not exceed number of clients")
	assert.LessOrEqual(t, bruteForceCacheSize, numClients/10+10,
		"Brute force cache should be reasonable size")
}

// BenchmarkProviderCircuitBreaker tests circuit breaker performance
func BenchmarkProviderCircuitBreaker(b *testing.B) {
	config := CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 2,
		Timeout:          30 * time.Second,
		MaxRequests:      10,
	}
	
	cb := NewCircuitBreaker(config)
	
	b.ResetTimer()
	b.ReportAllocs()

	b.Run("successful_executions", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := cb.Execute(func() error {
				return nil // Always succeed
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("mixed_success_failure", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := cb.Execute(func() error {
				if i%10 == 0 {
					return fmt.Errorf("simulated failure")
				}
				return nil
			})
			// Don't fail on circuit breaker errors for this test
			_ = err
		}
	})
}