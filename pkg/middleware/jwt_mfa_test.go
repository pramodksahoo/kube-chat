package middleware

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestJWTService_UpdateMFAStatus(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     string
		mfaCompleted  bool
		method        string
		validity      time.Duration
		setupMocks    func(*MockRedisClient)
		expectedError bool
	}{
		{
			name:         "successful MFA status update",
			sessionID:    "session123",
			mfaCompleted: true,
			method:       "TOTP",
			validity:     4 * time.Hour,
			setupMocks: func(mockRedis *MockRedisClient) {
				sessionData := map[string]interface{}{
					"user_id":      "user123",
					"active":       true,
					"mfa_completed": false,
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123"))
				
				mockRedis.On("Set", mock.Anything, "kubechat:session:session123", mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))
			},
			expectedError: false,
		},
		{
			name:         "session not found",
			sessionID:    "nonexistent",
			mfaCompleted: true,
			method:       "TOTP",
			validity:     4 * time.Hour,
			setupMocks: func(mockRedis *MockRedisClient) {
				mockRedis.On("Get", mock.Anything, "kubechat:session:nonexistent").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetErr(redis.Nil)
					return cmd
				}(context.Background(), "kubechat:session:nonexistent"))
			},
			expectedError: true,
		},
		{
			name:         "inactive session",
			sessionID:    "inactive_session",
			mfaCompleted: true,
			method:       "TOTP",
			validity:     4 * time.Hour,
			setupMocks: func(mockRedis *MockRedisClient) {
				sessionData := map[string]interface{}{
					"user_id": "user123",
					"active":  false, // Inactive session
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				mockRedis.On("Get", mock.Anything, "kubechat:session:inactive_session").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:inactive_session"))
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRedis := &MockRedisClient{}
			tt.setupMocks(mockRedis)

			config := JWTConfig{
				TokenDuration:   8 * time.Hour,
				RefreshDuration: 24 * time.Hour,
			}

			jwtService, err := NewJWTService(config)
			require.NoError(t, err)
			jwtService.redisClient = mockRedis

			err = jwtService.UpdateMFAStatus(tt.sessionID, tt.mfaCompleted, tt.method, tt.validity)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockRedis.AssertExpectations(t)
		})
	}
}

func TestJWTService_GetMFAStatus(t *testing.T) {
	tests := []struct {
		name            string
		sessionID       string
		storedSession   map[string]interface{}
		setupMocks      func(*MockRedisClient)
		expectedStatus  func(*MFASessionStatus)
		expectedError   bool
	}{
		{
			name:      "successful MFA status retrieval",
			sessionID: "session123",
			storedSession: map[string]interface{}{
				"user_id":               "user123",
				"mfa_completed":         true,
				"mfa_method":           "TOTP",
				"mfa_timestamp":        float64(time.Now().Unix()),
				"mfa_expires_at":       float64(time.Now().Add(4 * time.Hour).Unix()),
				"mfa_validity_duration": float64((4 * time.Hour).Seconds()),
				"requires_mfa_stepup":  false,
				"stepup_operations":    []interface{}{"delete-namespace"},
				"mfa_failure_count":    float64(0),
				"mfa_locked_until":     float64(0),
			},
			setupMocks: func(mockRedis *MockRedisClient) {
				sessionData := map[string]interface{}{
					"user_id":               "user123",
					"mfa_completed":         true,
					"mfa_method":           "TOTP",
					"mfa_timestamp":        float64(time.Now().Unix()),
					"mfa_expires_at":       float64(time.Now().Add(4 * time.Hour).Unix()),
					"mfa_validity_duration": float64((4 * time.Hour).Seconds()),
					"requires_mfa_stepup":  false,
					"stepup_operations":    []interface{}{"delete-namespace"},
					"mfa_failure_count":    float64(0),
					"mfa_locked_until":     float64(0),
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123"))
			},
			expectedStatus: func(status *MFASessionStatus) {
				assert.Equal(t, "session123", status.SessionID)
				assert.Equal(t, "user123", status.UserID)
				assert.True(t, status.MFACompleted)
				assert.Equal(t, "TOTP", status.MFAMethod)
				assert.Equal(t, 4*time.Hour, status.MFAValidityDuration)
				assert.False(t, status.RequiresMFAStepUp)
				assert.Contains(t, status.StepUpOperations, "delete-namespace")
				assert.Equal(t, 0, status.MFAFailureCount)
			},
			expectedError: false,
		},
		{
			name:      "session not found",
			sessionID: "nonexistent",
			setupMocks: func(mockRedis *MockRedisClient) {
				mockRedis.On("Get", mock.Anything, "kubechat:session:nonexistent").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetErr(redis.Nil)
					return cmd
				}(context.Background(), "kubechat:session:nonexistent"))
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRedis := &MockRedisClient{}
			tt.setupMocks(mockRedis)

			config := JWTConfig{
				TokenDuration:   8 * time.Hour,
				RefreshDuration: 24 * time.Hour,
			}

			jwtService, err := NewJWTService(config)
			require.NoError(t, err)
			jwtService.redisClient = mockRedis

			status, err := jwtService.GetMFAStatus(tt.sessionID)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, status)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, status)
				tt.expectedStatus(status)
			}

			mockRedis.AssertExpectations(t)
		})
	}
}

func TestJWTService_RequiresMFAStepUp(t *testing.T) {
	tests := []struct {
		name           string
		sessionID      string
		operation      string
		mockMFAHandler *MFAHandler
		setupMocks     func(*MockRedisClient, *MFAHandler)
		expectedResult bool
		expectedError  bool
	}{
		{
			name:      "requires step-up for expired MFA",
			sessionID: "session123",
			operation: "get-pods",
			setupMocks: func(mockRedis *MockRedisClient, handler *MFAHandler) {
				sessionData := map[string]interface{}{
					"user_id":        "user123",
					"mfa_completed":  false, // MFA not completed
					"mfa_expires_at": float64(time.Now().Add(-1 * time.Hour).Unix()), // Expired
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123"))
			},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name:      "requires step-up for high-risk operation",
			sessionID: "session123",
			operation: "delete-namespace",
			setupMocks: func(mockRedis *MockRedisClient, handler *MFAHandler) {
				now := time.Now()
				sessionData := map[string]interface{}{
					"user_id":        "user123",
					"mfa_completed":  true,
					"mfa_timestamp":  float64(now.Add(-30 * time.Minute).Unix()), // 30 minutes ago
					"mfa_expires_at": float64(now.Add(4 * time.Hour).Unix()),     // Valid
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123"))
			},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name:      "no step-up required for valid MFA",
			sessionID: "session123",
			operation: "get-pods",
			setupMocks: func(mockRedis *MockRedisClient, handler *MFAHandler) {
				now := time.Now()
				sessionData := map[string]interface{}{
					"user_id":             "user123",
					"mfa_completed":       true,
					"mfa_timestamp":       float64(now.Add(-5 * time.Minute).Unix()), // 5 minutes ago
					"mfa_expires_at":      float64(now.Add(4 * time.Hour).Unix()),    // Valid
					"requires_mfa_stepup": false,
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123"))
			},
			expectedResult: false,
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRedis := &MockRedisClient{}
			
			config := JWTConfig{
				TokenDuration:   8 * time.Hour,
				RefreshDuration: 24 * time.Hour,
			}

			jwtService, err := NewJWTService(config)
			require.NoError(t, err)
			jwtService.redisClient = mockRedis

			// Create a minimal MFA handler for testing
			mfaConfig := MFAConfig{
				TOTPIssuer:      "KubeChat",
				ChallengeExpiry: 5 * time.Minute,
			}
			mfaHandler := NewMFAHandler(mfaConfig, mockRedis, jwtService)
			jwtService.mfaHandler = mfaHandler

			tt.setupMocks(mockRedis, mfaHandler)

			result, err := jwtService.RequiresMFAStepUp(tt.sessionID, tt.operation)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}

			mockRedis.AssertExpectations(t)
		})
	}
}

func TestJWTService_ValidateMFAForOperation(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     string
		operation     string
		setupMocks    func(*MockRedisClient, *MFAHandler)
		expectedValid bool
		expectedError bool
	}{
		{
			name:      "valid MFA for operation",
			sessionID: "session123",
			operation: "get-pods",
			setupMocks: func(mockRedis *MockRedisClient, handler *MFAHandler) {
				now := time.Now()
				// Mock GetMFAStatus call
				sessionData := map[string]interface{}{
					"user_id":        "user123",
					"mfa_completed":  true,
					"mfa_expires_at": float64(now.Add(2 * time.Hour).Unix()), // Valid for 2 more hours
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				// First call for RequiresMFAStepUp
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123")).Once()
				
				// Second call for GetMFAStatus
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123")).Once()
				
				// Third call for updating last validation timestamp
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123")).Once()
				
				mockRedis.On("Set", mock.Anything, "kubechat:session:session123", mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background())).Maybe()
			},
			expectedValid: true,
			expectedError: false,
		},
		{
			name:      "invalid - MFA expired",
			sessionID: "session123",
			operation: "get-pods",
			setupMocks: func(mockRedis *MockRedisClient, handler *MFAHandler) {
				now := time.Now()
				sessionData := map[string]interface{}{
					"user_id":        "user123",
					"mfa_completed":  true,
					"mfa_expires_at": float64(now.Add(-1 * time.Hour).Unix()), // Expired 1 hour ago
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				// First call for RequiresMFAStepUp (will return true due to expired MFA)
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123")).Once()
			},
			expectedValid: false,
			expectedError: true,
		},
		{
			name:      "invalid - MFA not completed",
			sessionID: "session123",
			operation: "get-pods",
			setupMocks: func(mockRedis *MockRedisClient, handler *MFAHandler) {
				now := time.Now()
				sessionData := map[string]interface{}{
					"user_id":        "user123",
					"mfa_completed":  false, // MFA not completed
					"mfa_expires_at": float64(now.Add(2 * time.Hour).Unix()),
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				// First call for RequiresMFAStepUp (will return true due to incomplete MFA)
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123")).Once()
			},
			expectedValid: false,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRedis := &MockRedisClient{}
			
			config := JWTConfig{
				TokenDuration:   8 * time.Hour,
				RefreshDuration: 24 * time.Hour,
			}

			jwtService, err := NewJWTService(config)
			require.NoError(t, err)
			jwtService.redisClient = mockRedis

			// Create a minimal MFA handler for testing
			mfaConfig := MFAConfig{
				TOTPIssuer:      "KubeChat",
				ChallengeExpiry: 5 * time.Minute,
			}
			mfaHandler := NewMFAHandler(mfaConfig, mockRedis, jwtService)
			jwtService.mfaHandler = mfaHandler

			tt.setupMocks(mockRedis, mfaHandler)

			valid, err := jwtService.ValidateMFAForOperation(tt.sessionID, tt.operation)

			if tt.expectedError {
				assert.Error(t, err)
				assert.False(t, valid)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedValid, valid)
			}

			mockRedis.AssertExpectations(t)
		})
	}
}

func TestJWTService_SetMFAStepUpRequirement(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     string
		required      bool
		operation     string
		setupMocks    func(*MockRedisClient)
		expectedError bool
	}{
		{
			name:      "set step-up requirement successfully",
			sessionID: "session123",
			required:  true,
			operation: "delete-namespace",
			setupMocks: func(mockRedis *MockRedisClient) {
				sessionData := map[string]interface{}{
					"user_id":            "user123",
					"requires_mfa_stepup": false,
					"stepup_operations":  []interface{}{},
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123"))
				
				mockRedis.On("Set", mock.Anything, "kubechat:session:session123", mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))
			},
			expectedError: false,
		},
		{
			name:      "remove step-up requirement successfully",
			sessionID: "session123",
			required:  false,
			operation: "delete-namespace",
			setupMocks: func(mockRedis *MockRedisClient) {
				sessionData := map[string]interface{}{
					"user_id":            "user123",
					"requires_mfa_stepup": true,
					"stepup_operations":  []interface{}{"delete-namespace", "modify-rbac"},
				}
				sessionJSON, _ := json.Marshal(sessionData)
				
				mockRedis.On("Get", mock.Anything, "kubechat:session:session123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(sessionJSON))
					return cmd
				}(context.Background(), "kubechat:session:session123"))
				
				mockRedis.On("Set", mock.Anything, "kubechat:session:session123", mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRedis := &MockRedisClient{}
			tt.setupMocks(mockRedis)

			config := JWTConfig{
				TokenDuration:   8 * time.Hour,
				RefreshDuration: 24 * time.Hour,
			}

			jwtService, err := NewJWTService(config)
			require.NoError(t, err)
			jwtService.redisClient = mockRedis

			err = jwtService.SetMFAStepUpRequirement(tt.sessionID, tt.required, tt.operation)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockRedis.AssertExpectations(t)
		})
	}
}

func TestJWTService_InvalidateMFAForSessions(t *testing.T) {
	mockRedis := &MockRedisClient{}
	
	// Mock GetAllActiveSessions
	sessionKeys := []string{"kubechat:session:session1", "kubechat:session:session2"}
	mockRedis.On("Keys", mock.Anything, "kubechat:session:*").Return(func(ctx context.Context, pattern string) *redis.StringSliceCmd {
		cmd := redis.NewStringSliceCmd(ctx, "keys", pattern)
		cmd.SetVal(sessionKeys)
		return cmd
	}(context.Background(), "kubechat:session:*"))

	// Mock session data for both sessions
	for i := 1; i <= 2; i++ {
		sessionData := map[string]interface{}{
			"user_id":      "user123",
			"active":       true,
			"mfa_completed": true,
		}
		sessionJSON, _ := json.Marshal(sessionData)
		sessionKey := fmt.Sprintf("kubechat:session:session%d", i)
		
		mockRedis.On("Get", mock.Anything, sessionKey).Return(func(ctx context.Context, key string) *redis.StringCmd {
			cmd := redis.NewStringCmd(ctx, "get", key)
			cmd.SetVal(string(sessionJSON))
			return cmd
		}(context.Background(), sessionKey)).Times(2) // Called twice per session
	}

	// Mock GetSessionInfo calls
	for i := 1; i <= 2; i++ {
		sessionInfo := &SessionInfo{
			SessionID: fmt.Sprintf("session%d", i),
			UserID:    "user123",
			Active:    true,
		}
		mockRedis.On("Get", mock.Anything, fmt.Sprintf("kubechat:session:session%d", i)).Return(func(ctx context.Context, key string) *redis.StringCmd {
			sessionData := map[string]interface{}{
				"user_id": "user123",
				"active":  true,
			}
			sessionJSON, _ := json.Marshal(sessionData)
			cmd := redis.NewStringCmd(ctx, "get", key)
			cmd.SetVal(string(sessionJSON))
			return cmd
		}(context.Background(), fmt.Sprintf("kubechat:session:session%d", i))).Maybe()
	}

	// Mock invalidation updates
	mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background())).Times(2)

	config := JWTConfig{
		TokenDuration:   8 * time.Hour,
		RefreshDuration: 24 * time.Hour,
	}

	jwtService, err := NewJWTService(config)
	require.NoError(t, err)
	jwtService.redisClient = mockRedis

	err = jwtService.InvalidateMFAForSessions("user123")
	assert.NoError(t, err)

	mockRedis.AssertExpectations(t)
}

// Benchmark tests
func BenchmarkJWTService_UpdateMFAStatus(b *testing.B) {
	mockRedis := &MockRedisClient{}
	
	sessionData := map[string]interface{}{
		"user_id": "user123",
		"active":  true,
	}
	sessionJSON, _ := json.Marshal(sessionData)
	
	mockRedis.On("Get", mock.Anything, mock.AnythingOfType("string")).Return(func(ctx context.Context, key string) *redis.StringCmd {
		cmd := redis.NewStringCmd(ctx, "get", key)
		cmd.SetVal(string(sessionJSON))
		return cmd
	}(context.Background(), "test"))
	
	mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))

	config := JWTConfig{
		TokenDuration:   8 * time.Hour,
		RefreshDuration: 24 * time.Hour,
	}

	jwtService, err := NewJWTService(config)
	if err != nil {
		b.Fatal(err)
	}
	jwtService.redisClient = mockRedis

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		err := jwtService.UpdateMFAStatus("session123", true, "TOTP", 4*time.Hour)
		if err != nil {
			b.Fatal(err)
		}
	}
}