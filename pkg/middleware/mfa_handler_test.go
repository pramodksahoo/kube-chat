package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Note: Using existing MockRedisClient and MockJWTService from jwt_test.go

func TestMFAHandler_CreateChallenge(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		method        MFAMethod
		sessionData   map[string]interface{}
		setupMocks    func(*MockRedisClient)
		expectedError bool
	}{
		{
			name:   "successful TOTP challenge creation",
			userID: "user123",
			method: MFAMethodTOTP,
			sessionData: map[string]interface{}{
				"operation": "get-pods",
				"namespace": "default",
			},
			setupMocks: func(mockRedis *MockRedisClient) {
				mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))
			},
			expectedError: false,
		},
		{
			name:   "successful SMS challenge creation",
			userID: "user123",
			method: MFAMethodSMS,
			sessionData: map[string]interface{}{
				"phone_number": "+1234567890",
			},
			setupMocks: func(mockRedis *MockRedisClient) {
				mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))
			},
			expectedError: false,
		},
		{
			name:   "successful push challenge creation",
			userID: "user123",
			method: MFAMethodPush,
			sessionData: map[string]interface{}{
				"device_id": "device123",
			},
			setupMocks: func(mockRedis *MockRedisClient) {
				mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRedis := &MockRedisClient{}
			mockJWT := &MockJWTService{}
			
			tt.setupMocks(mockRedis)

			config := MFAConfig{
				TOTPIssuer:      "KubeChat",
				ChallengeExpiry: 5 * time.Minute,
			}

			handler := NewMFAHandler(config, mockRedis, mockJWT)
			require.NotNil(t, handler)

			ctx := context.Background()
			challenge, err := handler.CreateChallenge(ctx, tt.userID, tt.method, tt.sessionData)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, challenge)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, challenge)
				assert.Equal(t, tt.userID, challenge.UserID)
				assert.Equal(t, tt.method, challenge.Method)
				assert.NotEmpty(t, challenge.ChallengeID)
				assert.False(t, challenge.CreatedAt.IsZero())
				assert.True(t, challenge.ExpiresAt.After(challenge.CreatedAt))
			}

			mockRedis.AssertExpectations(t)
		})
	}
}

func TestMFAHandler_ValidateChallenge(t *testing.T) {
	tests := []struct {
		name            string
		challengeID     string
		response        map[string]interface{}
		storedChallenge *MFAChallenge
		setupMocks      func(*MockRedisClient, *MockJWTService)
		expectedSuccess bool
		expectedError   bool
	}{
		{
			name:        "successful TOTP validation",
			challengeID: "challenge123",
			response: map[string]interface{}{
				"totp_code": "123456",
			},
			storedChallenge: &MFAChallenge{
				ChallengeID: "challenge123",
				UserID:      "user123",
				Method:      MFAMethodTOTP,
				Secret:      "test_secret",
				CreatedAt:   time.Now(),
				ExpiresAt:   time.Now().Add(5 * time.Minute),
				Attempts:    0,
			},
			setupMocks: func(mockRedis *MockRedisClient, mockJWT *MockJWTService) {
				challenge := &MFAChallenge{
					ChallengeID: "challenge123",
					UserID:      "user123",
					Method:      MFAMethodTOTP,
					Secret:      "test_secret",
					CreatedAt:   time.Now(),
					ExpiresAt:   time.Now().Add(5 * time.Minute),
					Attempts:    0,
				}
				challengeJSON, _ := json.Marshal(challenge)
				mockRedis.On("Get", mock.Anything, "kubechat:mfa:challenge:challenge123").Return(&redis.StringCmd{}).Once()
				mockRedis.On("Get", mock.Anything, "kubechat:mfa:challenge:challenge123").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetVal(string(challengeJSON))
					return cmd
				}(context.Background(), "kubechat:mfa:challenge:challenge123"))
				mockRedis.On("Del", mock.Anything, []string{"kubechat:mfa:challenge:challenge123"}).Return(&redis.IntCmd{}).Once()
			},
			expectedSuccess: true,
			expectedError:   false,
		},
		{
			name:        "challenge not found",
			challengeID: "nonexistent",
			response:    map[string]interface{}{},
			setupMocks: func(mockRedis *MockRedisClient, mockJWT *MockJWTService) {
				mockRedis.On("Get", mock.Anything, "kubechat:mfa:challenge:nonexistent").Return(func(ctx context.Context, key string) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx, "get", key)
					cmd.SetErr(redis.Nil)
					return cmd
				}(context.Background(), "kubechat:mfa:challenge:nonexistent"))
			},
			expectedSuccess: false,
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRedis := &MockRedisClient{}
			mockJWT := &MockJWTService{}
			
			if tt.setupMocks != nil {
				tt.setupMocks(mockRedis, mockJWT)
			}

			config := MFAConfig{
				TOTPIssuer:      "KubeChat",
				ChallengeExpiry: 5 * time.Minute,
			}

			handler := NewMFAHandler(config, mockRedis, mockJWT)
			require.NotNil(t, handler)

			ctx := context.Background()
			response, err := handler.ValidateChallenge(ctx, tt.challengeID, tt.response)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.Equal(t, tt.expectedSuccess, response.Success)
			}

			mockRedis.AssertExpectations(t)
		})
	}
}

func TestMFAHandler_IsHighRiskOperation(t *testing.T) {
	config := MFAConfig{
		TOTPIssuer:      "KubeChat",
		ChallengeExpiry: 5 * time.Minute,
	}
	handler := NewMFAHandler(config, nil, nil)

	tests := []struct {
		operation string
		expected  bool
	}{
		{"delete-namespace", true},
		{"modify-rbac", true},
		{"access-secrets", true},
		{"delete-secret", true},
		{"create-cluster-role", true},
		{"get-pods", false},
		{"list-services", false},
		{"describe-deployment", false},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			result := handler.IsHighRiskOperation(tt.operation)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMFAHandler_GetSupportedMethods(t *testing.T) {
	config := MFAConfig{
		TOTPIssuer:      "KubeChat",
		ChallengeExpiry: 5 * time.Minute,
	}
	handler := NewMFAHandler(config, nil, nil)

	methods := handler.GetSupportedMethods()
	assert.NotEmpty(t, methods)
	assert.Contains(t, methods, MFAMethodTOTP)
	assert.Contains(t, methods, MFAMethodSMS)
	assert.Contains(t, methods, MFAMethodPush)
	assert.Contains(t, methods, MFAMethodHardware)
}

func TestMFAHandler_GenerateTOTPSecret(t *testing.T) {
	config := MFAConfig{
		TOTPIssuer:      "KubeChat",
		ChallengeExpiry: 5 * time.Minute,
	}
	handler := NewMFAHandler(config, nil, nil)

	secret, qrCode, err := handler.GenerateTOTPSecret("test@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.NotEmpty(t, qrCode)
	assert.Contains(t, qrCode, "otpauth://totp/")
	assert.Contains(t, qrCode, "KubeChat")
	assert.Contains(t, qrCode, "test@example.com")
}

// Benchmark tests for performance
func BenchmarkMFAHandler_CreateChallenge(b *testing.B) {
	mockRedis := &MockRedisClient{}
	mockJWT := &MockJWTService{}
	
	mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))

	config := MFAConfig{
		TOTPIssuer:      "KubeChat",
		ChallengeExpiry: 5 * time.Minute,
	}
	handler := NewMFAHandler(config, mockRedis, mockJWT)

	sessionData := map[string]interface{}{
		"operation": "get-pods",
		"namespace": "default",
	}

	ctx := context.Background()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := handler.CreateChallenge(ctx, "user123", MFAMethodTOTP, sessionData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMFAHandler_IsHighRiskOperation(b *testing.B) {
	config := MFAConfig{
		TOTPIssuer:      "KubeChat",
		ChallengeExpiry: 5 * time.Minute,
	}
	handler := NewMFAHandler(config, nil, nil)

	operations := []string{
		"delete-namespace",
		"get-pods",
		"modify-rbac",
		"list-services",
		"access-secrets",
	}

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		for _, op := range operations {
			handler.IsHighRiskOperation(op)
		}
	}
}