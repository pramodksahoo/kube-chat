package models

import (
	"testing"
	
	"github.com/stretchr/testify/assert"
)

func TestNewRBACPermissionError(t *testing.T) {
	// Test basic RBAC error creation
	rbacError := NewRBACPermissionError(
		"test-user",
		[]string{"test-group"},
		"pods", 
		"get", 
		"default", 
		"Permission denied for testing",
	)

	assert.NotNil(t, rbacError)
	assert.Equal(t, "test-user", rbacError.User)
	assert.Equal(t, []string{"test-group"}, rbacError.Groups)
	assert.Equal(t, "pods", rbacError.Resource)
	assert.Equal(t, "get", rbacError.Verb)
	assert.Equal(t, "default", rbacError.Namespace)
	assert.Equal(t, "Permission denied for testing", rbacError.Reason)
	assert.Equal(t, ErrorTypePermissionDenied, rbacError.Type)
	assert.NotEmpty(t, rbacError.ValidationID)
	assert.NotEmpty(t, rbacError.Suggestions)
}

func TestRBACPermissionError_GetUserFriendlyMessage(t *testing.T) {
	rbacError := &RBACPermissionError{
		User:          "test-user",
		Groups:        []string{"test-group"},
		Resource:      "pods",
		Verb:          "get",
		Namespace:     "default",
		Reason:        "Permission denied",
		OriginalInput: "get pods",
		Command:       "kubectl get pods",
		Severity:      ErrorSeverityMedium,
		Suggestions:   []string{"Try a different namespace", "Contact your administrator"},
	}

	message := rbacError.GetUserFriendlyMessage()
	
	assert.Contains(t, message, "Permission Denied")
	assert.Contains(t, message, "get pods")
	assert.Contains(t, message, "kubectl get pods")
	assert.Contains(t, message, "test-user")
	assert.Contains(t, message, "Try a different namespace")
	assert.Contains(t, message, "additional role permissions")
}

func TestRBACPermissionError_Error(t *testing.T) {
	rbacError := &RBACPermissionError{
		User:      "test-user",
		Resource:  "pods",
		Verb:      "get",
		Namespace: "default",
		Reason:    "Permission denied",
	}

	errMsg := rbacError.Error()
	expected := "RBAC permission denied: user 'test-user' cannot 'get' resource 'pods' in namespace 'default': Permission denied"
	assert.Equal(t, expected, errMsg)
}

func TestRBACPermissionError_ToKubectlError(t *testing.T) {
	rbacError := &RBACPermissionError{
		User:          "test-user",
		Resource:      "pods",
		Verb:          "get",
		Namespace:     "default",
		Reason:        "Permission denied",
		Type:          ErrorTypePermissionDenied,
		Suggestions:   []string{"Try a different namespace"},
		Recoverable:   true,
		EscalationLevel: EscalationLevelMedium,
	}

	kubectlErr := rbacError.ToKubectlError()
	
	assert.NotNil(t, kubectlErr)
	assert.Equal(t, ErrorTypePermissionDenied, kubectlErr.Type)
	assert.Equal(t, "RBAC_PERMISSION_DENIED", kubectlErr.Code)
	assert.Equal(t, "pods", kubectlErr.Resource)
	assert.Equal(t, "default", kubectlErr.Namespace)
	assert.True(t, kubectlErr.Recoverable)
	assert.Len(t, kubectlErr.RecoveryActions, 1)
	assert.Equal(t, RecoveryActionRequestPermission, kubectlErr.RecoveryActions[0].Type)
}