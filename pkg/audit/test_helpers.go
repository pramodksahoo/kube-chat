package audit

import (
	"context"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/mock"
)

// MockAuditStorage implements AuditStorage for testing
type MockAuditStorage struct {
	mock.Mock
}

func (m *MockAuditStorage) StoreEvent(ctx context.Context, event *models.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockAuditStorage) GetEvent(ctx context.Context, eventID string) (*models.AuditEvent, error) {
	args := m.Called(ctx, eventID)
	return args.Get(0).(*models.AuditEvent), args.Error(1)
}

func (m *MockAuditStorage) QueryEvents(ctx context.Context, filter models.AuditEventFilter) ([]*models.AuditEvent, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*models.AuditEvent), args.Error(1)
}

func (m *MockAuditStorage) VerifyIntegrity(ctx context.Context, eventID string) (bool, error) {
	args := m.Called(ctx, eventID)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuditStorage) GetEventsByUser(ctx context.Context, userID string, limit int) ([]*models.AuditEvent, error) {
	args := m.Called(ctx, userID, limit)
	return args.Get(0).([]*models.AuditEvent), args.Error(1)
}

func (m *MockAuditStorage) GetEventsByTimeRange(ctx context.Context, start, end time.Time) ([]*models.AuditEvent, error) {
	args := m.Called(ctx, start, end)
	return args.Get(0).([]*models.AuditEvent), args.Error(1)
}

func (m *MockAuditStorage) CountEventsByType(ctx context.Context) (map[models.AuditEventType]int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[models.AuditEventType]int64), args.Error(1)
}

func (m *MockAuditStorage) CountEvents(ctx context.Context, filter models.AuditEventFilter) (int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditStorage) CleanupExpiredEvents(ctx context.Context, retentionDays int) (int64, error) {
	args := m.Called(ctx, retentionDays)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditStorage) GetStorageStats(ctx context.Context) (*StorageStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*StorageStats), args.Error(1)
}

func (m *MockAuditStorage) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}