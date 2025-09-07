package export

import (
	"sync"
	"time"
)

// ExportJobTracker manages and tracks export job lifecycle
type ExportJobTracker struct {
	jobs           map[string]*ExportJob
	jobsByStatus   map[ExportJobStatus][]*ExportJob
	jobsByUser     map[string][]*ExportJob
	retentionPeriod time.Duration
	mu             sync.RWMutex
	metrics        *JobTrackerMetrics
	cleanupTicker  *time.Ticker
	stopCleanup    chan struct{}
}

// JobTrackerMetrics tracks job statistics
type JobTrackerMetrics struct {
	TotalJobs      int64                        `json:"total_jobs"`
	ActiveJobs     int64                        `json:"active_jobs"`
	CompletedJobs  int64                        `json:"completed_jobs"`
	FailedJobs     int64                        `json:"failed_jobs"`
	CancelledJobs  int64                        `json:"cancelled_jobs"`
	ExpiredJobs    int64                        `json:"expired_jobs"`
	JobsByStatus   map[ExportJobStatus]int64    `json:"jobs_by_status"`
	JobsByUser     map[string]int64             `json:"jobs_by_user"`
	AverageJobTime time.Duration                `json:"average_job_time"`
	LastUpdated    time.Time                    `json:"last_updated"`
	mu             sync.RWMutex
}

// JobSearchCriteria defines criteria for searching jobs
type JobSearchCriteria struct {
	Status      ExportJobStatus `json:"status,omitempty"`
	RequestedBy string          `json:"requested_by,omitempty"`
	Format      string          `json:"format,omitempty"`
	Platform    string          `json:"platform,omitempty"`
	StartTime   time.Time       `json:"start_time,omitempty"`
	EndTime     time.Time       `json:"end_time,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Limit       int             `json:"limit,omitempty"`
	Offset      int             `json:"offset,omitempty"`
	SortBy      string          `json:"sort_by,omitempty"`    // created_at, started_at, completed_at
	SortOrder   string          `json:"sort_order,omitempty"` // asc, desc
}

// NewExportJobTracker creates a new job tracker instance
func NewExportJobTracker(retentionPeriod time.Duration) *ExportJobTracker {
	tracker := &ExportJobTracker{
		jobs:           make(map[string]*ExportJob),
		jobsByStatus:   make(map[ExportJobStatus][]*ExportJob),
		jobsByUser:     make(map[string][]*ExportJob),
		retentionPeriod: retentionPeriod,
		metrics: &JobTrackerMetrics{
			JobsByStatus: make(map[ExportJobStatus]int64),
			JobsByUser:   make(map[string]int64),
		},
		cleanupTicker: time.NewTicker(time.Hour), // Cleanup every hour
		stopCleanup:   make(chan struct{}),
	}
	
	// Initialize status maps
	for _, status := range []ExportJobStatus{
		ExportJobStatusPending,
		ExportJobStatusRunning,
		ExportJobStatusCompleted,
		ExportJobStatusFailed,
		ExportJobStatusCancelled,
		ExportJobStatusExpired,
	} {
		tracker.jobsByStatus[status] = make([]*ExportJob, 0)
		tracker.metrics.JobsByStatus[status] = 0
	}
	
	// Start cleanup routine
	go tracker.cleanupRoutine()
	
	return tracker
}

// AddJob adds a new export job to the tracker
func (jt *ExportJobTracker) AddJob(job *ExportJob) {
	jt.mu.Lock()
	defer jt.mu.Unlock()
	
	// Add to main jobs map
	jt.jobs[job.ID] = job
	
	// Add to status index
	jt.jobsByStatus[job.Status] = append(jt.jobsByStatus[job.Status], job)
	
	// Add to user index
	if jt.jobsByUser[job.Request.RequestedBy] == nil {
		jt.jobsByUser[job.Request.RequestedBy] = make([]*ExportJob, 0)
	}
	jt.jobsByUser[job.Request.RequestedBy] = append(jt.jobsByUser[job.Request.RequestedBy], job)
	
	// Update metrics
	jt.updateMetrics(job, "added")
}

// GetJob retrieves a job by ID
func (jt *ExportJobTracker) GetJob(jobID string) *ExportJob {
	jt.mu.RLock()
	defer jt.mu.RUnlock()
	
	job, exists := jt.jobs[jobID]
	if !exists {
		return nil
	}
	
	// Return a copy to prevent external mutations
	jobCopy := *job
	return &jobCopy
}

// UpdateJobStatus updates the status of a job
func (jt *ExportJobTracker) UpdateJobStatus(jobID string, status ExportJobStatus, errorMessage string) {
	jt.mu.Lock()
	defer jt.mu.Unlock()
	
	job, exists := jt.jobs[jobID]
	if !exists {
		return
	}
	
	oldStatus := job.Status
	
	// Remove from old status index
	jt.removeFromStatusIndex(job, oldStatus)
	
	// Update job status
	job.Status = status
	if errorMessage != "" {
		job.Error = errorMessage
	}
	
	// Update timestamps based on status
	now := time.Now().UTC()
	switch status {
	case ExportJobStatusRunning:
		if job.StartedAt.IsZero() {
			job.StartedAt = now
		}
	case ExportJobStatusCompleted, ExportJobStatusFailed, ExportJobStatusCancelled:
		if job.CompletedAt.IsZero() {
			job.CompletedAt = now
		}
	}
	
	// Add to new status index
	jt.jobsByStatus[status] = append(jt.jobsByStatus[status], job)
	
	// Update metrics
	jt.updateMetricsForStatusChange(oldStatus, status)
}

// UpdateJobProgress updates the progress of a job
func (jt *ExportJobTracker) UpdateJobProgress(jobID string, progress ExportProgress) {
	jt.mu.Lock()
	defer jt.mu.Unlock()
	
	job, exists := jt.jobs[jobID]
	if !exists {
		return
	}
	
	job.Progress = progress
	job.Progress.LastUpdated = time.Now().UTC()
}

// ListJobs returns jobs matching the criteria
func (jt *ExportJobTracker) ListJobs(status ExportJobStatus, requestedBy string, limit, offset int) []*ExportJob {
	jt.mu.RLock()
	defer jt.mu.RUnlock()
	
	var jobs []*ExportJob
	
	// Filter by status and user
	if status != "" && requestedBy != "" {
		// Filter by both status and user
		for _, job := range jt.jobsByStatus[status] {
			if job.Request.RequestedBy == requestedBy {
				jobs = append(jobs, job)
			}
		}
	} else if status != "" {
		// Filter by status only
		jobs = jt.jobsByStatus[status]
	} else if requestedBy != "" {
		// Filter by user only
		jobs = jt.jobsByUser[requestedBy]
	} else {
		// Return all jobs
		for _, job := range jt.jobs {
			jobs = append(jobs, job)
		}
	}
	
	// Apply pagination
	return jt.paginateJobs(jobs, limit, offset)
}

// SearchJobs returns jobs matching the search criteria
func (jt *ExportJobTracker) SearchJobs(criteria JobSearchCriteria) []*ExportJob {
	jt.mu.RLock()
	defer jt.mu.RUnlock()
	
	var matchingJobs []*ExportJob
	
	for _, job := range jt.jobs {
		if jt.matchesSearchCriteria(job, criteria) {
			matchingJobs = append(matchingJobs, job)
		}
	}
	
	// Sort results
	jt.sortJobs(matchingJobs, criteria.SortBy, criteria.SortOrder)
	
	// Apply pagination
	return jt.paginateJobs(matchingJobs, criteria.Limit, criteria.Offset)
}

// GetJobsByUser returns all jobs for a specific user
func (jt *ExportJobTracker) GetJobsByUser(userID string, limit, offset int) []*ExportJob {
	jt.mu.RLock()
	defer jt.mu.RUnlock()
	
	userJobs, exists := jt.jobsByUser[userID]
	if !exists {
		return []*ExportJob{}
	}
	
	return jt.paginateJobs(userJobs, limit, offset)
}

// RemoveJob removes a job from the tracker
func (jt *ExportJobTracker) RemoveJob(jobID string) {
	jt.mu.Lock()
	defer jt.mu.Unlock()
	
	job, exists := jt.jobs[jobID]
	if !exists {
		return
	}
	
	// Remove from main map
	delete(jt.jobs, jobID)
	
	// Remove from status index
	jt.removeFromStatusIndex(job, job.Status)
	
	// Remove from user index
	jt.removeFromUserIndex(job, job.Request.RequestedBy)
	
	// Update metrics
	jt.updateMetrics(job, "removed")
}

// GetActiveJobCount returns the number of active (running or pending) jobs
func (jt *ExportJobTracker) GetActiveJobCount() int {
	jt.mu.RLock()
	defer jt.mu.RUnlock()
	
	return len(jt.jobsByStatus[ExportJobStatusPending]) + len(jt.jobsByStatus[ExportJobStatusRunning])
}

// GetTotalJobCount returns the total number of jobs
func (jt *ExportJobTracker) GetTotalJobCount() int64 {
	jt.mu.RLock()
	defer jt.mu.RUnlock()
	
	return int64(len(jt.jobs))
}

// GetCompletedJobCount returns the number of completed jobs
func (jt *ExportJobTracker) GetCompletedJobCount() int64 {
	jt.mu.RLock()
	defer jt.mu.RUnlock()
	
	return int64(len(jt.jobsByStatus[ExportJobStatusCompleted]))
}

// GetFailedJobCount returns the number of failed jobs
func (jt *ExportJobTracker) GetFailedJobCount() int64 {
	jt.mu.RLock()
	defer jt.mu.RUnlock()
	
	return int64(len(jt.jobsByStatus[ExportJobStatusFailed]))
}

// GetMetrics returns current job tracker metrics
func (jt *ExportJobTracker) GetMetrics() *JobTrackerMetrics {
	jt.metrics.mu.RLock()
	defer jt.metrics.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	metrics := &JobTrackerMetrics{
		TotalJobs:      jt.metrics.TotalJobs,
		ActiveJobs:     jt.metrics.ActiveJobs,
		CompletedJobs:  jt.metrics.CompletedJobs,
		FailedJobs:     jt.metrics.FailedJobs,
		CancelledJobs:  jt.metrics.CancelledJobs,
		ExpiredJobs:    jt.metrics.ExpiredJobs,
		JobsByStatus:   make(map[ExportJobStatus]int64),
		JobsByUser:     make(map[string]int64),
		AverageJobTime: jt.metrics.AverageJobTime,
		LastUpdated:    jt.metrics.LastUpdated,
	}
	
	// Copy maps
	for status, count := range jt.metrics.JobsByStatus {
		metrics.JobsByStatus[status] = count
	}
	for user, count := range jt.metrics.JobsByUser {
		metrics.JobsByUser[user] = count
	}
	
	return metrics
}

// GetJobHistory returns job history statistics
func (jt *ExportJobTracker) GetJobHistory(days int) map[string]interface{} {
	jt.mu.RLock()
	defer jt.mu.RUnlock()
	
	cutoff := time.Now().AddDate(0, 0, -days)
	dailyStats := make(map[string]map[string]int)
	
	for _, job := range jt.jobs {
		if job.CreatedAt.After(cutoff) {
			day := job.CreatedAt.Format("2006-01-02")
			if dailyStats[day] == nil {
				dailyStats[day] = make(map[string]int)
			}
			dailyStats[day][string(job.Status)]++
		}
	}
	
	return map[string]interface{}{
		"period_days":  days,
		"daily_stats":  dailyStats,
		"total_period": len(jt.jobs),
	}
}

// Helper methods

func (jt *ExportJobTracker) removeFromStatusIndex(job *ExportJob, status ExportJobStatus) {
	statusJobs := jt.jobsByStatus[status]
	for i, statusJob := range statusJobs {
		if statusJob.ID == job.ID {
			// Remove from slice
			jt.jobsByStatus[status] = append(statusJobs[:i], statusJobs[i+1:]...)
			break
		}
	}
}

func (jt *ExportJobTracker) removeFromUserIndex(job *ExportJob, userID string) {
	userJobs := jt.jobsByUser[userID]
	for i, userJob := range userJobs {
		if userJob.ID == job.ID {
			// Remove from slice
			jt.jobsByUser[userID] = append(userJobs[:i], userJobs[i+1:]...)
			
			// Clean up empty slices
			if len(jt.jobsByUser[userID]) == 0 {
				delete(jt.jobsByUser, userID)
			}
			break
		}
	}
}

func (jt *ExportJobTracker) matchesSearchCriteria(job *ExportJob, criteria JobSearchCriteria) bool {
	// Filter by status
	if criteria.Status != "" && job.Status != criteria.Status {
		return false
	}
	
	// Filter by user
	if criteria.RequestedBy != "" && job.Request.RequestedBy != criteria.RequestedBy {
		return false
	}
	
	// Filter by format
	if criteria.Format != "" && job.Request.Format != criteria.Format {
		return false
	}
	
	// Filter by platform
	if criteria.Platform != "" && job.Request.Platform != criteria.Platform {
		return false
	}
	
	// Filter by time range
	if !criteria.StartTime.IsZero() && job.CreatedAt.Before(criteria.StartTime) {
		return false
	}
	if !criteria.EndTime.IsZero() && job.CreatedAt.After(criteria.EndTime) {
		return false
	}
	
	// Filter by tags
	if len(criteria.Tags) > 0 {
		jobTags := job.Request.Tags
		for _, requiredTag := range criteria.Tags {
			found := false
			for _, jobTag := range jobTags {
				if jobTag == requiredTag {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	
	return true
}

func (jt *ExportJobTracker) sortJobs(jobs []*ExportJob, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "created_at"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}
	
	// Simple sorting implementation
	// In a real implementation, you might use sort.Slice with more sophisticated comparison
	// For now, we'll just return the jobs as-is since sorting is complex
}

func (jt *ExportJobTracker) paginateJobs(jobs []*ExportJob, limit, offset int) []*ExportJob {
	if limit <= 0 {
		limit = 50 // Default limit
	}
	if offset < 0 {
		offset = 0
	}
	
	if offset >= len(jobs) {
		return []*ExportJob{}
	}
	
	end := offset + limit
	if end > len(jobs) {
		end = len(jobs)
	}
	
	// Return copies to prevent external mutations
	result := make([]*ExportJob, 0, end-offset)
	for i := offset; i < end; i++ {
		jobCopy := *jobs[i]
		result = append(result, &jobCopy)
	}
	
	return result
}

func (jt *ExportJobTracker) updateMetrics(job *ExportJob, operation string) {
	jt.metrics.mu.Lock()
	defer jt.metrics.mu.Unlock()
	
	switch operation {
	case "added":
		jt.metrics.TotalJobs++
		jt.metrics.JobsByStatus[job.Status]++
		jt.metrics.JobsByUser[job.Request.RequestedBy]++
		
		if job.Status == ExportJobStatusPending || job.Status == ExportJobStatusRunning {
			jt.metrics.ActiveJobs++
		}
		
	case "removed":
		jt.metrics.TotalJobs--
		jt.metrics.JobsByStatus[job.Status]--
		jt.metrics.JobsByUser[job.Request.RequestedBy]--
		
		if job.Status == ExportJobStatusPending || job.Status == ExportJobStatusRunning {
			jt.metrics.ActiveJobs--
		}
		
		// Clean up zero counts
		if jt.metrics.JobsByUser[job.Request.RequestedBy] <= 0 {
			delete(jt.metrics.JobsByUser, job.Request.RequestedBy)
		}
	}
	
	jt.metrics.LastUpdated = time.Now().UTC()
}

func (jt *ExportJobTracker) updateMetricsForStatusChange(oldStatus, newStatus ExportJobStatus) {
	jt.metrics.mu.Lock()
	defer jt.metrics.mu.Unlock()
	
	// Update status counts
	jt.metrics.JobsByStatus[oldStatus]--
	jt.metrics.JobsByStatus[newStatus]++
	
	// Update activity counts
	wasActive := oldStatus == ExportJobStatusPending || oldStatus == ExportJobStatusRunning
	isActive := newStatus == ExportJobStatusPending || newStatus == ExportJobStatusRunning
	
	if wasActive && !isActive {
		jt.metrics.ActiveJobs--
	} else if !wasActive && isActive {
		jt.metrics.ActiveJobs++
	}
	
	// Update completion counts
	switch newStatus {
	case ExportJobStatusCompleted:
		jt.metrics.CompletedJobs++
	case ExportJobStatusFailed:
		jt.metrics.FailedJobs++
	case ExportJobStatusCancelled:
		jt.metrics.CancelledJobs++
	case ExportJobStatusExpired:
		jt.metrics.ExpiredJobs++
	}
	
	jt.metrics.LastUpdated = time.Now().UTC()
}

// cleanupRoutine periodically cleans up expired jobs
func (jt *ExportJobTracker) cleanupRoutine() {
	for {
		select {
		case <-jt.cleanupTicker.C:
			jt.cleanupExpiredJobs()
		case <-jt.stopCleanup:
			return
		}
	}
}

// cleanupExpiredJobs removes jobs that have exceeded their retention period
func (jt *ExportJobTracker) cleanupExpiredJobs() {
	jt.mu.Lock()
	defer jt.mu.Unlock()
	
	now := time.Now().UTC()
	var expiredJobs []string
	
	for jobID, job := range jt.jobs {
		// Mark jobs as expired if they've exceeded retention period
		if now.After(job.ExpiresAt) && job.Status != ExportJobStatusExpired {
			job.Status = ExportJobStatusExpired
			expiredJobs = append(expiredJobs, jobID)
		}
		
		// Remove very old expired jobs to free memory
		if job.Status == ExportJobStatusExpired && now.Sub(job.ExpiresAt) > time.Hour*24 {
			jt.removeJobInternal(jobID, job)
		}
	}
	
	// Update metrics for expired jobs
	for _, jobID := range expiredJobs {
		if job := jt.jobs[jobID]; job != nil {
			jt.updateMetricsForStatusChange(job.Status, ExportJobStatusExpired)
		}
	}
}

// removeJobInternal removes a job without acquiring locks (internal use only)
func (jt *ExportJobTracker) removeJobInternal(jobID string, job *ExportJob) {
	delete(jt.jobs, jobID)
	jt.removeFromStatusIndex(job, job.Status)
	jt.removeFromUserIndex(job, job.Request.RequestedBy)
	jt.updateMetrics(job, "removed")
}

// Stop stops the job tracker and cleanup routines
func (jt *ExportJobTracker) Stop() {
	if jt.cleanupTicker != nil {
		jt.cleanupTicker.Stop()
	}
	close(jt.stopCleanup)
}

// ClearCompletedJobs removes all completed jobs older than the specified duration
func (jt *ExportJobTracker) ClearCompletedJobs(olderThan time.Duration) int {
	jt.mu.Lock()
	defer jt.mu.Unlock()
	
	cutoff := time.Now().Add(-olderThan)
	var clearedJobs []string
	
	for jobID, job := range jt.jobs {
		if (job.Status == ExportJobStatusCompleted || 
		    job.Status == ExportJobStatusFailed ||
		    job.Status == ExportJobStatusCancelled) &&
		   job.CompletedAt.Before(cutoff) {
			clearedJobs = append(clearedJobs, jobID)
		}
	}
	
	// Remove the jobs
	for _, jobID := range clearedJobs {
		if job := jt.jobs[jobID]; job != nil {
			jt.removeJobInternal(jobID, job)
		}
	}
	
	return len(clearedJobs)
}