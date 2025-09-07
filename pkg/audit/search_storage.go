// Package audit provides enhanced storage with full-text search capabilities
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"log"
)

// SearchStorageExtension adds full-text search capabilities to existing audit storage
type SearchStorageExtension struct {
	db        *sql.DB
	tableName string
}

// NewSearchStorageExtension creates a new search storage extension
func NewSearchStorageExtension(db *sql.DB, tableName string) (*SearchStorageExtension, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}
	if tableName == "" {
		tableName = "audit_events"
	}

	ext := &SearchStorageExtension{
		db:        db,
		tableName: tableName,
	}

	// Initialize full-text search capabilities
	if err := ext.initializeSearchCapabilities(); err != nil {
		return nil, fmt.Errorf("failed to initialize search capabilities: %w", err)
	}

	return ext, nil
}

// initializeSearchCapabilities adds full-text search support to existing audit table
func (s *SearchStorageExtension) initializeSearchCapabilities() error {
	// Add search vector column if it doesn't exist
	alterTableSQL := fmt.Sprintf(`
		ALTER TABLE %s 
		ADD COLUMN IF NOT EXISTS search_vector tsvector,
		ADD COLUMN IF NOT EXISTS user_context JSONB,
		ADD COLUMN IF NOT EXISTS cluster_context JSONB,
		ADD COLUMN IF NOT EXISTS command_context JSONB;
	`, s.tableName)

	if _, err := s.db.Exec(alterTableSQL); err != nil {
		return fmt.Errorf("failed to add search columns: %w", err)
	}

	// Create or update the search vector update function
	createFunctionSQL := fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION update_audit_search_vector()
		RETURNS TRIGGER AS $$
		BEGIN
			-- Build user_context JSON from individual columns
			NEW.user_context := jsonb_build_object(
				'user_id', COALESCE(NEW.user_id, ''),
				'email', COALESCE(NEW.user_email, ''),
				'name', COALESCE(NEW.user_name, ''),
				'session_id', COALESCE(NEW.session_id, ''),
				'groups', COALESCE(NEW.user_groups, ARRAY[]::TEXT[]),
				'provider', COALESCE(NEW.provider, ''),
				'ip_address', COALESCE(NEW.ip_address::TEXT, ''),
				'user_agent', COALESCE(NEW.user_agent, '')
			);

			-- Build cluster_context JSON from individual columns
			NEW.cluster_context := jsonb_build_object(
				'cluster_name', COALESCE(NEW.cluster_name, ''),
				'namespace', COALESCE(NEW.namespace, ''),
				'resource_type', COALESCE(NEW.resource_type, ''),
				'resource_name', COALESCE(NEW.resource_name, ''),
				'kubectl_context', COALESCE(NEW.kubectl_context, '')
			);

			-- Build command_context JSON from individual columns
			NEW.command_context := jsonb_build_object(
				'natural_language_input', COALESCE(NEW.natural_language_input, ''),
				'generated_command', COALESCE(NEW.generated_command, ''),
				'command_args', COALESCE(NEW.command_args, ARRAY[]::TEXT[]),
				'risk_level', COALESCE(NEW.risk_level, ''),
				'execution_status', COALESCE(NEW.execution_status, ''),
				'execution_result', COALESCE(NEW.execution_result, ''),
				'execution_error', COALESCE(NEW.execution_error, ''),
				'execution_duration', COALESCE(NEW.execution_duration, 0)
			);

			-- Update the search vector with all searchable text
			NEW.search_vector := to_tsvector('english', 
				COALESCE(NEW.message, '') || ' ' ||
				COALESCE(NEW.user_id, '') || ' ' ||
				COALESCE(NEW.user_email, '') || ' ' ||
				COALESCE(NEW.user_name, '') || ' ' ||
				COALESCE(NEW.cluster_name, '') || ' ' ||
				COALESCE(NEW.namespace, '') || ' ' ||
				COALESCE(NEW.resource_type, '') || ' ' ||
				COALESCE(NEW.resource_name, '') || ' ' ||
				COALESCE(NEW.natural_language_input, '') || ' ' ||
				COALESCE(NEW.generated_command, '') || ' ' ||
				COALESCE(NEW.execution_result, '') || ' ' ||
				COALESCE(NEW.execution_error, '') || ' ' ||
				COALESCE(NEW.service_name, '') || ' ' ||
				COALESCE(NEW.correlation_id, '') || ' ' ||
				COALESCE(NEW.trace_id, '')
			);

			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
	`)

	if _, err := s.db.Exec(createFunctionSQL); err != nil {
		return fmt.Errorf("failed to create search vector function: %w", err)
	}

	// Create trigger to automatically update search vector
	createTriggerSQL := fmt.Sprintf(`
		DROP TRIGGER IF EXISTS update_audit_search_vector_trigger ON %s;
		CREATE TRIGGER update_audit_search_vector_trigger
			BEFORE INSERT OR UPDATE ON %s
			FOR EACH ROW EXECUTE FUNCTION update_audit_search_vector();
	`, s.tableName, s.tableName)

	if _, err := s.db.Exec(createTriggerSQL); err != nil {
		return fmt.Errorf("failed to create search vector trigger: %w", err)
	}

	// Create full-text search indexes
	searchIndexes := []string{
		// GIN index for full-text search vector
		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_search_vector_idx 
			ON %s USING gin(search_vector)`, s.tableName, s.tableName),
		
		// GIN indexes for JSON context fields
		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_user_context_gin_idx 
			ON %s USING gin(user_context)`, s.tableName, s.tableName),
		
		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_cluster_context_gin_idx 
			ON %s USING gin(cluster_context)`, s.tableName, s.tableName),
		
		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_command_context_gin_idx 
			ON %s USING gin(command_context)`, s.tableName, s.tableName),

		// Optimized composite indexes for common search patterns
		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_timestamp_user_idx 
			ON %s (timestamp DESC, user_id)`, s.tableName, s.tableName),

		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_event_type_severity_idx 
			ON %s (event_type, severity, timestamp DESC)`, s.tableName, s.tableName),

		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_cluster_namespace_idx 
			ON %s (cluster_name, namespace, timestamp DESC)`, s.tableName, s.tableName),

		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_correlation_trace_idx 
			ON %s (correlation_id, trace_id)`, s.tableName, s.tableName),

		// Performance indexes for large dataset queries
		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_service_timestamp_idx 
			ON %s (service_name, timestamp DESC)`, s.tableName, s.tableName),

		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_user_timestamp_idx 
			ON %s (user_id, timestamp DESC) WHERE user_id IS NOT NULL`, s.tableName, s.tableName),

		// Partial indexes for error and warning events (most queried)
		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_error_events_idx 
			ON %s (timestamp DESC, event_type) WHERE severity IN ('error', 'critical')`, s.tableName, s.tableName),

		// Index for command events with execution status
		fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS %s_command_execution_idx 
			ON %s (execution_status, timestamp DESC) 
			WHERE event_type IN ('command', 'command_execute', 'command_result')`, s.tableName, s.tableName),
	}

	for _, indexSQL := range searchIndexes {
		if _, err := s.db.Exec(indexSQL); err != nil {
			// Log warning but don't fail - indexes might already exist
			log.Printf("Warning: failed to create search index: %v", err)
		}
	}

	return nil
}

// UpdateExistingRecords updates existing audit records with search vectors
func (s *SearchStorageExtension) UpdateExistingRecords(ctx context.Context) error {
	// Update existing records to populate search vectors and JSON contexts
	updateSQL := fmt.Sprintf(`
		UPDATE %s SET
			user_context = jsonb_build_object(
				'user_id', COALESCE(user_id, ''),
				'email', COALESCE(user_email, ''),
				'name', COALESCE(user_name, ''),
				'session_id', COALESCE(session_id, ''),
				'groups', COALESCE(user_groups, ARRAY[]::TEXT[]),
				'provider', COALESCE(provider, ''),
				'ip_address', COALESCE(ip_address::TEXT, ''),
				'user_agent', COALESCE(user_agent, '')
			),
			cluster_context = jsonb_build_object(
				'cluster_name', COALESCE(cluster_name, ''),
				'namespace', COALESCE(namespace, ''),
				'resource_type', COALESCE(resource_type, ''),
				'resource_name', COALESCE(resource_name, ''),
				'kubectl_context', COALESCE(kubectl_context, '')
			),
			command_context = jsonb_build_object(
				'natural_language_input', COALESCE(natural_language_input, ''),
				'generated_command', COALESCE(generated_command, ''),
				'command_args', COALESCE(command_args, ARRAY[]::TEXT[]),
				'risk_level', COALESCE(risk_level, ''),
				'execution_status', COALESCE(execution_status, ''),
				'execution_result', COALESCE(execution_result, ''),
				'execution_error', COALESCE(execution_error, ''),
				'execution_duration', COALESCE(execution_duration, 0)
			),
			search_vector = to_tsvector('english', 
				COALESCE(message, '') || ' ' ||
				COALESCE(user_id, '') || ' ' ||
				COALESCE(user_email, '') || ' ' ||
				COALESCE(user_name, '') || ' ' ||
				COALESCE(cluster_name, '') || ' ' ||
				COALESCE(namespace, '') || ' ' ||
				COALESCE(resource_type, '') || ' ' ||
				COALESCE(resource_name, '') || ' ' ||
				COALESCE(natural_language_input, '') || ' ' ||
				COALESCE(generated_command, '') || ' ' ||
				COALESCE(execution_result, '') || ' ' ||
				COALESCE(execution_error, '') || ' ' ||
				COALESCE(service_name, '') || ' ' ||
				COALESCE(correlation_id, '') || ' ' ||
				COALESCE(trace_id, '')
			)
		WHERE search_vector IS NULL OR user_context IS NULL
	`, s.tableName)

	result, err := s.db.ExecContext(ctx, updateSQL)
	if err != nil {
		return fmt.Errorf("failed to update existing records with search vectors: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err == nil {
		log.Printf("Updated %d existing audit records with search capabilities", rowsAffected)
	}

	return nil
}

// OptimizeSearchPerformance runs PostgreSQL optimizations for search performance
func (s *SearchStorageExtension) OptimizeSearchPerformance(ctx context.Context) error {
	optimizations := []string{
		// Update table statistics for better query planning
		fmt.Sprintf("ANALYZE %s;", s.tableName),
		
		// Set GIN index fast update for better insert performance
		fmt.Sprintf(`ALTER INDEX %s_search_vector_idx SET (fastupdate = on);`, s.tableName),
		
		// Update PostgreSQL FTS configuration statistics
		"SELECT ts_stat('SELECT search_vector FROM audit_events') LIMIT 10;",
	}

	for _, sql := range optimizations {
		if _, err := s.db.ExecContext(ctx, sql); err != nil {
			log.Printf("Warning: optimization query failed: %v", err)
		}
	}

	return nil
}

// GetSearchStatistics returns statistics about search index usage and performance
func (s *SearchStorageExtension) GetSearchStatistics(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get index usage statistics
	indexStatsSQL := `
		SELECT 
			schemaname, tablename, indexname, 
			idx_tup_read, idx_tup_fetch,
			idx_scan
		FROM pg_stat_user_indexes 
		WHERE tablename = $1 
		AND indexname LIKE '%_search_%'
		ORDER BY idx_scan DESC
	`

	rows, err := s.db.QueryContext(ctx, indexStatsSQL, s.tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to get index statistics: %w", err)
	}
	defer rows.Close()

	var indexStats []map[string]interface{}
	for rows.Next() {
		var schemaName, tableName, indexName string
		var idxTupRead, idxTupFetch, idxScan int64

		if err := rows.Scan(&schemaName, &tableName, &indexName, &idxTupRead, &idxTupFetch, &idxScan); err != nil {
			return nil, fmt.Errorf("failed to scan index statistics: %w", err)
		}

		indexStats = append(indexStats, map[string]interface{}{
			"schema_name":      schemaName,
			"table_name":      tableName,
			"index_name":      indexName,
			"tuples_read":     idxTupRead,
			"tuples_fetched":  idxTupFetch,
			"scans":           idxScan,
		})
	}
	stats["index_usage"] = indexStats

	// Get table statistics
	tableStatsSQL := `
		SELECT 
			n_tup_ins, n_tup_upd, n_tup_del, n_live_tup, n_dead_tup,
			last_vacuum, last_autovacuum, last_analyze, last_autoanalyze
		FROM pg_stat_user_tables 
		WHERE relname = $1
	`

	var nTupIns, nTupUpd, nTupDel, nLiveTup, nDeadTup int64
	var lastVacuum, lastAutovacuum, lastAnalyze, lastAutoanalyze sql.NullTime

	err = s.db.QueryRowContext(ctx, tableStatsSQL, s.tableName).Scan(
		&nTupIns, &nTupUpd, &nTupDel, &nLiveTup, &nDeadTup,
		&lastVacuum, &lastAutovacuum, &lastAnalyze, &lastAutoanalyze,
	)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get table statistics: %w", err)
	}

	stats["table_statistics"] = map[string]interface{}{
		"inserts":           nTupIns,
		"updates":          nTupUpd,
		"deletes":          nTupDel,
		"live_tuples":      nLiveTup,
		"dead_tuples":      nDeadTup,
		"last_vacuum":      lastVacuum,
		"last_autovacuum":  lastAutovacuum,
		"last_analyze":     lastAnalyze,
		"last_autoanalyze": lastAutoanalyze,
	}

	// Get FTS dictionary statistics
	ftsStatsSQL := `
		SELECT word, nentry 
		FROM ts_stat('SELECT search_vector FROM audit_events') 
		ORDER BY nentry DESC 
		LIMIT 10
	`

	ftsRows, err := s.db.QueryContext(ctx, ftsStatsSQL)
	if err == nil {
		defer ftsRows.Close()
		var ftsStats []map[string]interface{}
		
		for ftsRows.Next() {
			var word string
			var nentry int
			if err := ftsRows.Scan(&word, &nentry); err == nil {
				ftsStats = append(ftsStats, map[string]interface{}{
					"word":  word,
					"count": nentry,
				})
			}
		}
		stats["fts_dictionary"] = ftsStats
	}

	return stats, nil
}

// ValidateSearchIndexes checks the health of search indexes
func (s *SearchStorageExtension) ValidateSearchIndexes(ctx context.Context) error {
	// Check if all required indexes exist and are valid
	checkIndexSQL := `
		SELECT indexname, indexdef 
		FROM pg_indexes 
		WHERE tablename = $1 
		AND indexname LIKE '%search%'
	`

	rows, err := s.db.QueryContext(ctx, checkIndexSQL, s.tableName)
	if err != nil {
		return fmt.Errorf("failed to check search indexes: %w", err)
	}
	defer rows.Close()

	var foundIndexes []string
	for rows.Next() {
		var indexName, indexDef string
		if err := rows.Scan(&indexName, &indexDef); err != nil {
			return fmt.Errorf("failed to scan index information: %w", err)
		}
		foundIndexes = append(foundIndexes, indexName)
	}

	// Check that the primary search vector index exists
	searchVectorIndexExists := false
	for _, indexName := range foundIndexes {
		if indexName == s.tableName+"_search_vector_idx" {
			searchVectorIndexExists = true
			break
		}
	}

	if !searchVectorIndexExists {
		return fmt.Errorf("search vector index does not exist - search functionality may be impaired")
	}

	log.Printf("Search index validation passed - found %d search-related indexes", len(foundIndexes))
	return nil
}