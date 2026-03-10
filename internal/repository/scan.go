package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brandon/bugscanner/internal/database"
)

type ScanRepo struct {
	pool *pgxpool.Pool
}

func NewScanRepo(pool *pgxpool.Pool) *ScanRepo {
	return &ScanRepo{pool: pool}
}

func (r *ScanRepo) Create(ctx context.Context, target string, scopeIn, scopeOut []string, config json.RawMessage) (*database.Scan, error) {
	if config == nil {
		config = json.RawMessage("{}")
	}

	scan := &database.Scan{
		ScopeIn:  scopeIn,
		ScopeOut: scopeOut,
		Config:   config,
	}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO scans (target, scope_in, scope_out, config)
		VALUES ($1, $2, $3, $4)
		RETURNING id, status, target, created_at, updated_at
	`, target, scopeIn, scopeOut, config).Scan(
		&scan.ID, &scan.Status, &scan.Target, &scan.CreatedAt, &scan.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create scan: %w", err)
	}
	return scan, nil
}

func (r *ScanRepo) GetByID(ctx context.Context, id string) (*database.Scan, error) {
	scan := &database.Scan{}
	var scopeIn, scopeOut []string
	err := r.pool.QueryRow(ctx, `
		SELECT id, status, target, scope_in, scope_out, config, started_at, completed_at, created_at, updated_at
		FROM scans WHERE id = $1
	`, id).Scan(
		&scan.ID, &scan.Status, &scan.Target, &scopeIn, &scopeOut,
		&scan.Config, &scan.StartedAt, &scan.CompletedAt, &scan.CreatedAt, &scan.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("scan not found: %s", id)
		}
		return nil, fmt.Errorf("get scan: %w", err)
	}
	scan.ScopeIn = scopeIn
	scan.ScopeOut = scopeOut
	return scan, nil
}

func (r *ScanRepo) UpdateStatus(ctx context.Context, id string, status database.ScanStatus) error {
	now := time.Now()
	var query string
	var args []interface{}

	switch status {
	case database.ScanStatusRunning:
		query = `UPDATE scans SET status = $1, started_at = $2, updated_at = $2 WHERE id = $3`
		args = []interface{}{status, now, id}
	case database.ScanStatusCompleted, database.ScanStatusFailed, database.ScanStatusCancelled:
		query = `UPDATE scans SET status = $1, completed_at = $2, updated_at = $2 WHERE id = $3`
		args = []interface{}{status, now, id}
	default:
		query = `UPDATE scans SET status = $1, updated_at = $2 WHERE id = $3`
		args = []interface{}{status, now, id}
	}

	_, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update scan status: %w", err)
	}
	return nil
}

func (r *ScanRepo) List(ctx context.Context, limit, offset int) ([]database.Scan, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, status, target, scope_in, scope_out, config, started_at, completed_at, created_at, updated_at
		FROM scans ORDER BY created_at DESC LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	var scans []database.Scan
	for rows.Next() {
		var s database.Scan
		var scopeIn, scopeOut []string
		if err := rows.Scan(&s.ID, &s.Status, &s.Target, &scopeIn, &scopeOut,
			&s.Config, &s.StartedAt, &s.CompletedAt, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		s.ScopeIn = scopeIn
		s.ScopeOut = scopeOut
		scans = append(scans, s)
	}
	return scans, nil
}

// CreateJob creates a scan job record for a pipeline stage.
func (r *ScanRepo) CreateJob(ctx context.Context, scanID, stage string) (*database.ScanJob, error) {
	job := &database.ScanJob{}
	// worker_id and error_message are nullable — scan into pointers
	var workerID, errorMessage *string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO scan_jobs (scan_id, stage)
		VALUES ($1, $2)
		RETURNING id, scan_id, stage, status, worker_id, input_count, output_count, error_message, started_at, completed_at, created_at
	`, scanID, stage).Scan(
		&job.ID, &job.ScanID, &job.Stage, &job.Status, &workerID,
		&job.InputCount, &job.OutputCount, &errorMessage,
		&job.StartedAt, &job.CompletedAt, &job.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create scan job: %w", err)
	}
	if workerID != nil {
		job.WorkerID = *workerID
	}
	if errorMessage != nil {
		job.ErrorMessage = *errorMessage
	}
	return job, nil
}

func (r *ScanRepo) UpdateJobStatus(ctx context.Context, jobID string, status database.ScanStatus, outputCount int, errMsg string) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx, `
		UPDATE scan_jobs
		SET status = $1, output_count = $2, error_message = $3,
			started_at = COALESCE(started_at, $4),
			completed_at = CASE WHEN $1 IN ('completed', 'failed') THEN $4 ELSE completed_at END
		WHERE id = $5
	`, status, outputCount, errMsg, now, jobID)
	if err != nil {
		return fmt.Errorf("update scan job: %w", err)
	}
	return nil
}

func (r *ScanRepo) GetJobsByScanID(ctx context.Context, scanID string) ([]database.ScanJob, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, scan_id, stage, status, worker_id, input_count, output_count, error_message, started_at, completed_at, created_at
		FROM scan_jobs WHERE scan_id = $1 ORDER BY created_at
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("get scan jobs: %w", err)
	}
	defer rows.Close()

	var jobs []database.ScanJob
	for rows.Next() {
		var j database.ScanJob
		var workerID, errorMessage *string
		if err := rows.Scan(&j.ID, &j.ScanID, &j.Stage, &j.Status, &workerID,
			&j.InputCount, &j.OutputCount, &errorMessage,
			&j.StartedAt, &j.CompletedAt, &j.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan job row: %w", err)
		}
		if workerID != nil {
			j.WorkerID = *workerID
		}
		if errorMessage != nil {
			j.ErrorMessage = *errorMessage
		}
		jobs = append(jobs, j)
	}
	return jobs, nil
}
