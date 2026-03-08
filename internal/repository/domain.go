package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brandon/bugscanner/internal/database"
)

type DomainRepo struct {
	pool *pgxpool.Pool
}

func NewDomainRepo(pool *pgxpool.Pool) *DomainRepo {
	return &DomainRepo{pool: pool}
}

func (r *DomainRepo) Create(ctx context.Context, scanID, name string) (*database.Domain, error) {
	d := &database.Domain{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO domains (scan_id, name)
		VALUES ($1, $2)
		ON CONFLICT (scan_id, name) DO UPDATE SET name = EXCLUDED.name
		RETURNING id, scan_id, name, created_at
	`, scanID, name).Scan(&d.ID, &d.ScanID, &d.Name, &d.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create domain: %w", err)
	}
	return d, nil
}

func (r *DomainRepo) GetByID(ctx context.Context, id string) (*database.Domain, error) {
	d := &database.Domain{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, scan_id, name, created_at FROM domains WHERE id = $1
	`, id).Scan(&d.ID, &d.ScanID, &d.Name, &d.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}
	return d, nil
}

func (r *DomainRepo) GetByName(ctx context.Context, scanID, name string) (*database.Domain, error) {
	d := &database.Domain{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, scan_id, name, created_at FROM domains WHERE scan_id = $1 AND name = $2
	`, scanID, name).Scan(&d.ID, &d.ScanID, &d.Name, &d.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get domain by name: %w", err)
	}
	return d, nil
}

func (r *DomainRepo) ListByScanID(ctx context.Context, scanID string) ([]database.Domain, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, scan_id, name, created_at FROM domains WHERE scan_id = $1 ORDER BY name
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	defer rows.Close()

	var domains []database.Domain
	for rows.Next() {
		var d database.Domain
		if err := rows.Scan(&d.ID, &d.ScanID, &d.Name, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan domain row: %w", err)
		}
		domains = append(domains, d)
	}
	return domains, nil
}
