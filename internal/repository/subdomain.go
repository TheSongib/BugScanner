package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brandon/bugscanner/internal/database"
)

type SubdomainRepo struct {
	pool *pgxpool.Pool
}

func NewSubdomainRepo(pool *pgxpool.Pool) *SubdomainRepo {
	return &SubdomainRepo{pool: pool}
}

func (r *SubdomainRepo) Create(ctx context.Context, domainID, name, source string) (*database.Subdomain, error) {
	s := &database.Subdomain{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO subdomains (domain_id, name, source)
		VALUES ($1, $2, $3)
		ON CONFLICT (domain_id, name) DO UPDATE SET source = EXCLUDED.source
		RETURNING id, domain_id, name, source, is_alive, created_at
	`, domainID, name, source).Scan(&s.ID, &s.DomainID, &s.Name, &s.Source, &s.IsAlive, &s.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create subdomain: %w", err)
	}
	return s, nil
}

// BulkUpsert inserts multiple subdomains efficiently using a batch.
func (r *SubdomainRepo) BulkUpsert(ctx context.Context, domainID string, subdomains []struct {
	Name   string
	Source string
}) (int, error) {
	if len(subdomains) == 0 {
		return 0, nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	count := 0
	for _, sub := range subdomains {
		_, err := tx.Exec(ctx, `
			INSERT INTO subdomains (domain_id, name, source)
			VALUES ($1, $2, $3)
			ON CONFLICT (domain_id, name) DO NOTHING
		`, domainID, sub.Name, sub.Source)
		if err != nil {
			return 0, fmt.Errorf("insert subdomain %s: %w", sub.Name, err)
		}
		count++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return count, nil
}

func (r *SubdomainRepo) GetByDomainID(ctx context.Context, domainID string) ([]database.Subdomain, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, domain_id, name, source, is_alive, created_at
		FROM subdomains WHERE domain_id = $1 ORDER BY name
	`, domainID)
	if err != nil {
		return nil, fmt.Errorf("get subdomains: %w", err)
	}
	defer rows.Close()

	var subs []database.Subdomain
	for rows.Next() {
		var s database.Subdomain
		if err := rows.Scan(&s.ID, &s.DomainID, &s.Name, &s.Source, &s.IsAlive, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan subdomain row: %w", err)
		}
		subs = append(subs, s)
	}
	return subs, nil
}

func (r *SubdomainRepo) GetAliveByDomainID(ctx context.Context, domainID string) ([]database.Subdomain, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, domain_id, name, source, is_alive, created_at
		FROM subdomains WHERE domain_id = $1 AND is_alive = TRUE ORDER BY name
	`, domainID)
	if err != nil {
		return nil, fmt.Errorf("get alive subdomains: %w", err)
	}
	defer rows.Close()

	var subs []database.Subdomain
	for rows.Next() {
		var s database.Subdomain
		if err := rows.Scan(&s.ID, &s.DomainID, &s.Name, &s.Source, &s.IsAlive, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan subdomain row: %w", err)
		}
		subs = append(subs, s)
	}
	return subs, nil
}

func (r *SubdomainRepo) MarkAlive(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `UPDATE subdomains SET is_alive = TRUE WHERE id = $1`, id)
	return err
}

func (r *SubdomainRepo) GetByName(ctx context.Context, domainID, name string) (*database.Subdomain, error) {
	s := &database.Subdomain{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, domain_id, name, source, is_alive, created_at
		FROM subdomains WHERE domain_id = $1 AND name = $2
	`, domainID, name).Scan(&s.ID, &s.DomainID, &s.Name, &s.Source, &s.IsAlive, &s.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get subdomain by name: %w", err)
	}
	return s, nil
}
