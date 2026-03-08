package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brandon/bugscanner/internal/database"
)

type TechnologyRepo struct {
	pool *pgxpool.Pool
}

func NewTechnologyRepo(pool *pgxpool.Pool) *TechnologyRepo {
	return &TechnologyRepo{pool: pool}
}

func (r *TechnologyRepo) Create(ctx context.Context, httpServiceID, name, version, category string) (*database.Technology, error) {
	t := &database.Technology{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO technologies (http_service_id, name, version, category)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (http_service_id, name) DO UPDATE SET version = EXCLUDED.version, category = EXCLUDED.category
		RETURNING id, http_service_id, name, version, category, created_at
	`, httpServiceID, name, version, category).Scan(&t.ID, &t.HTTPServiceID, &t.Name, &t.Version, &t.Category, &t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create technology: %w", err)
	}
	return t, nil
}

func (r *TechnologyRepo) GetByHTTPServiceID(ctx context.Context, httpServiceID string) ([]database.Technology, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, http_service_id, name, version, category, created_at
		FROM technologies WHERE http_service_id = $1 ORDER BY name
	`, httpServiceID)
	if err != nil {
		return nil, fmt.Errorf("get technologies: %w", err)
	}
	defer rows.Close()

	var techs []database.Technology
	for rows.Next() {
		var t database.Technology
		if err := rows.Scan(&t.ID, &t.HTTPServiceID, &t.Name, &t.Version, &t.Category, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan tech row: %w", err)
		}
		techs = append(techs, t)
	}
	return techs, nil
}

func (r *TechnologyRepo) GetByScanID(ctx context.Context, scanID string) ([]database.Technology, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT t.id, t.http_service_id, t.name, t.version, t.category, t.created_at
		FROM technologies t
		JOIN http_services hs ON hs.id = t.http_service_id
		JOIN subdomains s ON s.id = hs.subdomain_id
		JOIN domains d ON d.id = s.domain_id
		WHERE d.scan_id = $1
		ORDER BY t.name
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("get technologies by scan: %w", err)
	}
	defer rows.Close()

	var techs []database.Technology
	for rows.Next() {
		var t database.Technology
		if err := rows.Scan(&t.ID, &t.HTTPServiceID, &t.Name, &t.Version, &t.Category, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan tech row: %w", err)
		}
		techs = append(techs, t)
	}
	return techs, nil
}
