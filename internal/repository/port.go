package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brandon/bugscanner/internal/database"
)

type PortRepo struct {
	pool *pgxpool.Pool
}

func NewPortRepo(pool *pgxpool.Pool) *PortRepo {
	return &PortRepo{pool: pool}
}

func (r *PortRepo) Upsert(ctx context.Context, ipID string, port int, protocol, service string) (*database.Port, error) {
	p := &database.Port{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO ports (ip_id, port, protocol, service)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (ip_id, port, protocol) DO UPDATE SET service = EXCLUDED.service
		RETURNING id, ip_id, port, protocol, service, created_at
	`, ipID, port, protocol, service).Scan(&p.ID, &p.IPID, &p.Port, &p.Protocol, &p.Service, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("upsert port: %w", err)
	}
	return p, nil
}

func (r *PortRepo) GetByIPID(ctx context.Context, ipID string) ([]database.Port, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, ip_id, port, protocol, service, created_at
		FROM ports WHERE ip_id = $1 ORDER BY port
	`, ipID)
	if err != nil {
		return nil, fmt.Errorf("get ports: %w", err)
	}
	defer rows.Close()

	var ports []database.Port
	for rows.Next() {
		var p database.Port
		if err := rows.Scan(&p.ID, &p.IPID, &p.Port, &p.Protocol, &p.Service, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan port row: %w", err)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

func (r *PortRepo) BulkUpsert(ctx context.Context, ports []struct {
	IPID     string
	Port     int
	Protocol string
	Service  string
}) (int, error) {
	if len(ports) == 0 {
		return 0, nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	count := 0
	for _, p := range ports {
		_, err := tx.Exec(ctx, `
			INSERT INTO ports (ip_id, port, protocol, service)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (ip_id, port, protocol) DO NOTHING
		`, p.IPID, p.Port, p.Protocol, p.Service)
		if err != nil {
			return 0, fmt.Errorf("insert port: %w", err)
		}
		count++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return count, nil
}
