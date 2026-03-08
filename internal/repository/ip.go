package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brandon/bugscanner/internal/database"
)

type IPRepo struct {
	pool *pgxpool.Pool
}

func NewIPRepo(pool *pgxpool.Pool) *IPRepo {
	return &IPRepo{pool: pool}
}

func (r *IPRepo) Upsert(ctx context.Context, address string, isCDN bool, cdnName string) (*database.IP, error) {
	ip := &database.IP{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO ips (address, is_cdn, cdn_name)
		VALUES ($1::inet, $2, $3)
		ON CONFLICT (address) DO UPDATE SET is_cdn = EXCLUDED.is_cdn, cdn_name = EXCLUDED.cdn_name
		RETURNING id, address, is_cdn, cdn_name, created_at
	`, address, isCDN, cdnName).Scan(&ip.ID, &ip.Address, &ip.IsCDN, &ip.CDNName, &ip.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("upsert ip: %w", err)
	}
	return ip, nil
}

func (r *IPRepo) LinkSubdomain(ctx context.Context, subdomainID, ipID string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO subdomain_ips (subdomain_id, ip_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, subdomainID, ipID)
	if err != nil {
		return fmt.Errorf("link subdomain to ip: %w", err)
	}
	return nil
}

func (r *IPRepo) GetBySubdomainID(ctx context.Context, subdomainID string) ([]database.IP, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT i.id, i.address, i.is_cdn, i.cdn_name, i.created_at
		FROM ips i
		JOIN subdomain_ips si ON si.ip_id = i.id
		WHERE si.subdomain_id = $1
	`, subdomainID)
	if err != nil {
		return nil, fmt.Errorf("get ips by subdomain: %w", err)
	}
	defer rows.Close()

	var ips []database.IP
	for rows.Next() {
		var ip database.IP
		if err := rows.Scan(&ip.ID, &ip.Address, &ip.IsCDN, &ip.CDNName, &ip.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ip row: %w", err)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}
