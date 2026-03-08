package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/brandon/bugscanner/internal/config"
)

// Limiter provides Redis-backed rate limiting using a sliding window algorithm.
type Limiter struct {
	client    *redis.Client
	globalRPS int
	perTool   map[string]int
	perTarget int
}

// New creates a new Redis-backed rate limiter.
func New(cfg config.RedisConfig, rateCfg config.RateLimitConfig) (*Limiter, error) {
	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}

	client := redis.NewClient(opts)
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}

	return &Limiter{
		client:    client,
		globalRPS: rateCfg.Global,
		perTool:   rateCfg.PerTool,
		perTarget: rateCfg.PerTarget,
	}, nil
}

// Allow checks if a request is allowed under the rate limit for the given key.
// Uses a sliding window log algorithm with Redis sorted sets.
func (l *Limiter) Allow(ctx context.Context, key string, limit int) (bool, error) {
	now := time.Now()
	windowStart := now.Add(-time.Second).UnixMicro()
	nowMicro := now.UnixMicro()
	redisKey := fmt.Sprintf("ratelimit:%s", key)

	pipe := l.client.Pipeline()

	// Remove old entries outside the window
	pipe.ZRemRangeByScore(ctx, redisKey, "-inf", fmt.Sprintf("%d", windowStart))

	// Count current entries in window
	countCmd := pipe.ZCard(ctx, redisKey)

	// Add current request
	pipe.ZAdd(ctx, redisKey, redis.Z{
		Score:  float64(nowMicro),
		Member: nowMicro,
	})

	// Set expiry on the key
	pipe.Expire(ctx, redisKey, 2*time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("rate limit check: %w", err)
	}

	count := countCmd.Val()
	return count < int64(limit), nil
}

// AllowTool checks rate limit for a specific tool.
func (l *Limiter) AllowTool(ctx context.Context, toolName string) (bool, error) {
	limit, ok := l.perTool[toolName]
	if !ok {
		limit = l.globalRPS
	}
	return l.Allow(ctx, "tool:"+toolName, limit)
}

// AllowTarget checks rate limit for a specific target domain.
func (l *Limiter) AllowTarget(ctx context.Context, target string) (bool, error) {
	return l.Allow(ctx, "target:"+target, l.perTarget)
}

// Wait blocks until the rate limit allows a request, polling at short intervals.
func (l *Limiter) Wait(ctx context.Context, key string, limit int) error {
	for {
		allowed, err := l.Allow(ctx, key, limit)
		if err != nil {
			return err
		}
		if allowed {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
			// retry
		}
	}
}

// WaitTool blocks until the tool-specific rate limit allows a request.
func (l *Limiter) WaitTool(ctx context.Context, toolName string) error {
	limit, ok := l.perTool[toolName]
	if !ok {
		limit = l.globalRPS
	}
	return l.Wait(ctx, "tool:"+toolName, limit)
}

func (l *Limiter) Close() error {
	return l.client.Close()
}
