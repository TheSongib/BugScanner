package logging

import (
	"context"
	"log/slog"
	"os"
	"time"

	// Embed IANA timezone database into the binary so time.LoadLocation
	// works in minimal containers (Alpine) without tzdata installed.
	_ "time/tzdata"
)

// easternHandler wraps a slog.Handler to emit timestamps in US Eastern time.
type easternHandler struct {
	inner slog.Handler
	loc   *time.Location
}

func (h *easternHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *easternHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Time = r.Time.In(h.loc)
	return h.inner.Handle(ctx, r)
}

func (h *easternHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &easternHandler{inner: h.inner.WithAttrs(attrs), loc: h.loc}
}

func (h *easternHandler) WithGroup(name string) slog.Handler {
	return &easternHandler{inner: h.inner.WithGroup(name), loc: h.loc}
}

// Setup initializes the default slog logger with JSON output in US Eastern time.
func Setup() {
	eastern, err := time.LoadLocation("America/New_York")
	if err != nil {
		// Fallback: use fixed offset UTC-5 (won't handle DST)
		eastern = time.FixedZone("EST", -5*60*60)
	}

	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(&easternHandler{inner: jsonHandler, loc: eastern})
	slog.SetDefault(logger)
}
