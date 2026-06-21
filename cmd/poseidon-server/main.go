// Command poseidon-server is a production-grade, 12-factor HTTP/2 server binary
// built on the Poseidon server, conn, and middleware packages.
//
// Configuration follows the 12-factor convention: every knob is read from a
// POSEIDON_-prefixed environment variable, with an optional command-line flag
// override. Secure-by-default values are applied when a knob is unset, and the
// resolved configuration is validated before the server starts.
//
// Build with version metadata via the Makefile `build` target, which injects
// -ldflags "-X main.version=… -X main.commit=… -X main.date=…".
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/lodgvideon/poseidon-http-server/conn"
	"github.com/lodgvideon/poseidon-http-server/middleware"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// Version metadata, overridden at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// defaults — secure-by-default values applied when a knob is unset. These mirror
// the underlying package defaults (server.defaultIdleTimeout = 120s,
// conn.defaultHandshakeTimeout = 10s, server.defaultMaxRequestBodyBytes = 10 MiB).
const (
	defaultAddr             = ":8080"
	defaultIdleTimeout      = 120 * time.Second
	defaultShutdownTimeout  = 30 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
	defaultMaxBodyBytes     = 10 << 20 // 10 MiB
)

// Config is the fully resolved, validated server configuration.
type Config struct {
	Addr             string
	IdleTimeout      time.Duration // <0 => disabled (keep-alive forever)
	ShutdownTimeout  time.Duration // graceful drain budget; must be >= 0
	HandshakeTimeout time.Duration // <0 => disabled
	MaxConns         int           // 0 => unlimited; must be >= 0
	MaxBodyBytes     int64         // request body cap in bytes; must be >= 0
	MaxRapidResets   int           // <0 => mitigation disabled; 0 => package default
	TLSCert          string
	TLSKey           string
	H2C              bool
	EnablePprof      bool
}

// TLSEnabled reports whether TLS serving is configured (both cert and key set).
func (c Config) TLSEnabled() bool { return c.TLSCert != "" && c.TLSKey != "" }

// loadEnvConfig reads every knob from the environment (or its secure default),
// returning the resolved-but-not-yet-flag-overridden Config. Split out from
// loadConfig to keep each function focused and within length limits.
func loadEnvConfig(getenv func(string) string) (Config, error) {
	idle, err := envDuration(getenv, "POSEIDON_IDLE_TIMEOUT", defaultIdleTimeout)
	if err != nil {
		return Config{}, err
	}
	shutdown, err := envDuration(getenv, "POSEIDON_SHUTDOWN_TIMEOUT", defaultShutdownTimeout)
	if err != nil {
		return Config{}, err
	}
	handshake, err := envDuration(getenv, "POSEIDON_HANDSHAKE_TIMEOUT", defaultHandshakeTimeout)
	if err != nil {
		return Config{}, err
	}
	maxConns, err := envInt(getenv, "POSEIDON_MAX_CONNS", 0)
	if err != nil {
		return Config{}, err
	}
	maxBody, err := envInt64(getenv, "POSEIDON_MAX_BODY_BYTES", defaultMaxBodyBytes)
	if err != nil {
		return Config{}, err
	}
	maxRapidResets, err := envInt(getenv, "POSEIDON_MAX_RAPID_RESETS", 0)
	if err != nil {
		return Config{}, err
	}
	h2c, err := envBool(getenv, "POSEIDON_H2C", false)
	if err != nil {
		return Config{}, err
	}
	pprof, err := envBool(getenv, "POSEIDON_ENABLE_PPROF", false)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Addr:             envString(getenv, "POSEIDON_ADDR", defaultAddr),
		IdleTimeout:      idle,
		ShutdownTimeout:  shutdown,
		HandshakeTimeout: handshake,
		MaxConns:         maxConns,
		MaxBodyBytes:     maxBody,
		MaxRapidResets:   maxRapidResets,
		TLSCert:          envString(getenv, "POSEIDON_TLS_CERT", ""),
		TLSKey:           envString(getenv, "POSEIDON_TLS_KEY", ""),
		H2C:              h2c,
		EnablePprof:      pprof,
	}, nil
}

// loadConfig builds a Config from environment variables (read via getenv) and
// command-line flags (args, excluding the program name). Flags override env
// vars, which override secure defaults. It is a pure function: it performs no
// I/O and mutates no global state, so it is fully unit-testable.
func loadConfig(getenv func(string) string, args []string) (Config, error) {
	// Seed config from env (or built-in defaults), so an unset flag preserves
	// the env value instead of clobbering it with a zero default.
	cfg, err := loadEnvConfig(getenv)
	if err != nil {
		return Config{}, err
	}

	fs := flag.NewFlagSet("poseidon-server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfg.Addr, "addr", cfg.Addr, "listen address (POSEIDON_ADDR)")
	fs.DurationVar(&cfg.IdleTimeout, "idle-timeout", cfg.IdleTimeout, "idle connection timeout; <0 disables (POSEIDON_IDLE_TIMEOUT)")
	fs.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", cfg.ShutdownTimeout, "graceful drain timeout (POSEIDON_SHUTDOWN_TIMEOUT)")
	fs.DurationVar(&cfg.HandshakeTimeout, "handshake-timeout", cfg.HandshakeTimeout, "HTTP/2 handshake timeout; <0 disables (POSEIDON_HANDSHAKE_TIMEOUT)")
	fs.IntVar(&cfg.MaxConns, "max-conns", cfg.MaxConns, "max concurrent connections; 0 unlimited (POSEIDON_MAX_CONNS)")
	fs.Int64Var(&cfg.MaxBodyBytes, "max-body-bytes", cfg.MaxBodyBytes, "max request body size in bytes (POSEIDON_MAX_BODY_BYTES)")
	fs.IntVar(&cfg.MaxRapidResets, "max-rapid-resets", cfg.MaxRapidResets, "rapid-reset (CVE-2023-44487) budget; <0 disables (POSEIDON_MAX_RAPID_RESETS)")
	fs.StringVar(&cfg.TLSCert, "tls-cert", cfg.TLSCert, "TLS certificate file (POSEIDON_TLS_CERT)")
	fs.StringVar(&cfg.TLSKey, "tls-key", cfg.TLSKey, "TLS key file (POSEIDON_TLS_KEY)")
	fs.BoolVar(&cfg.H2C, "h2c", cfg.H2C, "enable HTTP/2 cleartext (POSEIDON_H2C)")
	fs.BoolVar(&cfg.EnablePprof, "enable-pprof", cfg.EnablePprof, "expose /debug/pprof/ (POSEIDON_ENABLE_PPROF)")
	// The --version flag is parsed in main() before loadConfig; declare it here
	// too so it is accepted (and ignored) when present in args during tests.
	var showVersion bool
	fs.BoolVar(&showVersion, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validate enforces the invariants documented on Config.
func (c Config) validate() error {
	if c.Addr == "" {
		return errors.New("config: addr must not be empty")
	}
	// TLS cert and key must be provided together.
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("config: TLS cert and key must be set together")
	}
	if c.ShutdownTimeout < 0 {
		return errors.New("config: shutdown timeout must be non-negative")
	}
	// IdleTimeout and HandshakeTimeout treat negative as the documented
	// "disabled" sentinel, so they are intentionally not range-checked here.
	// HandshakeTimeout's only invalid case would be a NaN-style value, which
	// time.ParseDuration cannot produce.
	if c.MaxConns < 0 {
		return errors.New("config: max conns must be non-negative")
	}
	if c.MaxBodyBytes < 0 {
		return errors.New("config: max body bytes must be non-negative")
	}
	return nil
}

// --- env parsing helpers (each wraps parse errors with the var name) ---------

func envString(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(getenv func(string) string, key string, def time.Duration) (time.Duration, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: invalid duration %q: %w", key, v, err)
	}
	return d, nil
}

func envInt(getenv func(string) string, key string, def int) (int, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: invalid integer %q: %w", key, v, err)
	}
	return n, nil
}

func envInt64(getenv func(string) string, key string, def int64) (int64, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s: invalid integer %q: %w", key, v, err)
	}
	return n, nil
}

func envBool(getenv func(string) string, key string, def bool) (bool, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("config: %s: invalid boolean %q: %w", key, v, err)
	}
	return b, nil
}

func main() {
	// Fast-path: handle --version / -version before anything else so it works
	// regardless of the rest of the configuration.
	for _, a := range os.Args[1:] {
		if a == "--version" || a == "-version" {
			fmt.Printf("poseidon-server %s (commit %s, built %s)\n", version, commit, date)
			os.Exit(0)
		}
	}

	cfg, err := loadConfig(os.Getenv, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(cfg, logger); err != nil {
		logger.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

// buildOptions assembles the default handler (mux + middleware chain) and maps
// the validated Config into server.Options.
func buildOptions(cfg Config, logger *slog.Logger, health *server.HealthState) server.Options {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "poseidon-server %s ok\n", version)
	})

	// Health probes (liveness/readiness) — served via the native Handler.
	healthHandler := server.HealthHandler(health)
	mux.HandleFunc("GET "+server.LivenessPath, nativeAdapter(healthHandler))
	mux.HandleFunc("GET "+server.ReadinessPath, nativeAdapter(healthHandler))

	// Metrics.
	metrics := middleware.NewMetricsCollector()
	mux.HandleFunc("GET /metrics", nativeAdapter(metrics.MetricsHandler()))

	// pprof — opt-in only.
	if cfg.EnablePprof {
		logger.Warn("pprof enabled: /debug/pprof/ exposes runtime internals; restrict access")
		mux.Handle("/debug/pprof/", server.ToHTTPHandler(server.PprofHandler()))
	}

	// Middleware chain (onion order, outermost first):
	// Recovery → RequestID → StructuredAccessLog → SecurityHeaders → Metrics.
	secCfg := middleware.DefaultSecurityHeadersConfig()
	if !cfg.TLSEnabled() {
		// HSTS is meaningless over plaintext/h2c; drop it.
		secCfg.HSTSMaxAge = 0
	}
	mw := []server.Middleware{
		middleware.Recovery(slogPrintf{logger}),
		middleware.RequestID(),
		middleware.StructuredAccessLog(logger),
		middleware.SecurityHeaders(secCfg),
		metrics.Metrics(),
	}

	return server.Options{
		Addr:                     cfg.Addr,
		HTTPHandler:              mux,
		Middleware:               mw,
		MaxConcurrentConnections: cfg.MaxConns,
		IdleTimeout:              cfg.IdleTimeout,
		MaxRequestBodyBytes:      cfg.MaxBodyBytes,
		GracefulShutdownTimeout:  cfg.ShutdownTimeout,
		H2C:                      cfg.H2C,
		Logger:                   slogPrintf{logger},
		OnDrainStart:             health.SetNotReady,
		ConnOpts: conn.ServerConnOptions{
			HandshakeTimeout: cfg.HandshakeTimeout,
			MaxRapidResets:   cfg.MaxRapidResets,
		},
	}
}

// run wires the configuration into a server.Server and blocks until a signal
// triggers graceful shutdown. It returns a non-nil error on fatal startup or
// serve failure.
func run(cfg Config, logger *slog.Logger) error {
	health := server.NewHealthState()
	opts := buildOptions(cfg, logger, health)

	srv, err := server.NewServer(opts)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		if cfg.TLSEnabled() {
			logger.Info("serving HTTPS (HTTP/2 over TLS)", "addr", cfg.Addr, "version", version)
			serveErr <- srv.ListenAndServeTLS(ctx, cfg.TLSCert, cfg.TLSKey)
			return
		}
		mode := "http/2 (prior knowledge)"
		if cfg.H2C {
			mode = "h2c (cleartext + upgrade)"
		}
		logger.Info("serving plaintext", "addr", cfg.Addr, "mode", mode, "version", version)
		serveErr <- srv.ListenAndServe(ctx)
	}()

	select {
	case err := <-serveErr:
		// Serve returned before a signal — a startup/bind failure.
		if err != nil && !errors.Is(err, server.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		stop() // restore default signal handling for a second Ctrl-C
		logger.Info("shutdown signal received; draining", "timeout", cfg.ShutdownTimeout)
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(drainCtx); err != nil && !errors.Is(err, server.ErrServerClosed) {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("shutdown complete")
	return nil
}

// nativeAdapter bridges a native server.Handler into an http.HandlerFunc.
func nativeAdapter(h server.Handler) http.HandlerFunc {
	return server.ToHTTPHandler(h).ServeHTTP
}

// slogPrintf adapts a *slog.Logger to the Printf-style Logger interface used by
// server.Options.Logger and middleware.Recovery.
type slogPrintf struct{ l *slog.Logger }

func (s slogPrintf) Printf(format string, args ...interface{}) {
	s.l.Info(fmt.Sprintf(format, args...))
}
