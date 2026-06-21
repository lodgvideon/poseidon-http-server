package main

import (
	"strings"
	"testing"
	"time"
)

// envMap returns a getenv func backed by a map, so loadConfig stays a pure
// function under test (no process environment mutation).
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := loadConfig(envMap(nil), nil)
	if err != nil {
		t.Fatalf("loadConfig() error = %v, want nil", err)
	}
	if cfg.Addr != ":8080" {
		t.Errorf("Addr = %q, want %q", cfg.Addr, ":8080")
	}
	if cfg.IdleTimeout != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want 120s", cfg.IdleTimeout)
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 30s", cfg.ShutdownTimeout)
	}
	if cfg.HandshakeTimeout != 10*time.Second {
		t.Errorf("HandshakeTimeout = %v, want 10s", cfg.HandshakeTimeout)
	}
	if cfg.MaxConns != 0 {
		t.Errorf("MaxConns = %d, want 0", cfg.MaxConns)
	}
	if cfg.MaxBodyBytes != 10<<20 {
		t.Errorf("MaxBodyBytes = %d, want %d", cfg.MaxBodyBytes, 10<<20)
	}
	if cfg.MaxRapidResets != 0 {
		t.Errorf("MaxRapidResets = %d, want 0", cfg.MaxRapidResets)
	}
	if cfg.H2C {
		t.Errorf("H2C = true, want false (secure default)")
	}
	if cfg.EnablePprof {
		t.Errorf("EnablePprof = true, want false (secure default)")
	}
	if cfg.TLSCert != "" || cfg.TLSKey != "" {
		t.Errorf("TLS cert/key = %q/%q, want empty", cfg.TLSCert, cfg.TLSKey)
	}
	if cfg.TLSEnabled() {
		t.Errorf("TLSEnabled() = true, want false")
	}
}

func TestLoadConfig_EnvOverrides(t *testing.T) {
	env := map[string]string{
		"POSEIDON_ADDR":              ":9090",
		"POSEIDON_IDLE_TIMEOUT":      "45s",
		"POSEIDON_SHUTDOWN_TIMEOUT":  "15s",
		"POSEIDON_HANDSHAKE_TIMEOUT": "5s",
		"POSEIDON_MAX_CONNS":         "1000",
		"POSEIDON_MAX_BODY_BYTES":    "1048576",
		"POSEIDON_MAX_RAPID_RESETS":  "200",
		"POSEIDON_H2C":               "true",
		"POSEIDON_ENABLE_PPROF":      "true",
		"POSEIDON_TLS_CERT":          "cert.pem",
		"POSEIDON_TLS_KEY":           "key.pem",
	}
	cfg, err := loadConfig(envMap(env), nil)
	if err != nil {
		t.Fatalf("loadConfig() error = %v, want nil", err)
	}
	if cfg.Addr != ":9090" {
		t.Errorf("Addr = %q, want :9090", cfg.Addr)
	}
	if cfg.IdleTimeout != 45*time.Second {
		t.Errorf("IdleTimeout = %v, want 45s", cfg.IdleTimeout)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 15s", cfg.ShutdownTimeout)
	}
	if cfg.HandshakeTimeout != 5*time.Second {
		t.Errorf("HandshakeTimeout = %v, want 5s", cfg.HandshakeTimeout)
	}
	if cfg.MaxConns != 1000 {
		t.Errorf("MaxConns = %d, want 1000", cfg.MaxConns)
	}
	if cfg.MaxBodyBytes != 1048576 {
		t.Errorf("MaxBodyBytes = %d, want 1048576", cfg.MaxBodyBytes)
	}
	if cfg.MaxRapidResets != 200 {
		t.Errorf("MaxRapidResets = %d, want 200", cfg.MaxRapidResets)
	}
	if !cfg.H2C {
		t.Errorf("H2C = false, want true")
	}
	if !cfg.EnablePprof {
		t.Errorf("EnablePprof = false, want true")
	}
	if cfg.TLSCert != "cert.pem" || cfg.TLSKey != "key.pem" {
		t.Errorf("TLS cert/key = %q/%q, want cert.pem/key.pem", cfg.TLSCert, cfg.TLSKey)
	}
	if !cfg.TLSEnabled() {
		t.Errorf("TLSEnabled() = false, want true")
	}
}

func TestLoadConfig_FlagOverridesEnv(t *testing.T) {
	env := map[string]string{
		"POSEIDON_ADDR":         ":9090",
		"POSEIDON_IDLE_TIMEOUT": "45s",
		"POSEIDON_ENABLE_PPROF": "false",
	}
	args := []string{
		"-addr", ":7000",
		"-idle-timeout", "90s",
		"-enable-pprof",
	}
	cfg, err := loadConfig(envMap(env), args)
	if err != nil {
		t.Fatalf("loadConfig() error = %v, want nil", err)
	}
	if cfg.Addr != ":7000" {
		t.Errorf("Addr = %q, want :7000 (flag over env)", cfg.Addr)
	}
	if cfg.IdleTimeout != 90*time.Second {
		t.Errorf("IdleTimeout = %v, want 90s (flag over env)", cfg.IdleTimeout)
	}
	if !cfg.EnablePprof {
		t.Errorf("EnablePprof = false, want true (flag over env)")
	}
}

func TestLoadConfig_FlagDefaultsToEnv(t *testing.T) {
	// When a flag is NOT passed, the env value must survive (flags must not
	// clobber env with their zero defaults).
	env := map[string]string{
		"POSEIDON_ADDR": ":9090",
	}
	cfg, err := loadConfig(envMap(env), []string{"-h2c"})
	if err != nil {
		t.Fatalf("loadConfig() error = %v, want nil", err)
	}
	if cfg.Addr != ":9090" {
		t.Errorf("Addr = %q, want :9090 (env survives unset flag)", cfg.Addr)
	}
	if !cfg.H2C {
		t.Errorf("H2C = false, want true")
	}
}

func TestLoadConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		args    []string
		wantSub string
	}{
		{
			name:    "tls cert without key",
			env:     map[string]string{"POSEIDON_TLS_CERT": "cert.pem"},
			wantSub: "TLS",
		},
		{
			name:    "tls key without cert",
			env:     map[string]string{"POSEIDON_TLS_KEY": "key.pem"},
			wantSub: "TLS",
		},
		{
			name:    "negative shutdown timeout",
			env:     map[string]string{"POSEIDON_SHUTDOWN_TIMEOUT": "-1s"},
			wantSub: "shutdown",
		},
		{
			name:    "negative max conns",
			env:     map[string]string{"POSEIDON_MAX_CONNS": "-3"},
			wantSub: "conns",
		},
		{
			name:    "negative max body bytes",
			env:     map[string]string{"POSEIDON_MAX_BODY_BYTES": "-4"},
			wantSub: "body",
		},
		{
			name:    "empty addr",
			env:     map[string]string{"POSEIDON_ADDR": ""},
			args:    []string{"-addr", ""},
			wantSub: "addr",
		},
		{
			name:    "invalid duration",
			env:     map[string]string{"POSEIDON_IDLE_TIMEOUT": "notaduration"},
			wantSub: "POSEIDON_IDLE_TIMEOUT",
		},
		{
			name:    "invalid int",
			env:     map[string]string{"POSEIDON_MAX_CONNS": "notanint"},
			wantSub: "POSEIDON_MAX_CONNS",
		},
		{
			name:    "invalid bool",
			env:     map[string]string{"POSEIDON_H2C": "notabool"},
			wantSub: "POSEIDON_H2C",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadConfig(envMap(tt.env), tt.args)
			if err == nil {
				t.Fatalf("loadConfig() error = nil, want error containing %q", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("loadConfig() error = %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestLoadConfig_NegativeSentinelsAllowed(t *testing.T) {
	// MaxBodyBytes < 0 is a documented "unlimited" sentinel in server.Options,
	// but for the binary we treat negative sizes as invalid EXCEPT the explicit
	// disable sentinels are not exposed; ensure -1 idle (disabled) is allowed.
	cfg, err := loadConfig(envMap(map[string]string{
		"POSEIDON_IDLE_TIMEOUT":     "-1ns",
		"POSEIDON_MAX_RAPID_RESETS": "-1",
	}), nil)
	if err != nil {
		t.Fatalf("loadConfig() error = %v, want nil (disable sentinels allowed)", err)
	}
	if cfg.IdleTimeout >= 0 {
		t.Errorf("IdleTimeout = %v, want negative (disabled)", cfg.IdleTimeout)
	}
	if cfg.MaxRapidResets != -1 {
		t.Errorf("MaxRapidResets = %d, want -1 (disabled)", cfg.MaxRapidResets)
	}
}
