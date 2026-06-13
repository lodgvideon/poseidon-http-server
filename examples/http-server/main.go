// Package main demonstrates Poseidon HTTP/2 server with net/http.ServeMux
// (Go 1.22+ pattern routing) as a drop-in replacement.
//
// Run: go run ./examples/http-server
// Test: curl --http2-prior-knowledge http://localhost:8080/api/users
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lodgvideon/poseidon-http-server/middleware"
	"github.com/lodgvideon/poseidon-http-server/server"
)

type User struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

var users = []User{
	{ID: 1, Name: "Alice"},
	{ID: 2, Name: "Bob"},
	{ID: 3, Name: "Charlie"},
}

func main() {
	// --- Router (standard net/http.ServeMux, Go 1.22+ patterns) ---
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Poseidon HTTP/2 Server ✅\n")
	})

	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	})

	mux.HandleFunc("GET /api/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		var found *User
		for i := range users {
			if fmt.Sprintf("%d", users[i].ID) == r.PathValue("id") {
				found = &users[i]
				break
			}
		}
		if found == nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(found)
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		var u User
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		u.ID = len(users) + 1
		users = append(users, u)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(u)
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok\n")
	})

	// --- Poseidon server with middleware ---
	srv, err := server.NewServer(server.Options{
		// FromHTTPHandler adapts any http.Handler → Poseidon Handler
		Handler:     server.FromHTTPHandler(mux),
		IdleTimeout: 30 * time.Second,
		Middleware: []server.Middleware{
			middleware.Recovery(nil),
			middleware.RequestID(),
			middleware.AccessLog(stdLogger{}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// --- Listen ---
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		log.Println("Poseidon HTTP/2 server listening on :8080 (h2c)")
		if err := srv.Serve(ctx, ln); err != nil {
			log.Printf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("draining...")

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer drainCancel()
	if err := srv.Shutdown(drainCtx); err != nil {
		log.Printf("drain: %v", err)
	}
	log.Println("bye 👋")
}

type stdLogger struct{}

func (stdLogger) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}
