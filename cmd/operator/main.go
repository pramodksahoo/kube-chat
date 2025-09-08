package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	version = "dev"
	service = "operator"
)

func main() {
	log.Printf("Starting KubeChat Operator %s (service: %s)", version, service)

	// Basic health check endpoint
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Ready")
	})

	// Start HTTP server for health checks
	go func() {
		port := getEnv("HEALTH_CHECK_PORT", "8082")
		address := ":" + port
		log.Printf("Health check server starting on %s", address)
		if err := http.ListenAndServe(address, nil); err != nil {
			log.Printf("Health check server error: %v", err)
		}
	}()

	// Simulate operator work
	go func() {
		for {
			log.Println("Operator heartbeat - monitoring Kubernetes resources...")
			time.Sleep(30 * time.Second)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	log.Println("KubeChat Operator shutting down...")
}

// Helper function to get environment variables with defaults
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}