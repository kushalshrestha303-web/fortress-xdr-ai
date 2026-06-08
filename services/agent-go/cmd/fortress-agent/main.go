package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"
)

type TelemetryEvent struct {
	TenantID   string         `json:"tenant_id"`
	Sector     string         `json:"sector"`
	Source     string         `json:"source"`
	EventType  string         `json:"event_type"`
	Severity   string         `json:"severity"`
	Attributes map[string]any `json:"attributes"`
}

func main() {
	api := env("FORTRESS_API_URL", "http://localhost:8080/api/v1/telemetry/events")
	tenant := env("FORTRESS_TENANT_ID", "default")
	sector := env("FORTRESS_SECTOR", "enterprise")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		event := TelemetryEvent{
			TenantID:  tenant,
			Sector:    sector,
			Source:    "fortress-shield-agent",
			EventType: "endpoint_health",
			Severity:  "info",
			Attributes: map[string]any{
				"os":           runtime.GOOS,
				"architecture": runtime.GOARCH,
				"goroutines":   runtime.NumGoroutine(),
			},
		}
		if err := postJSON(api, event); err != nil {
			log.Printf("telemetry post failed: %v", err)
		}
		<-ticker.C
	}
}

func env(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func postJSON(url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

