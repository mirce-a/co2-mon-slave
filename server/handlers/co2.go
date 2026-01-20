package handlers

import (
	"encoding/json"
	"net/http"
)

type Co2Handler struct{}

type Co2Reading struct {
	Value     int    `json:"value"`
	Area      string `json:"area"`
	Timestamp string `json:"timestamp"`
}

func (h *Co2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && (r.URL.Path == "/co2" || r.URL.Path == "/co2/") {
		h.Co2Read(w, r)
		return
	}
}

func (h *Co2Handler) Co2Read(w http.ResponseWriter, r *http.Request) {
	reading := Co2Reading{
		Value:     400,
		Area:      "greenhouse-01",
		Timestamp: "11-11-2025 19:03:24",
	}

	if err := json.NewEncoder(w).Encode(reading); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
