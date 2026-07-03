package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/redlens/redlens/internal/scanner"
)

type ScanRequest struct {
	Targets  []scanner.Target `json:"targets"`
	Scanners []string         `json:"scanners,omitempty"`
}

type ScanResponse struct {
	Results []*scanner.Result `json:"results"`
	Summary struct {
		Total    int    `json:"total"`
		Duration string `json:"duration"`
	} `json:"summary"`
}

func (s *Server) handleListScanners(w http.ResponseWriter, r *http.Request) {
	scanners := s.engine.List()
	json.NewEncoder(w).Encode(map[string]any{
		"scanners": scanners,
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Targets) == 0 {
		http.Error(w, "no targets provided", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	var targets []*scanner.Target
	for i := range req.Targets {
		targets = append(targets, &req.Targets[i])
	}

	results, err := s.engine.RunAll(ctx, targets)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	total := 0
	for _, result := range results {
		total += len(result.Vulns)
	}

	resp := ScanResponse{
		Results: results,
	}
	resp.Summary.Total = total

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
