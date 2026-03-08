package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/brandon/bugscanner/internal/broker"
	"github.com/brandon/bugscanner/internal/database"
)

// Request/Response types

type CreateScanRequest struct {
	Target   string   `json:"target"`
	ScopeIn  []string `json:"scope_in"`
	ScopeOut []string `json:"scope_out"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type ScanResponse struct {
	Scan *database.Scan  `json:"scan"`
	Jobs []database.ScanJob `json:"jobs,omitempty"`
}

type ScanResultsResponse struct {
	Scan            *database.Scan              `json:"scan"`
	Vulnerabilities []database.Vulnerability    `json:"vulnerabilities"`
}

// Handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}

	if req.Target == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "target is required"})
		return
	}

	// Default scope: include all subdomains of the target
	if len(req.ScopeIn) == 0 {
		req.ScopeIn = []string{`(?i)^.*\.?` + escapeRegex(req.Target) + `$`}
	}
	// Ensure never nil so pgx sends {} not NULL
	if req.ScopeOut == nil {
		req.ScopeOut = []string{}
	}

	scan, err := s.scanRepo.Create(r.Context(), req.Target, req.ScopeIn, req.ScopeOut, nil)
	if err != nil {
		slog.Error("failed to create scan", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to create scan"})
		return
	}

	// Update status to running
	if err := s.scanRepo.UpdateStatus(r.Context(), scan.ID, database.ScanStatusRunning); err != nil {
		slog.Error("failed to update scan status", "error", err)
	}

	// Publish discovery job to kick off the pipeline
	err = s.broker.PublishToStage(r.Context(), broker.QueueDiscovery, scan.ID, broker.DiscoveryPayload{
		Domain:   req.Target,
		ScopeIn:  req.ScopeIn,
		ScopeOut: req.ScopeOut,
	})
	if err != nil {
		slog.Error("failed to publish discovery job", "error", err)
		s.scanRepo.UpdateStatus(r.Context(), scan.ID, database.ScanStatusFailed)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to start scan"})
		return
	}

	slog.Info("scan created", "scan_id", scan.ID, "target", req.Target)
	writeJSON(w, http.StatusCreated, ScanResponse{Scan: scan})
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	if limit <= 0 || limit > 100 {
		limit = 20
	}

	scans, err := s.scanRepo.List(r.Context(), limit, offset)
	if err != nil {
		slog.Error("failed to list scans", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to list scans"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"scans": scans, "count": len(scans)})
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "scanID")

	scan, err := s.scanRepo.GetByID(r.Context(), scanID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "scan not found"})
		return
	}

	jobs, err := s.scanRepo.GetJobsByScanID(r.Context(), scanID)
	if err != nil {
		slog.Error("failed to get scan jobs", "error", err)
	}

	writeJSON(w, http.StatusOK, ScanResponse{Scan: scan, Jobs: jobs})
}

func (s *Server) handleGetScanResults(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "scanID")

	scan, err := s.scanRepo.GetByID(r.Context(), scanID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "scan not found"})
		return
	}

	vulns, err := s.vulnRepo.GetByScanID(r.Context(), scanID)
	if err != nil {
		slog.Error("failed to get vulnerabilities", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to get results"})
		return
	}

	writeJSON(w, http.StatusOK, ScanResultsResponse{Scan: scan, Vulnerabilities: vulns})
}

func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "scanID")

	scan, err := s.scanRepo.GetByID(r.Context(), scanID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "scan not found"})
		return
	}

	if scan.Status != database.ScanStatusRunning && scan.Status != database.ScanStatusPending {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "scan is not running"})
		return
	}

	if err := s.scanRepo.UpdateStatus(r.Context(), scanID, database.ScanStatusCancelled); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to cancel scan"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (s *Server) handleListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")

	var vulns []database.Vulnerability
	var err error

	if severity != "" {
		vulns, err = s.vulnRepo.GetBySeverity(r.Context(), severity)
	} else {
		scanID := r.URL.Query().Get("scan_id")
		if scanID != "" {
			vulns, err = s.vulnRepo.GetByScanID(r.Context(), scanID)
		} else {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "scan_id or severity filter required"})
			return
		}
	}

	if err != nil {
		slog.Error("failed to list vulnerabilities", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to list vulnerabilities"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"vulnerabilities": vulns, "count": len(vulns)})
}

func (s *Server) handleMarkFalsePositive(w http.ResponseWriter, r *http.Request) {
	vulnID := chi.URLParam(r, "vulnID")

	var req struct {
		Notes string `json:"notes"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if err := s.vulnRepo.MarkFalsePositive(r.Context(), vulnID, req.Notes); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "marked as false positive"})
}

func (s *Server) handleMarkTriaged(w http.ResponseWriter, r *http.Request) {
	vulnID := chi.URLParam(r, "vulnID")

	var req struct {
		Notes string `json:"notes"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if err := s.vulnRepo.MarkTriaged(r.Context(), vulnID, req.Notes); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "marked as triaged"})
}

// Helpers

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func escapeRegex(s string) string {
	special := `\.+*?[^]$(){}=!<>|:-`
	result := ""
	for _, c := range s {
		if containsRune(special, c) {
			result += `\`
		}
		result += string(c)
	}
	return result
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
