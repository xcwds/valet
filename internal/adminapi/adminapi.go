// Package adminapi is the operator API on the admin port (RFC Architecture).
// Every route requires an admin token (vlt_admin_…) as a Bearer token; there
// are no cookies, so there is nothing for a cross-site request to ride on.
package adminapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/operator"
	"github.com/xcwds/valet/internal/secrets"
	"github.com/xcwds/valet/internal/throttle"
)

// Deps are the services the API exposes.
type Deps struct {
	Jobs     *jobs.Service
	Operator *operator.Service
	Secrets  *secrets.Store
	AuditDB  *sql.DB // read-only, for listing events
	Log      *slog.Logger
}

const maxJSONBody = 64 << 10

type operatorKey struct{}

// Handler returns the API, to be mounted at /api/.
func Handler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/jobs", d.createJob)
	mux.HandleFunc("GET /api/jobs", d.listJobs)
	mux.HandleFunc("GET /api/jobs/{id}", d.getJob)
	mux.HandleFunc("POST /api/jobs/{id}/revoke", d.revokeJob)
	mux.HandleFunc("PUT /api/secrets/{name...}", d.putSecret)
	mux.HandleFunc("GET /api/secrets", d.listSecrets)
	mux.HandleFunc("DELETE /api/secrets/{name...}", d.deleteSecret)
	mux.HandleFunc("GET /api/audit", d.listAudit)
	return d.requireAdmin(mux)
}

func (d Deps) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Refuse paths a mux would clean (a//b, x/../y) instead of letting
		// it redirect or rewrite them: a secret name or job ID must mean
		// exactly what was sent.
		if p := r.URL.EscapedPath(); p != path.Clean(p) || strings.Contains(p, "%2") {
			writeError(w, http.StatusBadRequest, "non-canonical path")
			return
		}
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		name, err := d.Operator.Authenticate(r.Context(), strings.TrimSpace(tok), throttle.Source(r))
		if err != nil {
			if errors.Is(err, operator.ErrThrottled) {
				w.Header().Set("Retry-After", strconv.Itoa(d.Operator.RetryAfter()))
				writeError(w, http.StatusTooManyRequests, "too many failed authentications")
				return
			}
			if errors.Is(err, operator.ErrUnauthenticated) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="valet-admin"`)
				writeError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			d.internal(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), operatorKey{}, "admin:"+name)))
	})
}

func operatorName(r *http.Request) string {
	n, _ := r.Context().Value(operatorKey{}).(string)
	return n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // responses can hold a token once
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// internal logs the detail and returns a generic error, so database or file
// paths never reach the client.
func (d Deps) internal(w http.ResponseWriter, err error) {
	d.Log.Error("admin api", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "send application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

type createJobRequest struct {
	Role  string   `json:"role"`
	Repos []string `json:"repos"`
	TTL   string   `json:"ttl"`
}

type createJobResponse struct {
	Job   jobs.Job `json:"job"`
	Token string   `json:"token"`
}

func (d Deps) createJob(w http.ResponseWriter, r *http.Request) {
	var req createJobRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var ttl time.Duration
	if req.TTL != "" {
		var err error
		if ttl, err = time.ParseDuration(req.TTL); err != nil {
			writeError(w, http.StatusBadRequest, "ttl: "+err.Error())
			return
		}
	}
	job, token, err := d.Jobs.Create(r.Context(), jobs.CreateRequest{
		Role: req.Role, Repos: req.Repos, TTL: ttl, CreatedBy: operatorName(r),
	})
	if errors.Is(err, jobs.ErrInvalid) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		d.internal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createJobResponse{Job: job, Token: token})
}

func (d Deps) listJobs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := d.Jobs.List(r.Context(), limit)
	if err != nil {
		d.internal(w, err)
		return
	}
	if list == nil {
		list = []jobs.Job{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": list})
}

func (d Deps) getJob(w http.ResponseWriter, r *http.Request) {
	job, err := d.Jobs.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, jobs.ErrNotFound) {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if err != nil {
		d.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (d Deps) revokeJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &req) {
		return
	}
	err := d.Jobs.Revoke(r.Context(), r.PathValue("id"), operatorName(r), req.Reason)
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		writeError(w, http.StatusNotFound, "job not found")
	case errors.Is(err, jobs.ErrNotActive):
		writeError(w, http.StatusConflict, "job is not active")
	case err != nil:
		d.internal(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (d Deps) putSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := secrets.ValidateName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	value, err := io.ReadAll(http.MaxBytesReader(w, r.Body, secrets.MaxSecretSize))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("value is larger than %d bytes", secrets.MaxSecretSize))
		return
	}
	if len(value) == 0 {
		writeError(w, http.StatusBadRequest, "empty value")
		return
	}
	if err := d.Secrets.Put(r.Context(), name, value); err != nil {
		d.internal(w, err)
		return
	}
	clear(value)
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) listSecrets(w http.ResponseWriter, r *http.Request) {
	list, err := d.Secrets.List(r.Context())
	if err != nil {
		d.internal(w, err)
		return
	}
	type item struct {
		Name      string `json:"name"`
		UpdatedAt string `json:"updated_at"`
	}
	out := []item{}
	for _, i := range list {
		out = append(out, item{i.Name, i.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": out})
}

func (d Deps) deleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := secrets.ValidateName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	err := d.Secrets.Delete(r.Context(), name)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		writeError(w, http.StatusNotFound, "secret not found")
	case err != nil:
		d.internal(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (d Deps) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit > 1000 {
		limit = 1000
	}
	recs, err := audit.Tail(r.Context(), d.AuditDB, audit.Filter{JobID: q.Get("job"), Decision: q.Get("decision"), Limit: limit})
	if err != nil {
		d.internal(w, err)
		return
	}
	if recs == nil {
		recs = []audit.Record{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": recs})
}
