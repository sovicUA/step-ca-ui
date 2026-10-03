package handlers

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	appdb "step-ui/db"
)

const caHealthCacheTTL = 30 * time.Second

var caHealthCache = struct {
	sync.Mutex
	value     bool
	checkedAt time.Time
}{}

// metricWriter builds the Prometheus text format: HELP/TYPE are written
// once per metric, followed by its samples.
type metricWriter struct {
	buf      strings.Builder
	declared map[string]bool
}

func newMetricWriter() *metricWriter {
	return &metricWriter{declared: map[string]bool{}}
}

func (m *metricWriter) gauge(name, help, labels string, value interface{}) {
	if !m.declared[name] {
		fmt.Fprintf(&m.buf, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		m.declared[name] = true
	}
	if labels == "" {
		fmt.Fprintf(&m.buf, "%s %v\n", name, value)
		return
	}
	fmt.Fprintf(&m.buf, "%s{%s} %v\n", name, labels, value)
}

// Metrics serves metrics in the Prometheus text format.
// Endpoint enabled by the METRICS_TOKEN environment variable and requires
// the header `Authorization: Bearer <token>`.
func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	if !h.metricsAuthorized(r) {
		http.NotFound(w, r)
		return
	}

	m := newMetricWriter()
	m.gauge("step_ui_build_info", "Build metadata of the running UI.",
		fmt.Sprintf("version=%q,build_date=%q,commit=%q", Version, BuildDate, GitCommit), 1)
	m.gauge("step_ui_uptime_seconds", "Seconds since the UI process started.", "",
		int64(time.Since(StartedAt).Seconds()))

	dbUp := 0
	if err := h.db.PingContext(r.Context()); err == nil {
		dbUp = 1
	}
	m.gauge("step_ui_database_up", "PostgreSQL connectivity (1 = reachable).", "", dbUp)

	caUp := 0
	if h.caHealthy(r.Context()) {
		caUp = 1
	}
	m.gauge("step_ui_ca_up", "Step-CA health endpoint reachability (1 = reachable).", "", caUp)

	h.collectCertificateMetrics(m)
	h.collectUserMetrics(m)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(m.buf.String()))
}

func (h *Handler) metricsAuthorized(r *http.Request) bool {
	token := strings.TrimSpace(h.cfg.MetricsToken)
	if token == "" {
		return false
	}
	provided := strings.TrimPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

// caHealthy caches the result `step ca health`, so that frequent scrapes
// do not start a step CLI process on every call.
func (h *Handler) caHealthy(ctx context.Context) bool {
	caHealthCache.Lock()
	defer caHealthCache.Unlock()
	if !caHealthCache.checkedAt.IsZero() && time.Since(caHealthCache.checkedAt) < caHealthCacheTTL {
		return caHealthCache.value
	}
	ca := h.CA()
	healthy := false
	if ca.Configured {
		if _, err := runCheck(ctx, 5*time.Second, "step", "ca", "health",
			"--ca-url", ca.URL, "--root", ca.RootCert); err == nil {
			healthy = true
		}
	}
	caHealthCache.value = healthy
	caHealthCache.checkedAt = time.Now()
	return healthy
}

func (h *Handler) collectCertificateMetrics(m *metricWriter) {
	now := time.Now()

	certs, err := appdb.GetCerts(h.db, "")
	if err == nil {
		byStatus := map[string]int{"active": 0, "revoked": 0, "expired": 0}
		expiringSoon := 0
		for _, c := range certs {
			status := c.Status
			if status == "active" && c.ExpiresAt != nil && c.ExpiresAt.Before(now) {
				status = "expired"
			}
			byStatus[status]++
			if status == "active" && c.ExpiresAt != nil && c.ExpiresAt.Sub(now) <= 30*24*time.Hour {
				expiringSoon++
			}
		}
		for _, status := range []string{"active", "expired", "revoked"} {
			m.gauge("step_ui_certificates", "Internal CA certificates by status.",
				fmt.Sprintf("status=%q", status), byStatus[status])
		}
		m.gauge("step_ui_certificates_expiring_30d",
			"Active internal certificates expiring within 30 days.", "", expiringSoon)

		for _, c := range certs {
			if c.Status != "active" || c.ExpiresAt == nil {
				continue
			}
			m.gauge("step_ui_certificate_expiry_timestamp_seconds",
				"Certificate NotAfter as a Unix timestamp.",
				fmt.Sprintf("name=%q,domain=%q,source=%q", c.Name, c.Domain, "step-ca"),
				c.ExpiresAt.Unix())
		}
	}

	leCerts, err := appdb.GetLECerts(h.db)
	if err != nil {
		return
	}
	leByStatus := map[string]int{}
	for _, c := range leCerts {
		leByStatus[c.Status]++
	}
	for _, status := range []string{"active", "pending", "error"} {
		m.gauge("step_ui_le_certificates", "Let's Encrypt certificates by status.",
			fmt.Sprintf("status=%q", status), leByStatus[status])
	}
	for _, c := range leCerts {
		if c.Status != "active" || c.ExpiresAt == nil {
			continue
		}
		m.gauge("step_ui_certificate_expiry_timestamp_seconds",
			"Certificate NotAfter as a Unix timestamp.",
			fmt.Sprintf("name=%q,domain=%q,source=%q", c.Domain, c.Domain, "lets-encrypt"),
			c.ExpiresAt.Unix())
	}
}

func (h *Handler) collectUserMetrics(m *metricWriter) {
	var active, blocked, withTOTP int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_active = true`).Scan(&active)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_active = false`).Scan(&blocked)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE COALESCE(totp_enabled,false) = true`).Scan(&withTOTP)
	m.gauge("step_ui_users", "UI accounts by state.", `state="active"`, active)
	m.gauge("step_ui_users", "UI accounts by state.", `state="blocked"`, blocked)
	m.gauge("step_ui_users_totp_enabled", "UI accounts with TOTP enabled.", "", withTOTP)

	var failed24h int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM auth_log
		WHERE success = false AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&failed24h)
	m.gauge("step_ui_auth_failures_24h",
		"Failed authentication attempts in the last 24 hours.", "", failed24h)
}
