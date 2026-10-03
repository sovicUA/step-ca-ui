package handlers

import (
	"net/http"
	"time"
)

// AdminStats — summary counters for /admin.
type AdminStats struct {
	TotalUsers    int
	ActiveUsers   int
	BlockedUsers  int
	AdminsCount   int
	ManagersCount int
	ViewersCount  int
	LoginsToday   int
	FailedLogins  int
	ActiveCerts   int
	LeCerts       int
}

// AdminLogin — row of the recent logins.
type AdminLogin struct {
	Username  string
	IP        string
	CreatedAt time.Time
}

// AdminGet — admin overview page.
func (h *Handler) AdminGet(w http.ResponseWriter, r *http.Request) {
	var s AdminStats

	_ = h.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&s.TotalUsers)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_active = true`).Scan(&s.ActiveUsers)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_active = false`).Scan(&s.BlockedUsers)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&s.AdminsCount)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'manager'`).Scan(&s.ManagersCount)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'viewer'`).Scan(&s.ViewersCount)

	_ = h.db.QueryRow(`
		SELECT COUNT(*) FROM certificates
		WHERE status = 'active'
		  AND (expires_at IS NULL OR expires_at > NOW())
	`).Scan(&s.ActiveCerts)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM le_certificates`).Scan(&s.LeCerts)

	_ = h.db.QueryRow(`
		SELECT COUNT(*) FROM auth_log
		WHERE success = true
		  AND created_at > NOW() - INTERVAL '24 hours'
	`).Scan(&s.LoginsToday)
	_ = h.db.QueryRow(`
		SELECT COUNT(*) FROM auth_log
		WHERE success = false
		  AND created_at > NOW() - INTERVAL '24 hours'
	`).Scan(&s.FailedLogins)

	var recent []AdminLogin
	rows, err := h.db.Query(`
		SELECT COALESCE(username, '—') AS username,
		       COALESCE(ip, '—')       AS ip,
		       created_at
		FROM auth_log
		WHERE success = true
		ORDER BY created_at DESC
		LIMIT 10
	`)
	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var l AdminLogin
			if err := rows.Scan(&l.Username, &l.IP, &l.CreatedAt); err == nil {
				recent = append(recent, l)
			}
		}
	}

	data := h.base(w, r, "admin")
	data["Stats"] = s
	data["RecentLogins"] = recent
	h.render(w, "admin", data)
}

// AdminActivityGet — placeholder.
func (h *Handler) AdminActivityGet(w http.ResponseWriter, r *http.Request) {
	h.render(w, "admin_activity", h.base(w, r, "admin_activity"))
}

// AdminAboutGet — about the system.
func (h *Handler) AdminAboutGet(w http.ResponseWriter, r *http.Request) {
	data := h.base(w, r, "admin_about")
	checks, summary := h.preflight(r.Context())
	data["System"] = h.systemInfo()
	data["Checks"] = checks
	data["Summary"] = summary
	h.render(w, "admin_about", data)
}

// AdminIntegrityGet — CA integrity and update guardrails.
func (h *Handler) AdminIntegrityGet(w http.ResponseWriter, r *http.Request) {
	data := h.base(w, r, "admin_integrity")
	checks, summary := h.caIntegrity(r.Context())
	data["System"] = h.systemInfo()
	data["Checks"] = checks
	data["Summary"] = summary
	h.render(w, "admin_integrity", data)
}
