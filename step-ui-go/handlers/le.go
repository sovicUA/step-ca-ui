package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	appdb "step-ui/db"
	"step-ui/le"
	"step-ui/models"
)

// ─── Dashboard ────────────────────────────────────────────────────────────────

func (h *Handler) LEDashboard(w http.ResponseWriter, r *http.Request) {
	certs, _ := appdb.GetLECerts(h.db)
	total, active, expiringSoon, expired := appdb.GetLEStats(h.db)
	logs, _ := appdb.GetLELogs(h.db, "", 20)
	settings, _ := appdb.GetLESettings(h.db)
	data := h.base(w, r, "le")
	data["LECerts"] = certs
	data["LETotal"] = total
	data["LEActive"] = active
	data["LEExpiring"] = expiringSoon
	data["LEExpired"] = expired
	data["LELogs"] = logs
	data["LESettings"] = settings
	h.render(w, "le_dashboard", data)
}

// ─── Issue ────────────────────────────────────────────────────────────────────

func (h *Handler) LEIssueGet(w http.ResponseWriter, r *http.Request) {
	settings, _ := appdb.GetLESettings(h.db)
	data := h.base(w, r, "le-issue")
	data["LESettings"] = settings
	h.render(w, "le_issue", data)
}

func (h *Handler) LEIssuePost(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/le/issue") {
		return
	}
	domain := trimStr(r.FormValue("domain"))
	email := trimStr(r.FormValue("email"))
	provider := r.FormValue("provider")
	autoRenew := r.FormValue("auto_renew") == "on"

	if domain == "" || email == "" {
		h.flash(w, r, "err", "Заповніть домен і email")
		http.Redirect(w, r, "/le/issue", http.StatusFound)
		return
	}

	if appdb.LECertExists(h.db, domain) {
		h.flash(w, r, "err", "Сертифікат для цього домену вже існує")
		http.Redirect(w, r, "/le/issue", http.StatusFound)
		return
	}

	settings, _ := appdb.GetLESettings(h.db)

	// Create a database record with status pending
	id, err := appdb.CreateLECert(h.db, domain, email, provider, autoRenew)
	if err != nil {
		h.flash(w, r, "err", "Помилка створення запису: "+err.Error())
		http.Redirect(w, r, "/le/issue", http.StatusFound)
		return
	}

	appdb.AddLELog(h.db, domain, "issue", "Початок випуску сертифіката")

	// Issue in the background
	go func() {
		result, err := le.IssueCert(le.LEConfig{
			Email:     email,
			Domain:    domain,
			Provider:  provider,
			CFToken:   settings.CFToken,
			CFZoneID:  settings.CFZoneID,
			R53KeyID:  settings.R53KeyID,
			R53Secret: settings.R53SecretKey,
			R53Region: settings.R53Region,
		})
		if err != nil {
			appdb.UpdateLECertStatus(h.db, id, "error", err.Error())
			appdb.AddLELog(h.db, domain, "error", fmt.Sprintf("Помилка: %v", err))
			return
		}
		appdb.UpdateLECertPaths(h.db, id, result.CertPath, result.KeyPath, result.IssuedAt, result.ExpiresAt)
		appdb.AddLELog(h.db, domain, "issue", "Сертифікат успішно випущено")
	}()

	h.flash(w, r, "ok", fmt.Sprintf("Випуск сертифіката для %s запущено! Стан оновиться за хвилину.", domain))
	http.Redirect(w, r, "/le", http.StatusFound)
}

// ─── Renew ────────────────────────────────────────────────────────────────────

func (h *Handler) LERenew(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/le") {
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	cert, _ := appdb.GetLECert(h.db, id)
	if cert == nil {
		http.Redirect(w, r, "/le", http.StatusFound)
		return
	}

	settings, _ := appdb.GetLESettings(h.db)
	appdb.UpdateLECertStatus(h.db, id, "pending", "")
	appdb.AddLELog(h.db, cert.Domain, "renew", "Ручне оновлення запущено")

	go func() {
		result, err := le.IssueCert(le.LEConfig{
			Email:    cert.Email,
			Domain:   cert.Domain,
			Provider: cert.Provider,
			CFToken:  settings.CFToken,
			CFZoneID: settings.CFZoneID,
		})
		if err != nil {
			appdb.UpdateLECertStatus(h.db, id, "error", err.Error())
			appdb.AddLELog(h.db, cert.Domain, "error", fmt.Sprintf("Помилка оновлення: %v", err))
			return
		}
		appdb.UpdateLECertPaths(h.db, id, result.CertPath, result.KeyPath, result.IssuedAt, result.ExpiresAt)
		appdb.AddLELog(h.db, cert.Domain, "renew", "Сертифікат успішно оновлено")
	}()

	h.flash(w, r, "ok", "Оновлення запущено!")
	http.Redirect(w, r, "/le", http.StatusFound)
}

// ─── Delete ───────────────────────────────────────────────────────────────────

func (h *Handler) LEDelete(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/le") {
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	cert, _ := appdb.GetLECert(h.db, id)
	if cert != nil {
		appdb.AddLELog(h.db, cert.Domain, "delete", "Сертифікат видалено із системи")
		appdb.DeleteLECert(h.db, id)
	}
	h.flash(w, r, "ok", "Сертифікат видалено")
	http.Redirect(w, r, "/le", http.StatusFound)
}

// ─── Toggle AutoRenew ─────────────────────────────────────────────────────────

func (h *Handler) LEToggleAutoRenew(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/le") {
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	cert, _ := appdb.GetLECert(h.db, id)
	if cert != nil {
		appdb.UpdateLECertAutoRenew(h.db, id, !cert.AutoRenew)
		if !cert.AutoRenew {
			h.flash(w, r, "ok", "Автооновлення увімкнено")
		} else {
			h.flash(w, r, "ok", "Автооновлення вимкнено")
		}
	}
	http.Redirect(w, r, "/le", http.StatusFound)
}

// ─── Download ─────────────────────────────────────────────────────────────────

func (h *Handler) LEDownloadCert(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	cert, _ := appdb.GetLECert(h.db, id)
	if cert == nil || cert.CertPath == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.crt", cert.Domain))
	http.ServeFile(w, r, cert.CertPath)
}

func (h *Handler) LEDownloadKey(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	cert, _ := appdb.GetLECert(h.db, id)
	if cert == nil || cert.KeyPath == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.key", cert.Domain))
	h.auditSecurity(r, fmt.Sprintf("le.key_download id=%d domain=%s", cert.ID, cert.Domain))
	http.ServeFile(w, r, cert.KeyPath)
}

// ─── Settings ─────────────────────────────────────────────────────────────────

func (h *Handler) LESettingsGet(w http.ResponseWriter, r *http.Request) {
	settings, _ := appdb.GetLESettings(h.db)
	data := h.base(w, r, "le-settings")
	data["LESettings"] = settings
	h.render(w, "le_settings", data)
}

func (h *Handler) LESettingsPost(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/le/settings") {
		return
	}
	settings := &models.LESettings{
		Email:        trimStr(r.FormValue("email")),
		Provider:     r.FormValue("provider"),
		CFToken:      trimStr(r.FormValue("cf_token")),
		CFZoneID:     trimStr(r.FormValue("cf_zone_id")),
		R53KeyID:     trimStr(r.FormValue("r53_key_id")),
		R53SecretKey: trimStr(r.FormValue("r53_secret")),
		R53Region:    trimStr(r.FormValue("r53_region")),
	}
	if settings.R53Region == "" {
		settings.R53Region = "us-east-1"
	}
	if err := appdb.SaveLESettings(h.db, settings); err != nil {
		h.flash(w, r, "err", "Помилка збереження: "+err.Error())
	} else {
		h.auditSecurity(r, fmt.Sprintf("le.settings.save provider=%s email=%s cf_configured=%t r53_configured=%t",
			settings.Provider, settings.Email, settings.CFToken != "" || settings.CFZoneID != "", settings.R53KeyID != "" || settings.R53SecretKey != ""))
		h.flash(w, r, "ok", "Налаштування збережено")
	}
	http.Redirect(w, r, "/le/settings", http.StatusFound)
}

// ─── Logs ─────────────────────────────────────────────────────────────────────

func (h *Handler) LELogs(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	logs, _ := appdb.GetLELogs(h.db, domain, 100)
	data := h.base(w, r, "le-logs")
	data["LELogs"] = logs
	data["FilterDomain"] = domain
	h.render(w, "le_logs", data)
}
