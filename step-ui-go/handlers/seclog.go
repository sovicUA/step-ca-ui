package handlers

import (
	"net/http"
	"strconv"
	"strings"

	appdb "step-ui/db"
	"step-ui/models"
)

func (h *Handler) SecurityLog(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("q")
	filter := r.URL.Query().Get("filter")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	entries, total, _ := appdb.GetAuthLogs(h.db, search, filter, page, pageSize)
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	okCount, failCount := appdb.GetAuthStats(h.db)
	data := h.base(w, r, "admin_security")
	data["Entries"] = entries
	data["SearchQ"] = search
	data["Filter"] = filter
	data["Total"] = total
	data["TotalOK"] = okCount
	data["TotalFail"] = failCount
	data["CurrentPage"] = page
	data["TotalPages"] = totalPages
	data["Force2FARole"] = h.force2FARole()
	data["Pending2FAUsers"] = h.pending2FAPolicyUsers()
	h.render(w, "admin_security", data)
}

// SecurityPolicyPost saves the mandatory 2FA policy.
func (h *Handler) SecurityPolicyPost(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/admin/security") {
		return
	}
	role := strings.TrimSpace(r.FormValue("force_2fa_role"))
	if role != "" && role != "admin" && role != "manager" {
		h.flash(w, r, "err", "Неприпустима роль для політики 2FA")
		http.Redirect(w, r, "/admin/security", http.StatusSeeOther)
		return
	}
	if err := appdb.SaveSecuritySettings(h.db, &models.SecuritySettings{Force2FARole: role}); err != nil {
		h.flash(w, r, "err", "Не вдалося зберегти політику: "+err.Error())
		http.Redirect(w, r, "/admin/security", http.StatusSeeOther)
		return
	}
	h.auditSecurity(r, "security.policy.save force_2fa_role="+role)
	if role == "" {
		h.flash(w, r, "ok", "Політику обов’язкової 2FA вимкнено")
	} else {
		h.flash(w, r, "ok", "Політику обов’язкової 2FA збережено: "+role+" і вище")
	}
	http.Redirect(w, r, "/admin/security", http.StatusSeeOther)
}

// pending2FAPolicyUsers — active users whom the policy requires
// to enable TOTP but who have not set it up yet.
func (h *Handler) pending2FAPolicyUsers() []string {
	minRole := h.force2FARole()
	if minRole == "" {
		return nil
	}
	rows, err := h.db.Query(`SELECT username, role FROM users
		WHERE is_active = true AND COALESCE(totp_enabled,false) = false ORDER BY username`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var username, role string
		if err := rows.Scan(&username, &role); err != nil {
			continue
		}
		if roleAtLeast(role, minRole) {
			out = append(out, username+" ("+role+")")
		}
	}
	return out
}
