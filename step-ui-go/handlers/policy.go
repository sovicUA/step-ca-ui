package handlers

import (
	"net/http"
	"strings"

	appdb "step-ui/db"
)

var roleLevels = map[string]int{"viewer": 1, "manager": 2, "admin": 3}

func roleAtLeast(role, minRole string) bool {
	return roleLevels[role] >= roleLevels[minRole]
}

// force2FARole returns the lowest role that must use TOTP.
// An empty string means the policy is off.
func (h *Handler) force2FARole() string {
	settings, err := appdb.GetSecuritySettings(h.db)
	if err != nil || settings == nil {
		return ""
	}
	role := strings.TrimSpace(settings.Force2FARole)
	if _, ok := roleLevels[role]; !ok {
		return ""
	}
	return role
}

// requires2FA reports whether TOTP is required for the given role.
func (h *Handler) requires2FA(role string) bool {
	minRole := h.force2FARole()
	if minRole == "" {
		return false
	}
	return roleAtLeast(role, minRole)
}

// twoFAPolicyExemptPaths — routes available without meeting the 2FA policy,
// otherwise the user could not enable TOTP or log out.
var twoFAPolicyExemptPaths = []string{
	"/logout",
	"/profile/2fa",
	"/profile/2fa/start",
	"/profile/2fa/qr",
	"/profile/2fa/confirm",
	"/profile/2fa/disable",
}

// Enforce2FAPolicy redirects users who must use TOTP
// by the policy but have not enabled it to the 2FA setup page.
func (h *Handler) Enforce2FAPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range twoFAPolicyExemptPaths {
			if r.URL.Path == p {
				next.ServeHTTP(w, r)
				return
			}
		}

		si := h.sessionInfo(r)
		if si.UserID == 0 || !h.requires2FA(si.Role) {
			next.ServeHTTP(w, r)
			return
		}
		u, err := appdb.GetUserByID(h.db, si.UserID)
		if err != nil || u == nil || u.TOTPEnabled {
			next.ServeHTTP(w, r)
			return
		}

		h.flash(w, r, "warn", "Політика безпеки вимагає ввімкнути 2FA для вашої ролі.")
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
	})
}
