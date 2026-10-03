package handlers

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"image/png"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	appdb "step-ui/db"
	"step-ui/security"
)

const (
	totpIssuer     = "Step-CA UI"
	totpPendingTTL = 5 * time.Minute
)

func (h *Handler) Profile2FAGet(w http.ResponseWriter, r *http.Request) {
	si := h.sessionInfo(r)
	u, _ := appdb.GetUserByID(h.db, si.UserID)
	data := h.base(w, r, "profile")
	data["U"] = u
	h.render(w, "profile_2fa", data)
}

func (h *Handler) Profile2FAStart(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/profile/2fa") {
		return
	}
	si := h.sessionInfo(r)
	u, _ := appdb.GetUserByID(h.db, si.UserID)
	if u == nil {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}
	if u.TOTPEnabled {
		h.flash(w, r, "err", "2FA уже ввімкнена")
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: u.Username,
	})
	if err != nil {
		h.flash(w, r, "err", "Не вдалося створити секрет TOTP: "+err.Error())
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
		return
	}
	if err := appdb.UpdateUserTOTPPending(h.db, u.ID, key.Secret()); err != nil {
		h.flash(w, r, "err", "Не вдалося зберегти секрет TOTP")
	} else {
		h.flash(w, r, "ok", "Відскануйте QR-код і підтвердьте 6-значним кодом")
	}
	http.Redirect(w, r, "/profile/2fa", http.StatusFound)
}

func (h *Handler) Profile2FAQR(w http.ResponseWriter, r *http.Request) {
	si := h.sessionInfo(r)
	u, _ := appdb.GetUserByID(h.db, si.UserID)
	if u == nil || u.TOTPPendingSecret == "" || u.TOTPEnabled {
		http.NotFound(w, r)
		return
	}
	cleanSecret := strings.ToUpper(strings.TrimSpace(u.TOTPPendingSecret))
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(cleanSecret, "="))
	if err != nil {
		secretBytes, err = base32.StdEncoding.DecodeString(cleanSecret)
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: u.Username,
		Secret:      secretBytes,
	})
	if err != nil {
		http.NotFound(w, r)
		return
	}
	img, err := key.Image(220, 220)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_ = png.Encode(w, img)
}

func (h *Handler) Profile2FAConfirm(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/profile/2fa") {
		return
	}
	si := h.sessionInfo(r)
	u, _ := appdb.GetUserByID(h.db, si.UserID)
	if u == nil || u.TOTPPendingSecret == "" || u.TOTPEnabled {
		h.flash(w, r, "err", "Немає активного налаштування 2FA")
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
		return
	}
	code := strings.TrimSpace(r.FormValue("totp_code"))
	if !totp.Validate(code, u.TOTPPendingSecret) {
		h.flash(w, r, "err", "Неправильний код TOTP")
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
		return
	}
	recoveryCodes, hashes := generateRecoveryCodes(8)
	if err := appdb.EnableUserTOTP(h.db, u.ID, u.TOTPPendingSecret); err != nil {
		h.flash(w, r, "err", "Не вдалося ввімкнути 2FA")
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
		return
	}
	if err := appdb.ReplaceRecoveryCodes(h.db, u.ID, hashes); err != nil {
		h.flash(w, r, "err", "2FA увімкнена, але коди відновлення не збережено")
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
		return
	}
	u.TOTPEnabled = true
	u.TOTPSecret = u.TOTPPendingSecret
	u.TOTPPendingSecret = ""
	_ = appdb.LogAuth(h.db, u.Username, r.RemoteAddr, true, "2FA enabled")
	h.flash(w, r, "ok", "2FA успішно підключена")
	data := h.base(w, r, "profile")
	data["U"] = u
	data["RecoveryCodes"] = recoveryCodes
	h.render(w, "profile_2fa", data)
}

func (h *Handler) Profile2FADisable(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/profile/2fa") {
		return
	}
	si := h.sessionInfo(r)
	u, _ := appdb.GetUserByID(h.db, si.UserID)
	if u == nil || !u.TOTPEnabled {
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
		return
	}
	password := r.FormValue("current_password")
	code := strings.TrimSpace(r.FormValue("totp_code"))
	if !security.VerifyPassword(password, u.PasswordHash) {
		h.flash(w, r, "err", "Неправильний поточний пароль")
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
		return
	}
	if !totp.Validate(code, u.TOTPSecret) {
		h.flash(w, r, "err", "Неправильний код TOTP")
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
		return
	}
	if err := appdb.DisableUserTOTP(h.db, u.ID); err != nil {
		h.flash(w, r, "err", "Не вдалося вимкнути 2FA")
	} else {
		_ = appdb.LogAuth(h.db, u.Username, r.RemoteAddr, true, "2FA disabled")
		h.flash(w, r, "ok", "2FA вимкнена")
	}
	http.Redirect(w, r, "/profile/2fa", http.StatusFound)
}

func generateRecoveryCodes(n int) ([]string, []string) {
	codes := make([]string, 0, n)
	hashes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw := make([]byte, 9)
		_, _ = rand.Read(raw)
		hexed := strings.ToUpper(hex.EncodeToString(raw))
		code := fmt.Sprintf("%s-%s-%s", hexed[:6], hexed[6:12], hexed[12:18])
		codes = append(codes, code)
		hashes = append(hashes, security.HashPassword(code))
	}
	return codes, hashes
}

func (h *Handler) verifyRecoveryCode(userID int, code string) bool {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return false
	}
	hashes, err := appdb.GetUnusedRecoveryCodes(h.db, userID)
	if err != nil {
		return false
	}
	for id, hash := range hashes {
		if security.VerifyPassword(code, hash) {
			_ = appdb.UseRecoveryCode(h.db, id)
			return true
		}
	}
	return false
}
