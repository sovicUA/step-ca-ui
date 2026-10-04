package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"

	"io"
	"mime"
	"path/filepath"
	"step-ui/config"
	appdb "step-ui/db"
	"step-ui/handlers"
	"step-ui/le"
	mw "step-ui/middleware"
	"step-ui/models"
	"strings"
)

// staticHandlerWithMIME serves static files with the CORRECT Content-Type.
// Does not use http.FileServer/ServeContent so that they do not overwrite the MIME type
// with values from the system /etc/mime.types (where .css may be text/plain).
func staticHandlerWithMIME(rootDir string) http.Handler {
	mimeByExt := map[string]string{
		".css":   "text/css; charset=utf-8",
		".js":    "application/javascript; charset=utf-8",
		".mjs":   "application/javascript; charset=utf-8",
		".json":  "application/json; charset=utf-8",
		".svg":   "image/svg+xml",
		".png":   "image/png",
		".jpg":   "image/jpeg",
		".jpeg":  "image/jpeg",
		".gif":   "image/gif",
		".webp":  "image/webp",
		".ico":   "image/x-icon",
		".woff":  "font/woff",
		".woff2": "font/woff2",
		".ttf":   "font/ttf",
		".otf":   "font/otf",
		".map":   "application/json; charset=utf-8",
		".html":  "text/html; charset=utf-8",
		".txt":   "text/plain; charset=utf-8",
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// safe path join
		clean := filepath.Clean("/" + r.URL.Path)
		full := filepath.Join(rootDir, clean)
		// path traversal protection
		absRoot, _ := filepath.Abs(rootDir)
		absFile, _ := filepath.Abs(full)
		if !strings.HasPrefix(absFile, absRoot) {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(full)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		ext := strings.ToLower(filepath.Ext(full))
		if mt, ok := mimeByExt[ext]; ok {
			w.Header().Set("Content-Type", mt)
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		io.Copy(w, f)
	})
}

func init() {
	// Force-register correct MIME types for static files.
	// http.ServeContent uses mime.TypeByExtension() and overwrites
	// any Content-Type set before, so only this approach works.
	mime.AddExtensionType(".css", "text/css; charset=utf-8")
	mime.AddExtensionType(".js", "application/javascript; charset=utf-8")
	mime.AddExtensionType(".mjs", "application/javascript; charset=utf-8")
	mime.AddExtensionType(".json", "application/json; charset=utf-8")
	mime.AddExtensionType(".svg", "image/svg+xml")
	mime.AddExtensionType(".webp", "image/webp")
	mime.AddExtensionType(".woff", "font/woff")
	mime.AddExtensionType(".woff2", "font/woff2")
	mime.AddExtensionType(".ttf", "font/ttf")
	mime.AddExtensionType(".otf", "font/otf")
	mime.AddExtensionType(".map", "application/json; charset=utf-8")
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "provisioner-register", "provisioner-update", "provisioner-list":
			if err := runProvisionerCLI(os.Args[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	handlers.StartedAt = time.Now()
	// Register types for gob (gorilla/sessions)
	gob.Register(int(0))
	gob.Register(int64(0))
	gob.Register("")
	gob.Register(models.FlashMsg{})
	gob.Register([]models.FlashMsg{})
	cfg := config.Load()

	// ─── Database ────────────────────────────────────────────────────────────
	conn, err := appdb.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Cannot connect to database: %v", err)
	}
	defer conn.Close()

	if err := appdb.InitSchema(conn); err != nil {
		log.Fatalf("Cannot init DB schema: %v", err)
	}
	if err := appdb.InitLESchema(conn); err != nil {
		log.Fatalf("Cannot init LE schema: %v", err)
	}
	if err := appdb.InitNotificationSchema(conn); err != nil {
		log.Fatalf("Cannot init notification schema: %v", err)
	}
	if err := appdb.InitPasswordResetSchema(conn); err != nil {
		log.Fatalf("Cannot init password reset schema: %v", err)
	}
	sysPassword, _ := appdb.ReadProvisionerPasswordFile(cfg.PasswordFile)
	if err := appdb.EnsureSystemProvisioner(conn, cfg.Provisioner, sysPassword, cfg.SecretKey); err != nil {
		log.Printf("[startup] warning: could not seed system provisioner: %v", err)
	}

	// ─── Sessions ────────────────────────────────────────────────────────────
	hashKey := sha256.Sum256([]byte(cfg.SecretKey))
	blockKey := sha256.Sum256([]byte(cfg.SecretKey + "_block"))
	store := sessions.NewCookieStore(hashKey[:], blockKey[:16])
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   28800,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cfg.SessionSecure,
	}

	// ─── Handlers ────────────────────────────────────────────────────────────
	h := handlers.New(conn, cfg, store)

	// ─── Let's Encrypt auto-renewer ──────────────────────────────────────────
	le.StartRenewer(conn, h.NotifyAsync)
	h.StartNotificationWorker()

	// ─── Router ──────────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.RealIP)
	r.Use(mw.SecurityHeaders(func() bool {
		return h.CA().EnableHSTS
	}))

	// Public routes
	r.Get("/login", h.LoginGet)
	r.Post("/login", h.LoginPost)
	r.Get("/forgot-password", h.ForgotPasswordGet)
	r.Post("/forgot-password", h.ForgotPasswordPost)
	r.Get("/reset-password", h.ResetPasswordGet)
	r.Post("/reset-password", h.ResetPasswordPost)
	r.Get("/logout", h.Logout)
	// Interface language switcher (cookie + profile of a logged-in user)
	r.Get("/lang/{code}", h.SetLang)
	// Prometheus scrape endpoint: enabled by METRICS_TOKEN, bearer token authorization.
	r.Get("/metrics", h.Metrics)

	// Authorized routes
	r.Group(func(r chi.Router) {
		r.Use(mw.RequireLogin(store))
		r.Use(h.Enforce2FAPolicy)

		r.Get("/", h.Home)
		r.Get("/dashboard", h.Dashboard)
		r.Get("/api/status", h.APIStatus)

		// Certificates (viewer+)
		r.Get("/certificates", h.Certificates)
		r.Get("/certificates/{id}", h.CertificateDetails)
		r.Get("/history", h.History)
		r.Get("/provisioners", h.Provisioners)

		// Download CA cert (admin)
		r.Group(func(r chi.Router) {
			r.Use(mw.RequireRole("admin", store))
			r.Get("/download/ca", h.DownloadCA)
			r.Get("/download/intermediate-ca", h.DownloadIntermediateCA)
			r.Get("/download/full-chain", h.DownloadFullChain)
		})

		// Certificate operations (manager+)
		r.Group(func(r chi.Router) {
			r.Use(mw.RequireRole("manager", store))
			r.Get("/issue", h.IssueGet)
			r.Post("/issue", h.IssuePost)
			r.Post("/renew/{id}", h.Renew)
			r.Get("/import", h.ImportGet)
			r.Post("/import", h.ImportPost)
			r.Get("/download/cert/{id}", h.DownloadCert)
			r.Get("/download/key/{id}", h.DownloadKey)
			r.Get("/download/bundle/{id}", h.DownloadBundle)
			r.Post("/download/bundle/{id}/pkcs12", h.DownloadBundlePKCS12)
		})

		// Revocation (admin)
		r.Group(func(r chi.Router) {
			r.Use(mw.RequireRole("admin", store))
			r.Post("/revoke/{id}", h.Revoke)
		})

		// User management (admin)
		r.Group(func(r chi.Router) {
			r.Use(mw.RequireRole("admin", store))
			// Admin area
			r.Get("/admin", h.AdminGet)
			r.Get("/admin/users", h.Users)
			r.Post("/admin/users", h.UsersPost)
			r.Get("/admin/users/{id}", h.UserProfile)
			r.Get("/admin/users-temp", h.AdminUsersTempGet)
			r.Post("/admin/users-temp", h.AdminUsersTempPost)
			r.Get("/admin/activity", h.AdminActivityGet)
			r.Get("/admin/ca-certs", h.AdminCACertsGet)
			r.Get("/admin/ca-certs/{serial}/download", h.AdminCACertDownload)
			r.Get("/admin/security", h.SecurityLog)
			r.Post("/admin/security/policy", h.SecurityPolicyPost)
			r.Get("/admin/console", h.AdminConsoleGet)
			r.Post("/admin/console", h.AdminConsolePost)
			r.Get("/admin/about", h.AdminAboutGet)
			r.Get("/admin/integrity", h.AdminIntegrityGet)
			r.Get("/admin/backup", h.AdminBackupGet)
			r.Post("/admin/backup/download", h.AdminBackupDownload)
			r.Get("/admin/notifications", h.AdminNotificationsGet)
			r.Post("/admin/notifications", h.AdminNotificationsPost)
			r.Post("/admin/notifications/test", h.AdminNotificationsTest)
			r.Get("/admin/ca", h.AdminCAGet)
			r.Post("/admin/ca", h.AdminCAPost)
			r.Post("/admin/ca/test", h.AdminCATestPost)
		})

		// Let's Encrypt (manager+)
		r.Group(func(r chi.Router) {
			r.Use(mw.RequireRole("manager", store))
			r.Get("/le", h.LEDashboard)
			r.Get("/le/issue", h.LEIssueGet)
			r.Post("/le/issue", h.LEIssuePost)
			r.Post("/le/{id}/renew", h.LERenew)
			r.Post("/le/{id}/delete", h.LEDelete)
			r.Post("/le/{id}/autorenew", h.LEToggleAutoRenew)
			r.Get("/le/download/cert/{id}", h.LEDownloadCert)
			r.Get("/le/download/key/{id}", h.LEDownloadKey)
			r.Get("/le/settings", h.LESettingsGet)
			r.Post("/le/settings", h.LESettingsPost)
			r.Get("/le/logs", h.LELogs)
		})

		// Profile (any authorized user)
		r.Get("/profile", h.ProfileGet)
		r.Post("/profile", h.ProfilePost)
		r.Get("/profile/2fa", h.Profile2FAGet)
		r.Post("/profile/2fa/start", h.Profile2FAStart)
		r.Get("/profile/2fa/qr", h.Profile2FAQR)
		r.Post("/profile/2fa/confirm", h.Profile2FAConfirm)
		r.Post("/profile/2fa/disable", h.Profile2FADisable)
	})

	// ─── Static files ─────────────────────────────────────────────────────────
	r.Handle("/static/*", http.StripPrefix("/static/", staticHandlerWithMIME("static")))
	// ─── Start server ─────────────────────────────────────────────────────────
	for _, dir := range []string{cfg.CertsDir, cfg.UploadDir, "/opt/step-ui/ssl", "/opt/step-ui/data"} {
		os.MkdirAll(dir, 0755)
	}

	// // temp_users_expire_ticker
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			if n, err := appdb.ExpireOverdueTempUsers(conn); err == nil && n > 0 {
				log.Printf("temp-users: expired %d account(s)", n)
			}
		}
	}()

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	if _, err := os.Stat(cfg.SSLCert); err == nil {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		srv := &http.Server{Addr: addr, Handler: r, TLSConfig: tlsCfg}
		fmt.Printf("[*] Starting Step-CA UI (HTTPS) on port %d\n", cfg.Port)
		log.Fatal(srv.ListenAndServeTLS(cfg.SSLCert, cfg.SSLKey))
	} else {
		fmt.Printf("[!] SSL cert not found, starting HTTP on port %d\n", cfg.Port)
		log.Fatal(http.ListenAndServe(addr, r))
	}
}
