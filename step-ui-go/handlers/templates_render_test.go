package handlers

import (
	"bytes"
	"html/template"
	"os"
	"strings"
	"testing"
	"time"

	"step-ui/models"
)

// TestTemplatesExecute renders pages through the real templates so that typos
// in field names do not become silent render errors at runtime.
func TestTemplatesExecute(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(".."); err != nil {
		t.Fatalf("chdir to module root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	h := &Handler{tmpls: make(map[string]*template.Template)}
	h.loadTemplates()

	expires := time.Now().Add(45 * 24 * time.Hour)
	issued := time.Now().Add(-10 * 24 * time.Hour)
	cert := &models.Certificate{
		ID: 1, Name: "app", Domain: "app.example.com", Status: "active",
		CertPath: "/opt/step-ui/certs/app/certificate.crt",
		KeyPath:  "/opt/step-ui/certs/app/private.key",
		Serial:   "123", KeyType: "EC:P-256", Provisioner: "admin",
		IssuedAt: &issued, ExpiresAt: &expires,
	}

	base := func(page string) map[string]interface{} {
		return map[string]interface{}{
			"Session":    &models.SessionInfo{UserID: 1, Username: "admin", Role: "admin", Theme: "dark"},
			"Msgs":       []models.FlashMsg{{Type: "warn", Text: "warn"}, {Type: "ok", Text: "ok"}},
			"ActivePage": page,
			"CSRFToken":  "test-token",
			"CARuntime":  models.CARuntime{Mode: "bundled", Configured: true},
		}
	}

	cases := []struct {
		page   string
		extra  map[string]interface{}
		expect []string
	}{
		{
			page: "certificates",
			extra: map[string]interface{}{
				"Certs": []*models.Certificate{cert},
			},
			expect: []string{`action="/renew/1"`, `action="/revoke/1"`, "csrf_token", "format=zip"},
		},
		{
			page: "dashboard",
			extra: map[string]interface{}{
				"Certs": []*models.Certificate{cert},
				"Activity": map[string]map[string]int{
					"24h": {"issue": 1, "total": 1}, "7d": {}, "30d": {},
				},
				"Total": 1, "OkC": 1, "WarnC": 0, "ExpC": 0,
				"AllCerts": 1, "LECerts": 0, "UsersCount": 1,
				"Uptime": "1хв", "StartedAt": "2026-01-01 00:00",
				"Version": Version, "BuildDate": BuildDate, "GitCommit": GitCommit,
			},
			expect: []string{`action="/renew/1"`, "csrf_token"},
		},
		{
			page: "certificate_detail",
			extra: map[string]interface{}{
				"Cert": cert,
				"Detail": &CertDetail{
					ID: 1, Name: "app", Domain: "app.example.com", DaysLeft: 45,
					PublicKey: "ECDSA P-256", NotBefore: issued, NotAfter: expires,
					DNSNames: []string{"app.example.com"}, ExtKeyUsage: []string{"Server Auth"},
				},
				"Validations": []CertValidation{{Name: "CA chain", Status: "ok", Detail: "verified"}},
			},
			expect: []string{"Download presets", "format=fullchain", "/pkcs12"},
		},
		{
			page: "admin_security",
			extra: map[string]interface{}{
				"Entries": []*models.AuthLog{{Username: "admin", IP: "10.0.0.1", Success: true, CreatedAt: time.Now()}},
				"SearchQ": "", "Filter": "", "Total": 1, "TotalOK": 1, "TotalFail": 0,
				"CurrentPage": 1, "TotalPages": 1,
				"Force2FARole": "admin", "Pending2FAUsers": []string{"admin (admin)"},
			},
			expect: []string{"Політика обов’язкової 2FA", `action="/admin/security/policy"`, "admin (admin)"},
		},
		{
			page: "admin_notifications",
			extra: map[string]interface{}{
				"Settings": &models.NotificationSettings{
					ExpiryDays: 30, SMTPPort: 587, SMTPSecurity: "starttls",
					NotifyEmailTo: "ops@example.com", TelegramEnabled: true, TelegramChatID: "-100",
				},
				"Logs": []*models.NotificationLog{{
					EventType: "certificate.expiring", Channel: "telegram",
					Title: "t", Message: "m", Success: true, CreatedAt: time.Now(),
				}},
			},
			expect: []string{"Telegram", "notify_email_to", "telegram_chat_id"},
		},
		{
			page: "admin_console",
			extra: map[string]interface{}{
				"Commands":          []adminConsoleCommand{{ID: "system.date", Label: "Дата", Name: "date"}},
				"SelectedCommandID": "",
				"Timeout":           "8s",
				"MaxOutputKB":       16,
				"TOTPEnabled":       false,
			},
			expect: []string{"запуск команд заблоковано", "disabled"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.page, func(t *testing.T) {
			tmpl, ok := h.tmpls[tc.page]
			if !ok {
				t.Fatalf("template %s was not loaded", tc.page)
			}
			data := base(tc.page)
			for k, v := range tc.extra {
				data[k] = v
			}
			name := "layout"
			if strings.HasPrefix(tc.page, "admin_") {
				name = "admin_layout"
			}
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
				t.Fatalf("execute %s: %v", tc.page, err)
			}
			for _, want := range tc.expect {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("%s: rendered output does not contain %q", tc.page, want)
				}
			}
		})
	}
}
