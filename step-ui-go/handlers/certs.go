package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	appdb "step-ui/db"
	"step-ui/models"
)

func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	// CA status: checked with step ca health
	ca := h.CA()
	caOnline := true
	if !ca.Configured {
		caOnline = false
	} else {
		_, err := exec.Command("step", "ca", "health",
			"--ca-url", ca.URL,
			"--root", ca.RootCert).Output()
		if err != nil {
			caOnline = false
		}
	}

	// Quick statistics of active certificates
	certs, _ := appdb.GetCerts(h.db, "active")
	var activeCount, expiringCount int
	for _, c := range certs {
		d := daysLeftVal(c.ExpiresAt)
		if d > 0 && d <= 30 {
			expiringCount++
		}
		if d > 0 {
			activeCount++
		}
	}

	var leCount int
	h.db.QueryRow("SELECT COUNT(*) FROM le_certificates WHERE status='active'").Scan(&leCount)

	data := h.base(w, r, "home")
	data["CAOnline"] = caOnline
	data["CAMode"] = ca.Mode
	data["CAConfigured"] = ca.Configured
	data["Uptime"] = fmtUptime(time.Since(StartedAt))
	data["ActiveCerts"] = activeCount
	data["ExpiringCerts"] = expiringCount
	data["LECerts"] = leCount
	data["Version"] = Version
	h.render(w, "home", data)
}

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	certs, _ := appdb.GetCerts(h.db, "active")
	total := len(certs)
	okC, warnC, expC := 0, 0, 0
	for _, c := range certs {
		d := daysLeftVal(c.ExpiresAt)
		if d <= 0 {
			expC++
		} else if d <= 30 {
			warnC++
		} else {
			okC++
		}
	}

	// ── CA activity per period ──
	act := map[string]map[string]int{
		"24h": dashCountActions(h.db, 24*time.Hour),
		"7d":  dashCountActions(h.db, 7*24*time.Hour),
		"30d": dashCountActions(h.db, 30*24*time.Hour),
	}

	// ── Overall statistics ──
	var allCerts, leCerts, usersCount int
	h.db.QueryRow("SELECT COUNT(*) FROM certificates").Scan(&allCerts)
	h.db.QueryRow("SELECT COUNT(*) FROM le_certificates").Scan(&leCerts)
	h.db.QueryRow("SELECT COUNT(*) FROM users WHERE is_active = true").Scan(&usersCount)

	// ── Server uptime ──
	uptime := time.Since(StartedAt)

	data := h.base(w, r, "dash")
	data["Certs"] = certs
	data["Total"] = total
	data["OkC"] = okC
	data["WarnC"] = warnC
	data["ExpC"] = expC
	data["Activity"] = act
	data["AllCerts"] = allCerts
	data["LECerts"] = leCerts
	data["UsersCount"] = usersCount
	data["Uptime"] = fmtUptime(uptime)
	data["StartedAt"] = StartedAt.Format("2006-01-02 15:04")
	data["Version"] = Version
	data["BuildDate"] = BuildDate
	data["GitCommit"] = GitCommit
	h.render(w, "dashboard", data)
}

// ─── helper: counts actions by type for the last period ──────────────────
func dashCountActions(db *sql.DB, since time.Duration) map[string]int {
	result := map[string]int{"issue": 0, "renew": 0, "revoke": 0, "import": 0, "total": 0}
	rows, err := db.Query(
		`SELECT action, COUNT(*) FROM cert_history WHERE created_at >= $1 GROUP BY action`,
		time.Now().Add(-since),
	)
	if err != nil {
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var action string
		var count int
		if err := rows.Scan(&action, &count); err == nil {
			if _, ok := result[action]; ok {
				result[action] = count
			}
			result["total"] += count
		}
	}
	return result
}

// ─── helper: formats a duration ──────────────────────────────────────────
func fmtUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dд %dг %dхв", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dг %dхв", hours, mins)
	}
	return fmt.Sprintf("%dхв", mins)
}

func (h *Handler) Certificates(w http.ResponseWriter, r *http.Request) {
	certs, _ := appdb.GetCerts(h.db, "")
	data := h.base(w, r, "certs")
	data["Certs"] = certs
	h.render(w, "certificates", data)
}

func (h *Handler) IssueGet(w http.ResponseWriter, r *http.Request) {
	data := h.base(w, r, "issue")
	h.attachIssueProvisioners(data)
	h.render(w, "issue", data)
}

func (h *Handler) IssuePost(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/issue") {
		return
	}
	si := h.sessionInfo(r)
	name := trimStr(r.FormValue("name"))
	domain := trimStr(r.FormValue("domain"))
	provisionerName := trimStr(r.FormValue("provisioner"))
	policy, policyErr := normalizeIssuePolicy(r.FormValue("template"), r.FormValue("duration"), r.FormValue("key_type"), domain)
	data := h.base(w, r, "issue")
	h.attachIssueProvisioners(data)
	if name == "" || domain == "" {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Заповніть усі поля"}}
		h.render(w, "issue", data)
		return
	}
	if policyErr != nil {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Помилка політики: " + policyErr.Error()}}
		h.render(w, "issue", data)
		return
	}
	if provisionerName == "" {
		provisionerName = h.CA().Provisioner
	}
	prov, err := appdb.GetCAProvisioner(h.db, provisionerName)
	if err != nil || prov == nil {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Провізіонер не зареєстровано в UI"}}
		h.render(w, "issue", data)
		return
	}
	if durationExceedsMax(policy.Duration, prov.MaxDuration) {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Строк дії перевищує максимум вибраного провізіонера"}}
		h.render(w, "issue", data)
		return
	}
	certDir := filepath.Join(h.cfg.CertsDir, sanitizeName(name))
	os.MkdirAll(certDir, 0755)
	certPath := filepath.Join(certDir, "certificate.crt")
	keyPath := filepath.Join(certDir, "private.key")
	if err := h.issueWithRegisteredProvisioner(domain, certPath, keyPath, policy.Duration, policy.KeyType, policy.Purpose, provisionerName); err != nil {
		h.notifyAsync("", "certificate.issue_failed", "error",
			"Certificate issue failed",
			fmt.Sprintf("Не вдалося випустити сертифікат %s для %s: %s", name, domain, err.Error()),
			map[string]string{"name": name, "domain": domain, "template": policy.Template, "key_type": policy.KeyType})
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Помилка: " + err.Error()}}
		h.render(w, "issue", data)
		return
	}
	issued, expires, serial, _ := parseCertDates(certPath)
	appdb.InsertCert(h.db, &models.Certificate{
		Name: name, Domain: domain, CertPath: certPath, KeyPath: keyPath,
		IssuedAt: issued, ExpiresAt: expires, Serial: serial, KeyType: policy.KeyType, Provisioner: provisionerName,
	})
	appdb.InsertHistory(h.db, "issue", name, domain, fmt.Sprintf("Шаблон: %s, тип: %s, строк: %s, провізіонер: %s", policy.Template, policy.KeyType, policy.Duration, provisionerName), si.Username, si.Role)
	h.flash(w, r, "ok", fmt.Sprintf("Сертифікат %s для %s випущено (%s)!", name, domain, policy.KeyType))
	http.Redirect(w, r, "/issue", http.StatusFound)
}

func (h *Handler) Renew(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/certificates") {
		return
	}
	si := h.sessionInfo(r)
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	c, _ := appdb.GetCert(h.db, id)
	if c != nil {
		keyType := c.KeyType
		if keyType == "" {
			keyType = "EC:P-256"
		}
		provisionerName := c.Provisioner
		if provisionerName == "" {
			provisionerName = h.CA().Provisioner
		}
		renewDuration := "8760h"
		if prov, _ := appdb.GetCAProvisioner(h.db, provisionerName); prov != nil && durationExceedsMax(renewDuration, prov.MaxDuration) {
			renewDuration = prov.MaxDuration
		}
		purpose := certPurposeFromFile(c.CertPath)
		if err := h.issueWithRegisteredProvisioner(c.Domain, c.CertPath, c.KeyPath, renewDuration, keyType, purpose, provisionerName); err == nil {
			issued, expires, serial, _ := parseCertDates(c.CertPath)
			appdb.InsertCert(h.db, &models.Certificate{
				Name: c.Name, Domain: c.Domain, CertPath: c.CertPath, KeyPath: c.KeyPath,
				IssuedAt: issued, ExpiresAt: expires, Serial: serial, KeyType: keyType, Provisioner: provisionerName,
			})
			appdb.InsertHistory(h.db, "renew", c.Name, c.Domain, "Перевипуск, тип: "+keyType+", провізіонер: "+provisionerName, si.Username, si.Role)
			h.auditSecurity(r, fmt.Sprintf("certificate.renew id=%d name=%s domain=%s provisioner=%s", c.ID, c.Name, c.Domain, provisionerName))
			h.flash(w, r, "ok", "Сертифікат перевипущено")
		} else {
			h.notifyAsync("", "certificate.renew_failed", "error",
				"Certificate renew failed",
				fmt.Sprintf("Не вдалося перевипустити сертифікат %s для %s: %s", c.Name, c.Domain, err.Error()),
				map[string]string{"id": strconv.Itoa(c.ID), "name": c.Name, "domain": c.Domain, "key_type": keyType})
			h.flash(w, r, "err", "Помилка: "+err.Error())
		}
	}
	http.Redirect(w, r, "/certificates", http.StatusFound)
}

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/certificates") {
		return
	}
	si := h.sessionInfo(r)
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	c, _ := appdb.GetCert(h.db, id)
	if c != nil {
		h.revokeStep(c.CertPath, c.KeyPath)
		appdb.UpdateCertStatus(h.db, id, "revoked")
		appdb.InsertHistory(h.db, "revoke", c.Name, c.Domain, "Відкликано (CRL)", si.Username, si.Role)
		h.auditSecurity(r, fmt.Sprintf("certificate.revoke id=%d name=%s domain=%s serial=%s", c.ID, c.Name, c.Domain, c.Serial))
		h.flash(w, r, "ok", "Сертифікат відкликано")
	}
	http.Redirect(w, r, "/certificates", http.StatusFound)
}

func (h *Handler) DownloadCA(w http.ResponseWriter, r *http.Request) {
	ca := h.CA()
	h.serveCAFile(w, r, ca.RootCert, "home-ca-root.crt")
}

func (h *Handler) DownloadIntermediateCA(w http.ResponseWriter, r *http.Request) {
	h.serveCAFile(w, r, h.intermediateCertPath(), "home-ca-intermediate.crt")
}

func (h *Handler) DownloadFullChain(w http.ResponseWriter, r *http.Request) {
	intermediatePath := h.intermediateCertPath()
	intermediate, err := os.ReadFile(intermediatePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ca := h.CA()
	root, err := os.ReadFile(ca.RootCert)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var chain bytes.Buffer
	chain.Write(intermediate)
	if len(intermediate) > 0 && intermediate[len(intermediate)-1] != '\n' {
		chain.WriteByte('\n')
	}
	chain.Write(root)

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=home-ca-full-chain.crt")
	http.ServeContent(w, r, "home-ca-full-chain.crt", time.Now(), bytes.NewReader(chain.Bytes()))
}

func (h *Handler) intermediateCertPath() string {
	if h.resolver != nil {
		ca := h.resolver.Runtime()
		if ca.IntermediateCert != "" {
			return ca.IntermediateCert
		}
		if ca.RootCert != "" {
			return filepath.Join(filepath.Dir(ca.RootCert), "intermediate_ca.crt")
		}
	}
	if h.cfg.RootCert != "" {
		return filepath.Join(filepath.Dir(h.cfg.RootCert), "intermediate_ca.crt")
	}
	return ""
}

func (h *Handler) serveCAFile(w http.ResponseWriter, r *http.Request, path, filename string) {
	if _, err := os.Stat(path); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	http.ServeFile(w, r, path)
}

func (h *Handler) DownloadCert(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	c, _ := appdb.GetCert(h.db, id)
	if c == nil || c.CertPath == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.crt", sanitizeName(c.Name)))
	http.ServeFile(w, r, c.CertPath)
}

func (h *Handler) DownloadKey(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	c, _ := appdb.GetCert(h.db, id)
	if c == nil || c.KeyPath == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.key", sanitizeName(c.Name)))
	h.auditSecurity(r, fmt.Sprintf("certificate.key_download id=%d name=%s domain=%s", c.ID, c.Name, c.Domain))
	http.ServeFile(w, r, c.KeyPath)
}

func (h *Handler) ImportGet(w http.ResponseWriter, r *http.Request) {
	data := h.base(w, r, "import")
	data["Unregistered"] = scanExistingCerts(h.cfg.CertsDir, h.db)
	data["ActiveTab"] = r.URL.Query().Get("tab")
	h.render(w, "import", data)
}

func (h *Handler) ImportPost(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/import") {
		return
	}
	si := h.sessionInfo(r)
	switch r.FormValue("action") {
	case "upload":
		h.importUpload(w, r, si)
	case "scan":
		h.importScan(w, r, si)
	case "manual":
		h.importManual(w, r, si)
	default:
		http.Redirect(w, r, "/import", http.StatusFound)
	}
}

func (h *Handler) importUpload(w http.ResponseWriter, r *http.Request, si *models.SessionInfo) {
	r.ParseMultipartForm(10 << 20)
	name := trimStr(r.FormValue("name"))
	domain := trimStr(r.FormValue("domain"))
	data := h.base(w, r, "import")
	data["ActiveTab"] = "upload"
	certFile, _, err := r.FormFile("cert_file")
	if name == "" || domain == "" || err != nil {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Заповніть ім’я, домен і завантажте файл .crt"}}
		h.render(w, "import", data)
		return
	}
	defer certFile.Close()
	certDir := filepath.Join(h.cfg.CertsDir, sanitizeName(name))
	os.MkdirAll(certDir, 0755)
	certPath := filepath.Join(certDir, "certificate.crt")
	keyPath := filepath.Join(certDir, "private.key")
	if err := saveUploadedFile(certFile, certPath); err != nil {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Помилка збереження файлу"}}
		h.render(w, "import", data)
		return
	}
	if kf, _, err := r.FormFile("key_file"); err == nil {
		saveUploadedFile(kf, keyPath)
		kf.Close()
	} else {
		keyPath = ""
	}
	issued, expires, serial, err := parseCertDates(certPath)
	if err != nil || serial == "" {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Не вдалося прочитати сертифікат"}}
		h.render(w, "import", data)
		return
	}
	if keyPath != "" {
		cert, certErr := readPEMCert(certPath)
		if certErr != nil {
			os.Remove(keyPath)
			data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Не вдалося прочитати сертифікат"}}
			h.render(w, "import", data)
			return
		}
		if pairErr := validateKeyPair(cert, keyPath); pairErr != nil {
			os.Remove(keyPath)
			data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Приватний ключ не відповідає сертифікату: " + pairErr.Error()}}
			h.render(w, "import", data)
			return
		}
	}
	kt := getCertKeyType(certPath)
	if err := appdb.InsertCert(h.db, &models.Certificate{
		Name: name, Domain: domain, CertPath: certPath, KeyPath: keyPath,
		IssuedAt: issued, ExpiresAt: expires, Serial: serial, KeyType: kt,
	}); err != nil {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Сертифікат уже є в базі"}}
		h.render(w, "import", data)
		return
	}
	appdb.InsertHistory(h.db, "import", name, domain, "Завантаження з ПК, тип: "+kt, si.Username, si.Role)
	h.flash(w, r, "ok", fmt.Sprintf("Сертифікат %s завантажено!", name))
	http.Redirect(w, r, "/import?tab=upload", http.StatusFound)
}

func (h *Handler) importScan(w http.ResponseWriter, r *http.Request, si *models.SessionInfo) {
	count := 0
	for _, item := range scanExistingCerts(h.cfg.CertsDir, h.db) {
		issued, expires, serial, err := parseCertDates(item["cert_path"])
		if err != nil {
			continue
		}
		kt := getCertKeyType(item["cert_path"])
		if appdb.InsertCert(h.db, &models.Certificate{
			Name: item["name"], Domain: item["name"],
			CertPath: item["cert_path"], KeyPath: item["key_path"],
			IssuedAt: issued, ExpiresAt: expires, Serial: serial, KeyType: kt,
		}) == nil {
			appdb.InsertHistory(h.db, "import", item["name"], item["name"], "Сканування сервера", si.Username, si.Role)
			count++
		}
	}
	if count > 0 {
		h.flash(w, r, "ok", fmt.Sprintf("Знайдено й імпортовано: %d", count))
	} else {
		h.flash(w, r, "ok", "Нових сертифікатів не знайдено")
	}
	http.Redirect(w, r, "/import?tab=scan", http.StatusFound)
}

func (h *Handler) importManual(w http.ResponseWriter, r *http.Request, si *models.SessionInfo) {
	name := trimStr(r.FormValue("name"))
	domain := trimStr(r.FormValue("domain"))
	certPath := trimStr(r.FormValue("cert_path"))
	keyPath := trimStr(r.FormValue("key_path"))
	data := h.base(w, r, "import")
	data["ActiveTab"] = "manual"
	if name == "" || domain == "" || certPath == "" {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Заповніть усі поля"}}
		h.render(w, "import", data)
		return
	}
	if _, err := os.Stat(certPath); err != nil {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Файл не знайдено: " + certPath}}
		h.render(w, "import", data)
		return
	}
	if keyPath != "" {
		cert, certErr := readPEMCert(certPath)
		if certErr != nil {
			data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Не вдалося прочитати сертифікат"}}
			h.render(w, "import", data)
			return
		}
		if pairErr := validateKeyPair(cert, keyPath); pairErr != nil {
			data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Приватний ключ не відповідає сертифікату: " + pairErr.Error()}}
			h.render(w, "import", data)
			return
		}
	}
	issued, expires, serial, _ := parseCertDates(certPath)
	kt := getCertKeyType(certPath)
	if err := appdb.InsertCert(h.db, &models.Certificate{
		Name: name, Domain: domain, CertPath: certPath, KeyPath: keyPath,
		IssuedAt: issued, ExpiresAt: expires, Serial: serial, KeyType: kt,
	}); err != nil {
		data["Msgs"] = []models.FlashMsg{{Type: "err", Text: "Уже в базі"}}
		h.render(w, "import", data)
		return
	}
	appdb.InsertHistory(h.db, "import", name, domain, "Шлях вручну", si.Username, si.Role)
	h.flash(w, r, "ok", fmt.Sprintf("Сертифікат %s імпортовано", name))
	http.Redirect(w, r, "/import?tab=manual", http.StatusFound)
}

func (h *Handler) APIStatus(w http.ResponseWriter, r *http.Request) {
	certs, _ := appdb.GetCerts(h.db, "active")
	type exp struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
		Days   int    `json:"days"`
	}
	var expiring []exp
	for _, c := range certs {
		if d := daysLeftVal(c.ExpiresAt); d <= 30 {
			expiring = append(expiring, exp{c.Name, c.Domain, d})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total": len(certs), "expiring_soon": expiring,
	})
}

type issueProvisionerOption struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	DefaultDuration string `json:"default_duration"`
	MaxDuration     string `json:"max_duration"`
	IsSystem        bool   `json:"is_system"`
}

func (h *Handler) attachIssueProvisioners(data map[string]interface{}) {
	list, err := appdb.ListCAProvisioners(h.db)
	if err != nil {
		list = nil
	}
	opts := make([]issueProvisionerOption, 0, len(list))
	selected := h.CA().Provisioner
	for _, p := range list {
		opts = append(opts, issueProvisionerOption{
			Name:            p.Name,
			Type:            p.Type,
			DefaultDuration: p.DefaultDuration,
			MaxDuration:     p.MaxDuration,
			IsSystem:        p.IsSystem,
		})
		if p.IsSystem {
			selected = p.Name
		}
	}
	if selected == "" && len(opts) > 0 {
		selected = opts[0].Name
	}
	raw, _ := json.Marshal(opts)
	data["RegisteredProvisioners"] = opts
	data["SelectedProvisioner"] = selected
	data["ProvisionersJSON"] = template.JS(raw)
}
