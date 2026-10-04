package handlers

// All certificates issued by step-ca, read from the CA's own database (CA_DB_URL, a read-only role).
// step-ca keeps every certificate it signs - ACME, CLI, this UI - in x509_certs, the provisioner in
// x509_certs_data and revocations in revoked_x509_certs. Each table is a key/value pair: nkey is the
// decimal serial number, nvalue the DER certificate or a JSON document.

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	appdb "step-ui/db"
)

// CACert is one certificate from the CA database
type CACert struct {
	Serial          string
	SerialHex       string
	CommonName      string
	Names           []string
	NotBefore       time.Time
	NotAfter        time.Time
	Provisioner     string
	ProvisionerType string
	Status          string // active, expiring (30 days or less), expired, revoked
	RevokedAt       *time.Time
	RevokedReason   string
	UIID            int // the certificate in this UI's accounting, 0 if it is not there
}

const caCertsQuery = `SELECT c.nkey, c.nvalue, d.nvalue, r.nvalue FROM x509_certs c
	LEFT JOIN x509_certs_data d ON d.nkey = c.nkey
	LEFT JOIN revoked_x509_certs r ON r.nkey = c.nkey`

var caSerialRe = regexp.MustCompile(`^[0-9]{1,80}$`)

// openCADB opens the CA database lazily: the UI starts and works without it
func openCADB(dsn string) *sql.DB {
	if dsn == "" {
		return nil
	}
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Printf("[ca-db] cannot open the CA database: %v", err)
		return nil
	}
	conn.SetMaxOpenConns(2)
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(5 * time.Minute)
	return conn
}

// parseCACert builds a CACert from the columns of one x509_certs row (data and revoked may be nil)
func parseCACert(serial string, der, data, revoked []byte, now time.Time) (CACert, error) {
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return CACert{}, fmt.Errorf("certificate %s: %w", serial, err)
	}
	c := CACert{
		Serial:     serial,
		SerialHex:  strings.ToUpper(crt.SerialNumber.Text(16)),
		CommonName: crt.Subject.CommonName,
		NotBefore:  crt.NotBefore,
		NotAfter:   crt.NotAfter,
	}
	c.Names = append(c.Names, crt.DNSNames...)
	for _, ip := range crt.IPAddresses {
		c.Names = append(c.Names, ip.String())
	}
	c.Names = append(c.Names, crt.EmailAddresses...)
	for _, u := range crt.URIs {
		c.Names = append(c.Names, u.String())
	}
	if len(c.Names) == 0 && c.CommonName != "" {
		c.Names = []string{c.CommonName}
	}

	if len(data) > 0 {
		var d struct {
			Provisioner *struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"provisioner"`
		}
		if json.Unmarshal(data, &d) == nil && d.Provisioner != nil {
			c.Provisioner, c.ProvisionerType = d.Provisioner.Name, d.Provisioner.Type
		}
	}

	switch {
	case len(revoked) > 0:
		c.Status = "revoked"
		// step-ca stores db.RevokedCertificateInfo without JSON tags
		var r struct {
			Reason    string
			RevokedAt time.Time
		}
		if json.Unmarshal(revoked, &r) == nil {
			c.RevokedReason = r.Reason
			if !r.RevokedAt.IsZero() {
				c.RevokedAt = &r.RevokedAt
			}
		}
	case now.After(c.NotAfter):
		c.Status = "expired"
	case c.NotAfter.Sub(now) <= 30*24*time.Hour:
		c.Status = "expiring"
	default:
		c.Status = "active"
	}
	return c, nil
}

// loadCACerts reads every certificate of the CA database, newest first
func (h *Handler) loadCACerts(ctx context.Context) ([]CACert, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := h.caDB.QueryContext(ctx, caCertsQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now()
	var certs []CACert
	for rows.Next() {
		var key, der, data, revoked []byte
		if err := rows.Scan(&key, &der, &data, &revoked); err != nil {
			return nil, err
		}
		c, err := parseCACert(string(key), der, data, revoked, now)
		if err != nil {
			log.Printf("[ca-db] skipping %v", err)
			continue
		}
		certs = append(certs, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].NotBefore.After(certs[j].NotBefore) })
	return certs, nil
}

func (h *Handler) AdminCACertsGet(w http.ResponseWriter, r *http.Request) {
	data := h.base(w, r, "admin_ca_certs")
	if h.caDB == nil {
		data["NotConfigured"] = true
		h.render(w, "admin_ca_certs", data)
		return
	}
	certs, err := h.loadCACerts(r.Context())
	if err != nil {
		log.Printf("[ca-db] %v", err)
		data["LoadError"] = true
		h.render(w, "admin_ca_certs", data)
		return
	}

	inUI := map[string]int{}
	if uiCerts, err := appdb.GetCerts(h.db, ""); err == nil {
		for _, c := range uiCerts {
			if c.Serial != "" {
				inUI[c.Serial] = c.ID
			}
		}
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	var provisioners []string
	for i := range certs {
		certs[i].UIID = inUI[certs[i].Serial]
		counts[certs[i].Status]++
		if p := certs[i].Provisioner; p != "" && !seen[p] {
			seen[p] = true
			provisioners = append(provisioners, p)
		}
	}
	sort.Strings(provisioners)

	data["Certs"] = certs
	data["Counts"] = counts
	data["Provisioners"] = provisioners
	h.render(w, "admin_ca_certs", data)
}

// AdminCACertDownload returns one certificate of the CA database as PEM (the CA never has the private key)
func (h *Handler) AdminCACertDownload(w http.ResponseWriter, r *http.Request) {
	serial := chi.URLParam(r, "serial")
	if h.caDB == nil || !caSerialRe.MatchString(serial) {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var der []byte
	err := h.caDB.QueryRowContext(ctx, `SELECT nvalue FROM x509_certs WHERE nkey = $1`, []byte(serial)).Scan(&der)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("[ca-db] %v", err)
		http.Error(w, "CA database error", http.StatusBadGateway)
		return
	}

	name := serial
	if crt, err := x509.ParseCertificate(der); err == nil && crt.Subject.CommonName != "" {
		name = safeFileName(crt.Subject.CommonName)
	}
	h.auditSecurity(r, "ca_cert.download serial="+serial)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.crt"`, name))
	_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeFileName(s string) string {
	s = strings.Trim(unsafeFileChars.ReplaceAllString(strings.ReplaceAll(s, "*", "wildcard"), "_"), "._")
	if s == "" {
		return "certificate"
	}
	return s
}
