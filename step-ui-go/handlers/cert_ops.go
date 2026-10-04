package handlers

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	appdb "step-ui/db"
	"step-ui/models"
	"step-ui/security"
)

type IssuePolicy struct {
	Template string
	Duration string
	KeyType  string
	// Purpose is passed to step-ca as the template data variable x509Purpose
	// and sets extKeyUsage of the issued certificate.
	Purpose string
}

// Allowed values of x509Purpose. The provisioner template (see provisioner.sh)
// expands them to extKeyUsage: server -> serverAuth, client -> clientAuth,
// internal -> serverAuth + clientAuth.
const (
	purposeServer   = "server"
	purposeClient   = "client"
	purposeInternal = "internal"
)

var issueTemplates = map[string]IssuePolicy{
	"server":   {Template: "server", Duration: "8760h", KeyType: "EC:P-256", Purpose: purposeServer},
	"internal": {Template: "internal", Duration: "87600h", KeyType: "EC:P-256", Purpose: purposeInternal},
	"wildcard": {Template: "wildcard", Duration: "8760h", KeyType: "EC:P-256", Purpose: purposeServer},
	"client":   {Template: "client", Duration: "8760h", KeyType: "EC:P-256", Purpose: purposeClient},
}

var allowedIssueDurations = map[string]bool{
	"720h": true, "4380h": true, "8760h": true, "87600h": true,
}

var allowedIssueKeyTypes = map[string]bool{
	"EC:P-256": true, "EC:P-384": true, "RSA:2048": true, "RSA:4096": true,
}

func normalizeIssuePolicy(template, duration, keyType, domain string) (IssuePolicy, error) {
	template = strings.TrimSpace(strings.ToLower(template))
	if template == "" {
		template = "server"
	}
	policy, ok := issueTemplates[template]
	if !ok {
		return IssuePolicy{}, fmt.Errorf("unknown certificate template: %s", template)
	}
	if allowedIssueDurations[duration] {
		policy.Duration = duration
	}
	if allowedIssueKeyTypes[keyType] {
		policy.KeyType = keyType
	}
	if policy.Template == "wildcard" && !strings.HasPrefix(strings.TrimSpace(domain), "*.") {
		return IssuePolicy{}, fmt.Errorf("wildcard template requires domain like *.example.com")
	}
	return policy, nil
}

func decryptProvisionerPassword(encrypted, secretKey string) (string, error) {
	return security.DecryptSecret(encrypted, secretKey)
}

func durationExceedsMax(requested, maxDur string) bool {
	return appdb.DurationExceedsMax(requested, maxDur)
}

func (h *Handler) issueCert(domain string, sans []string, certPath, keyPath, duration, keyType, purpose, provisioner, passwordFile string) error {
	ca := h.CA()
	if !ca.Configured {
		return fmt.Errorf("Step-CA не налаштовано. Налаштуйте підключення в розділі Адмін -> Налаштування CA (/admin/ca)")
	}
	if provisioner == "" {
		provisioner = ca.Provisioner
	}
	if passwordFile == "" {
		passwordFile = ca.PasswordFile
	}
	args := stepCertificateArgs(ca.URL, ca.RootCert, provisioner, passwordFile, duration, keyType, purpose, domain, sans, certPath, keyPath)
	log.Printf("[step-cli] step %s", strings.Join(args, " "))
	cmd := exec.Command("step", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

func stepCertificateArgs(caURL, rootCert, provisioner, passwordFile, duration, keyType, purpose, domain string, sans []string, certPath, keyPath string) []string {
	args := []string{
		"ca", "certificate",
		"--ca-url", caURL,
		"--root", rootCert,
		"--provisioner", provisioner,
		"--provisioner-password-file", passwordFile,
		"--not-after", duration,
		"--force",
	}
	if purpose != "" {
		args = append(args, "--set", "x509Purpose="+purpose)
	}
	if strings.HasPrefix(keyType, "EC:") {
		args = append(args, "--kty", "EC", "--curve", strings.TrimPrefix(keyType, "EC:"))
	} else if strings.HasPrefix(keyType, "RSA:") {
		args = append(args, "--kty", "RSA", "--size", strings.TrimPrefix(keyType, "RSA:"))
	}
	if len(sans) > 0 {
		// With --san the certificate gets exactly these names, so the main domain is listed too
		for _, name := range append([]string{domain}, sans...) {
			args = append(args, "--san", name)
		}
	}
	return append(args, domain, certPath, keyPath)
}

var sanNameRe = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// parseSANs splits additional names (separated by commas, semicolons or spaces), dropping repeats and the
// main domain; on an invalid name it returns that name
func parseSANs(raw, domain string) (sans []string, invalid string) {
	seen := map[string]bool{strings.ToLower(strings.TrimSpace(domain)): true}
	for _, name := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || unicode.IsSpace(r) }) {
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		if net.ParseIP(name) == nil && !sanNameRe.MatchString(name) {
			return nil, name
		}
		seen[key] = true
		sans = append(sans, name)
	}
	return sans, ""
}

// certExtraNames returns the names of an existing certificate besides the main domain, so that reissuing
// keeps all of them
func certExtraNames(certPath, domain string) []string {
	cert, err := readPEMCert(certPath)
	if err != nil {
		return nil
	}
	names := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	sans, _ := parseSANs(strings.Join(names, ","), domain)
	return sans
}

// revokeBySerial revokes any certificate of the CA by its decimal serial number. step ca revoke takes no
// provisioner: the request is authorised by a revoke token of the UI's JWK provisioner (step-ca lets any
// JWK provisioner revoke any certificate).
func (h *Handler) revokeBySerial(serial, reason string) error {
	ca := h.CA()
	if !ca.Configured {
		return fmt.Errorf("Step-CA не налаштовано")
	}
	var stderr bytes.Buffer
	tokenCmd := exec.Command("step", "ca", "token", serial, "--revoke",
		"--provisioner", ca.Provisioner, "--provisioner-password-file", ca.PasswordFile,
		"--ca-url", ca.URL, "--root", ca.RootCert)
	tokenCmd.Stderr = &stderr
	token, err := tokenCmd.Output()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	args := []string{"ca", "revoke", serial, "--token", strings.TrimSpace(string(token)), "--ca-url", ca.URL, "--root", ca.RootCert}
	if reason != "" {
		args = append(args, "--reason", reason)
	}
	if out, err := exec.Command("step", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (h *Handler) issueWithRegisteredProvisioner(domain string, sans []string, certPath, keyPath, duration, keyType, purpose, provisionerName string) error {
	ca := h.CA()
	if provisionerName == "" {
		provisionerName = ca.Provisioner
	}
	prov, err := appdb.GetCAProvisioner(h.db, provisionerName)
	if err != nil {
		return err
	}
	if prov == nil {
		return fmt.Errorf("провізіонер %s не зареєстровано в UI", provisionerName)
	}
	if durationExceedsMax(duration, prov.MaxDuration) {
		return fmt.Errorf("строк %s перевищує максимум провізіонера %s (%s)", duration, prov.Name, prov.MaxDuration)
	}
	passwordFile := ca.PasswordFile
	if prov.EncryptedPassword != "" {
		plain, decErr := decryptProvisionerPassword(prov.EncryptedPassword, h.cfg.SecretKey)
		if decErr != nil {
			return fmt.Errorf("не вдалося розшифрувати пароль провізіонера")
		}
		tmp, writeErr := os.CreateTemp("/opt/step-ui/data", "prov-*.pw")
		if writeErr != nil {
			tmp, writeErr = os.CreateTemp("", "prov-*.pw")
		}
		if writeErr != nil {
			return writeErr
		}
		passwordFile = tmp.Name()
		defer os.Remove(passwordFile)
		if _, err := tmp.WriteString(plain); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Chmod(0600); err != nil {
			tmp.Close()
			return err
		}
		tmp.Close()
	} else if !prov.IsSystem && provisionerName != ca.Provisioner {
		return fmt.Errorf("для провізіонера %s не задано пароль", provisionerName)
	}
	return h.issueCert(domain, sans, certPath, keyPath, duration, keyType, purpose, prov.Name, passwordFile)
}

// certPurposeFromFile derives x509Purpose from extKeyUsage of an existing
// certificate so that reissuing keeps the original purpose.
func certPurposeFromFile(certPath string) string {
	cert, err := readPEMCert(certPath)
	if err != nil {
		return purposeServer
	}
	server, client := false, false
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			server = true
		case x509.ExtKeyUsageClientAuth:
			client = true
		}
	}
	switch {
	case server && client:
		return purposeInternal
	case client:
		return purposeClient
	default:
		return purposeServer
	}
}

func (h *Handler) revokeStep(certPath, keyPath string) {
	ca := h.CA()
	if !ca.Configured {
		log.Printf("[step-cli] revoke skipped: CA not configured")
		return
	}
	exec.Command("step", "ca", "revoke",
		"--cert", certPath,
		"--key", keyPath,
		"--ca-url", ca.URL,
		"--root", ca.RootCert,
	).Run()
}

func parseCertDates(certPath string) (issued, expires *time.Time, serial string, err error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		err = fmt.Errorf("no PEM block found")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	i := cert.NotBefore
	e := cert.NotAfter
	issued = &i
	expires = &e
	serial = cert.SerialNumber.String()
	return
}

func getCertKeyType(certPath string) string {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	switch cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		return "EC"
	case x509.RSA:
		return "RSA"
	default:
		return "Unknown"
	}
}

func scanExistingCerts(certsDir string, d *sql.DB) []map[string]string {
	var found []map[string]string
	filepath.WalkDir(certsDir, func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, "certificate.crt") {
			dir := filepath.Dir(path)
			name := filepath.Base(dir)
			keyPath := filepath.Join(dir, "private.key")
			if _, e := os.Stat(keyPath); e != nil {
				keyPath = ""
			}
			// Check whether it is already in the database
			_, _, serial, e := parseCertDates(path)
			if e != nil || serial == "" {
				return nil
			}
			c, _ := appdb.GetCertBySerial(d, serial)
			if c == nil {
				found = append(found, map[string]string{
					"name": name, "cert_path": path, "key_path": keyPath,
				})
			}
		}
		return nil
	})
	return found
}

func sanitizeName(name string) string {
	replacer := strings.NewReplacer(
		" ", "_", "/", "_", "\\", "_",
		"..", "_", "<", "_", ">", "_",
	)
	return replacer.Replace(name)
}

func saveUploadedFile(file multipart.File, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, file)
	return err
}

func trimStr(s string) string {
	return strings.TrimSpace(s)
}

func daysLeftVal(t *time.Time) int {
	if t == nil {
		return 999
	}
	return int(time.Until(*t).Hours() / 24)
}

// GetCertBySerial wrapper needed in db
var _ = (*models.Certificate)(nil)
