package handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	appdb "step-ui/db"
	"step-ui/models"
)

const pkcs12Timeout = 15 * time.Second

// DownloadBundle serves ready-made sets of certificate files.
// format=fullchain — leaf + intermediate + root in one PEM (nginx/traefik).
// format=zip — archive with the certificate, key, full chain and root CA.
func (h *Handler) DownloadBundle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	c, _ := appdb.GetCert(h.db, id)
	if c == nil || c.CertPath == "" {
		http.NotFound(w, r)
		return
	}

	switch r.URL.Query().Get("format") {
	case "fullchain":
		h.serveFullChainBundle(w, r, c)
	case "zip":
		h.serveZipBundle(w, r, c)
	default:
		http.Error(w, "unknown bundle format", http.StatusBadRequest)
	}
}

// DownloadBundlePKCS12 builds a .p12 with openssl. The password comes from a form,
// so the route requires POST and a CSRF token.
func (h *Handler) DownloadBundlePKCS12(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	redirectTo := fmt.Sprintf("/certificates/%d", id)
	if !h.requireCSRF(w, r, redirectTo) {
		return
	}
	c, _ := appdb.GetCert(h.db, id)
	if c == nil || c.CertPath == "" {
		http.NotFound(w, r)
		return
	}
	if c.KeyPath == "" {
		h.flash(w, r, "err", "Для PKCS#12 потрібен приватний ключ, а його не збережено в UI")
		http.Redirect(w, r, redirectTo, http.StatusSeeOther)
		return
	}

	password := r.FormValue("p12_password")
	chain, err := h.caChainPEM()
	if err != nil {
		h.flash(w, r, "err", "Не вдалося прочитати ланцюжок CA: "+err.Error())
		http.Redirect(w, r, redirectTo, http.StatusSeeOther)
		return
	}

	bundle, err := h.buildPKCS12(r.Context(), c, chain, password)
	if err != nil {
		h.flash(w, r, "err", "Не вдалося зібрати PKCS#12: "+err.Error())
		http.Redirect(w, r, redirectTo, http.StatusSeeOther)
		return
	}

	h.auditSecurity(r, fmt.Sprintf("certificate.bundle_download id=%d name=%s format=pkcs12 encrypted=%t",
		c.ID, c.Name, password != ""))
	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.p12"`, sanitizeName(c.Name)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, sanitizeName(c.Name)+".p12", time.Now(), bytes.NewReader(bundle))
}

func (h *Handler) serveFullChainBundle(w http.ResponseWriter, r *http.Request, c *models.Certificate) {
	leaf, err := os.ReadFile(c.CertPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	chain, err := h.caChainPEM()
	if err != nil {
		http.Error(w, "CA chain is not available", http.StatusServiceUnavailable)
		return
	}

	var out bytes.Buffer
	writePEMBlock(&out, leaf)
	out.Write(chain)

	filename := sanitizeName(c.Name) + "-fullchain.pem"
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	http.ServeContent(w, r, filename, time.Now(), bytes.NewReader(out.Bytes()))
}

func (h *Handler) serveZipBundle(w http.ResponseWriter, r *http.Request, c *models.Certificate) {
	leaf, err := os.ReadFile(c.CertPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	chain, chainErr := h.caChainPEM()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, content []byte) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write(content)
		return err
	}

	if err := add("certificate.crt", leaf); err != nil {
		http.Error(w, "bundle build failed", http.StatusInternalServerError)
		return
	}
	hasKey := false
	if c.KeyPath != "" {
		if key, err := os.ReadFile(c.KeyPath); err == nil {
			_ = add("private.key", key)
			hasKey = true
		}
	}
	if chainErr == nil {
		var fullchain bytes.Buffer
		writePEMBlock(&fullchain, leaf)
		fullchain.Write(chain)
		_ = add("fullchain.pem", fullchain.Bytes())
		_ = add("ca-chain.pem", chain)
	}
	_ = add("README.txt", []byte(bundleReadme(c, hasKey, chainErr == nil)))

	if err := zw.Close(); err != nil {
		http.Error(w, "bundle build failed", http.StatusInternalServerError)
		return
	}

	h.auditSecurity(r, fmt.Sprintf("certificate.bundle_download id=%d name=%s format=zip with_key=%t",
		c.ID, c.Name, hasKey))
	filename := sanitizeName(c.Name) + "-bundle.zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, filename, time.Now(), bytes.NewReader(buf.Bytes()))
}

// caChainPEM returns intermediate + root in PEM.
func (h *Handler) caChainPEM() ([]byte, error) {
	intermediate, err := os.ReadFile(h.intermediateCertPath())
	if err != nil {
		return nil, err
	}
	root, err := os.ReadFile(h.CA().RootCert)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	writePEMBlock(&out, intermediate)
	writePEMBlock(&out, root)
	return out.Bytes(), nil
}

func (h *Handler) buildPKCS12(ctx context.Context, c *models.Certificate, chain []byte, password string) ([]byte, error) {
	tmp, err := os.MkdirTemp("", "step-ui-p12-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	chainPath := filepath.Join(tmp, "ca-chain.pem")
	if err := os.WriteFile(chainPath, chain, 0600); err != nil {
		return nil, err
	}
	outPath := filepath.Join(tmp, "bundle.p12")

	cctx, cancel := context.WithTimeout(ctx, pkcs12Timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "openssl", "pkcs12", "-export",
		"-in", c.CertPath,
		"-inkey", c.KeyPath,
		"-certfile", chainPath,
		"-name", c.Name,
		"-passout", "env:STEP_UI_P12_PASS",
		"-out", outPath,
	)
	// The password is passed in the environment to keep it out of argv and process logs.
	cmd.Env = append(os.Environ(), "STEP_UI_P12_PASS="+password)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("openssl: %s", strings.TrimSpace(string(out)))
	}
	return os.ReadFile(outPath)
}

func writePEMBlock(buf *bytes.Buffer, pem []byte) {
	buf.Write(pem)
	if len(pem) > 0 && pem[len(pem)-1] != '\n' {
		buf.WriteByte('\n')
	}
}

func bundleReadme(c *models.Certificate, hasKey, hasChain bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Step-CA UI bundle\n")
	fmt.Fprintf(&b, "Сертифікат: %s\n", c.Name)
	fmt.Fprintf(&b, "Домен: %s\n", c.Domain)
	fmt.Fprintf(&b, "Серійний номер: %s\n\n", c.Serial)
	b.WriteString("certificate.crt — лише кінцевий (leaf) сертифікат\n")
	if hasChain {
		b.WriteString("fullchain.pem  — leaf + intermediate + root (nginx ssl_certificate)\n")
		b.WriteString("ca-chain.pem   — intermediate + root (ssl_trusted_certificate)\n")
	}
	if hasKey {
		b.WriteString("private.key    — приватний ключ, зберігайте як секрет (chmod 600)\n")
	}
	return b.String()
}
