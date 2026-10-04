package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func testCertDER(t *testing.T, serial int64, notBefore, notAfter time.Time, dnsNames ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "cn.example.lan"},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseCACert(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	data := []byte(`{"provisioner":{"id":"x","name":"acme","type":"ACME"}}`)

	t.Run("active", func(t *testing.T) {
		der := testCertDER(t, 255, now.AddDate(0, 0, -1), now.AddDate(0, 0, 60), "git.example.lan", "www.example.lan")
		c, err := parseCACert("255", der, data, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if c.Status != "active" || c.SerialHex != "FF" || c.Provisioner != "acme" || c.ProvisionerType != "ACME" {
			t.Errorf("unexpected %+v", c)
		}
		if len(c.Names) != 2 || c.Names[0] != "git.example.lan" {
			t.Errorf("names = %v", c.Names)
		}
	})

	t.Run("expiring, no SAN, no data", func(t *testing.T) {
		der := testCertDER(t, 2, now.AddDate(0, 0, -60), now.AddDate(0, 0, 10))
		c, err := parseCACert("2", der, nil, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if c.Status != "expiring" || c.Provisioner != "" || len(c.Names) != 1 || c.Names[0] != "cn.example.lan" {
			t.Errorf("unexpected %+v", c)
		}
	})

	t.Run("expired", func(t *testing.T) {
		der := testCertDER(t, 3, now.AddDate(0, 0, -10), now.AddDate(0, 0, -1), "old.example.lan")
		c, _ := parseCACert("3", der, data, nil, now)
		if c.Status != "expired" {
			t.Errorf("status = %s", c.Status)
		}
	})

	t.Run("revoked wins over expired", func(t *testing.T) {
		der := testCertDER(t, 4, now.AddDate(0, 0, -10), now.AddDate(0, 0, -1), "rev.example.lan")
		revoked := []byte(`{"Serial":"4","ReasonCode":1,"Reason":"key compromise","RevokedAt":"2026-10-01T10:00:00Z"}`)
		c, _ := parseCACert("4", der, data, revoked, now)
		if c.Status != "revoked" || c.RevokedReason != "key compromise" || c.RevokedAt == nil || c.RevokedAt.Day() != 1 {
			t.Errorf("unexpected %+v", c)
		}
	})

	t.Run("broken DER", func(t *testing.T) {
		if _, err := parseCACert("5", []byte("nope"), nil, nil, now); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestSafeFileName(t *testing.T) {
	for in, want := range map[string]string{
		"git.example.lan":      "git.example.lan",
		"*.example.lan":        "wildcard.example.lan",
		"../../etc/passwd":     "etc_passwd",
		"name with \"quotes\"": "name_with_quotes",
		"":                     "certificate",
	} {
		if got := safeFileName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReissueURL(t *testing.T) {
	if u := reissueURL(CACert{ProvisionerType: "ACME", Names: []string{"git.example.lan"}}); u != "" {
		t.Errorf("ACME certificate must not be reissued from the UI: %s", u)
	}
	u := reissueURL(CACert{ProvisionerType: "JWK", Names: []string{"mail.example.lan", "imap.example.lan", "smtp.example.lan"}})
	want := "/issue?domain=mail.example.lan&name=mail.example.lan&sans=imap.example.lan%2C+smtp.example.lan"
	if u != want {
		t.Errorf("reissueURL = %s, want %s", u, want)
	}
}
