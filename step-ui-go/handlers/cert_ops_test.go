package handlers

import (
	"strings"
	"testing"
)

func TestNormalizeIssuePolicy(t *testing.T) {
	t.Parallel()
	p, err := normalizeIssuePolicy("server", "720h", "EC:P-256", "app.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Duration != "720h" || p.Template != "server" || p.Purpose != purposeServer {
		t.Fatalf("unexpected policy: %+v", p)
	}
	if _, err := normalizeIssuePolicy("wildcard", "8760h", "EC:P-256", "example.com"); err == nil {
		t.Fatal("wildcard without *. prefix must fail")
	}
	client, err := normalizeIssuePolicy("client", "8760h", "EC:P-256", "client-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.Purpose != purposeClient {
		t.Fatalf("client template must request clientAuth: %+v", client)
	}
	internal, err := normalizeIssuePolicy("internal", "87600h", "EC:P-256", "svc.home.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if internal.Purpose != purposeInternal {
		t.Fatalf("internal template must request serverAuth+clientAuth: %+v", internal)
	}
}

func TestDurationExceedsMaxForIssue(t *testing.T) {
	t.Parallel()
	if !durationExceedsMax("87600h", "4380h") {
		t.Fatal("internal 10y must be rejected against web max 4380h")
	}
	if durationExceedsMax("720h", "4380h") {
		t.Fatal("720h must be allowed against 4380h")
	}
}

func TestStepCertificateArgsUsesPasswordFile(t *testing.T) {
	t.Parallel()
	args := stepCertificateArgs("https://step-ca:9443", "/root.crt", "web", "/tmp/web.pw", "720h", "EC:P-256", purposeClient, "app.local", nil, "/c.crt", "/c.key")
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "secret-password") {
		t.Fatal("password must not appear in step argv")
	}
	if !containsPair(args, "--provisioner", "web") {
		t.Fatalf("expected --provisioner web in %v", args)
	}
	if !containsPair(args, "--provisioner-password-file", "/tmp/web.pw") {
		t.Fatalf("expected password file flag in %v", args)
	}
	if !containsPair(args, "--set", "x509Purpose=client") {
		t.Fatalf("expected x509Purpose template data in %v", args)
	}
}

func containsPair(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func TestParseSANs(t *testing.T) {
	t.Parallel()
	sans, bad := parseSANs("imap.example.lan, smtp.example.lan;MAIL.example.lan  10.0.0.5\nimap.example.lan", "mail.example.lan")
	if bad != "" || strings.Join(sans, " ") != "imap.example.lan smtp.example.lan 10.0.0.5" {
		t.Fatalf("parseSANs = %v, %q", sans, bad)
	}
	if _, bad := parseSANs("ok.example.lan, --flag", "a.example.lan"); bad != "--flag" {
		t.Fatalf("expected --flag to be rejected, got %q", bad)
	}
	if sans, bad := parseSANs("  ", "a.example.lan"); bad != "" || sans != nil {
		t.Fatalf("empty input: %v, %q", sans, bad)
	}
}

func TestStepCertificateArgsSANs(t *testing.T) {
	t.Parallel()
	args := stepCertificateArgs("https://ca", "/root.crt", "ui", "/pw", "720h", "EC:P-256", purposeServer, "mail.local", []string{"imap.local"}, "/c.crt", "/c.key")
	if !containsPair(args, "--san", "mail.local") || !containsPair(args, "--san", "imap.local") {
		t.Fatalf("expected --san for the main domain and the extra name in %v", args)
	}
	if got := args[len(args)-3:]; got[0] != "mail.local" || got[1] != "/c.crt" || got[2] != "/c.key" {
		t.Fatalf("positional arguments: %v", got)
	}
	if args := stepCertificateArgs("https://ca", "/root.crt", "ui", "/pw", "720h", "EC:P-256", purposeServer, "a.local", nil, "/c.crt", "/c.key"); strings.Contains(strings.Join(args, " "), "--san") {
		t.Fatalf("no --san expected without extra names: %v", args)
	}
}
