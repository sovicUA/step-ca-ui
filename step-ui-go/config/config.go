package config

import (
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL   string
	CAURL         string
	RootCert      string
	Provisioner   string
	PasswordFile  string
	StepCAImage   string
	SecretKey     string
	SessionSecure bool
	EnableHSTS    bool
	Port          int
	CertsDir      string
	UploadDir     string
	SSLCert       string
	SSLKey        string
	CAMode        string
	CAHostPath    string
	// MetricsToken enables /metrics. Empty value - endpoint disabled.
	MetricsToken string
	// CADatabaseURL is the step-ca database (PostgreSQL, a read-only role) for the list of all issued
	// certificates. Empty value - the page says it is not configured.
	CADatabaseURL string
}

func Load() *Config {
	port, _ := strconv.Atoi(getEnv("PORT", "8443"))
	return &Config{
		DatabaseURL:   getEnv("DATABASE_URL", "postgres://stepui:stepui@postgres:5432/stepui?sslmode=disable"),
		CAURL:         getEnv("CA_URL", "https://step-ca:9443"),
		RootCert:      getEnv("ROOT_CERT", "/home/step/certs/root_ca.crt"),
		Provisioner:   getEnv("PROVISIONER", "admin"),
		PasswordFile:  getEnv("PASSWORD_FILE", "/opt/step-ui/data/provisioner_password"),
		StepCAImage:   getEnv("STEP_CA_IMAGE", "smallstep/step-ca:0.30.2"),
		SecretKey:     getEnv("SECRET_KEY", "change-me-in-production-32chars!"),
		SessionSecure: getEnvBool("SESSION_SECURE", true),
		EnableHSTS:    getEnvBool("ENABLE_HSTS", false),
		Port:          port,
		CertsDir:      "/opt/step-ui/certs",
		UploadDir:     "/opt/step-ui/uploads",
		SSLCert:       "/opt/step-ui/ssl/server.crt",
		SSLKey:        "/opt/step-ui/ssl/server.key",
		CAMode:        getEnv("CA_MODE", "bundled"),
		CAHostPath:    getEnv("CA_HOST_PATH", ""),
		MetricsToken:  getEnv("METRICS_TOKEN", ""),
		CADatabaseURL: getEnv("CA_DB_URL", ""),
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
