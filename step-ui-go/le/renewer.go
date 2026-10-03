package le

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	appdb "step-ui/db"
)

// Notifier delivers an event to the UI notification system.
// Same signature as handlers.Handler.NotifyAsync.
type Notifier func(eventKey, eventType, severity, title, message string, meta map[string]string)

// StartRenewer starts a background goroutine that checks certificates every 24 hours.
// notify may be nil, then no notifications are sent.
func StartRenewer(db *sql.DB, notify Notifier) {
	go func() {
		log.Println("[LE] Auto-renewer started (checks every 24h)")
		// First check 5 minutes after start
		time.Sleep(5 * time.Minute)
		for {
			runRenewal(db, notify)
			time.Sleep(24 * time.Hour)
		}
	}()
}

func runRenewal(db *sql.DB, notify Notifier) {
	certs, err := appdb.GetLECertsForRenewal(db)
	if err != nil {
		log.Printf("[LE] Renewal check error: %v", err)
		return
	}
	if len(certs) == 0 {
		log.Println("[LE] No certificates need renewal")
		return
	}
	log.Printf("[LE] Found %d certificate(s) to renew", len(certs))

	settings, err := appdb.GetLESettings(db)
	if err != nil {
		log.Printf("[LE] Cannot load settings: %v", err)
		return
	}

	for _, cert := range certs {
		log.Printf("[LE] Renewing %s...", cert.Domain)
		appdb.AddLELog(db, cert.Domain, "renew", "Початок автоматичного оновлення")

		email := cert.Email
		if email == "" {
			email = settings.Email
		}
		provider := cert.Provider
		if provider == "" {
			provider = settings.Provider
		}

		result, err := IssueCert(LEConfig{
			Email:     email,
			Domain:    cert.Domain,
			Provider:  provider,
			CFToken:   settings.CFToken,
			CFZoneID:  settings.CFZoneID,
			R53KeyID:  settings.R53KeyID,
			R53Secret: settings.R53SecretKey,
			R53Region: settings.R53Region,
		})
		if err != nil {
			appdb.UpdateLECertStatus(db, cert.ID, "error", err.Error())
			appdb.AddLELog(db, cert.Domain, "error", fmt.Sprintf("Помилка оновлення: %v", err))
			log.Printf("[LE] Renewal failed for %s: %v", cert.Domain, err)
			if notify != nil {
				notify("", "certificate.renew_failed", "error",
					"Let's Encrypt auto-renew failed",
					fmt.Sprintf("Не вдалося оновити сертифікат LE %s: %v", cert.Domain, err),
					map[string]string{"domain": cert.Domain, "provider": provider, "source": "lets-encrypt"})
			}
			continue
		}
		appdb.UpdateLECertPaths(db, cert.ID, result.CertPath, result.KeyPath, result.IssuedAt, result.ExpiresAt)
		appdb.AddLELog(db, cert.Domain, "renew", "Сертифікат успішно оновлено")
		log.Printf("[LE] Successfully renewed %s", cert.Domain)
	}
}
