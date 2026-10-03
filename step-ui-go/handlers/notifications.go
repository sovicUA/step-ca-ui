package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	appdb "step-ui/db"
	"step-ui/models"
)

type notificationPayload struct {
	Type      string            `json:"type"`
	Severity  string            `json:"severity"`
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Version   string            `json:"version"`
	Meta      map[string]string `json:"meta,omitempty"`
}

func (h *Handler) AdminNotificationsGet(w http.ResponseWriter, r *http.Request) {
	settings, err := appdb.GetNotificationSettings(h.db)
	if err != nil {
		h.flash(w, r, "err", "Не вдалося завантажити налаштування сповіщень: "+err.Error())
		settings = &models.NotificationSettings{NotifyExpiry: true, ExpiryDays: 30, NotifyFailures: true, NotifyAuthBurst: true}
	}
	logs, _ := appdb.GetNotificationLogs(h.db, 25)

	data := h.base(w, r, "admin_notifications")
	data["Settings"] = settings
	data["Logs"] = logs
	h.render(w, "admin_notifications", data)
}

func (h *Handler) AdminNotificationsPost(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/admin/notifications") {
		return
	}
	_ = r.ParseForm()
	current, _ := appdb.GetNotificationSettings(h.db)
	if current == nil {
		current = &models.NotificationSettings{ExpiryDays: 30, SMTPPort: 587, SMTPSecurity: "starttls"}
	}
	expiryDays, _ := strconv.Atoi(r.FormValue("expiry_days"))
	if expiryDays < 1 {
		expiryDays = 1
	}
	if expiryDays > 365 {
		expiryDays = 365
	}
	settings := &models.NotificationSettings{
		WebhookEnabled:   r.FormValue("webhook_enabled") == "on",
		WebhookURL:       strings.TrimSpace(r.FormValue("webhook_url")),
		NotifyExpiry:     r.FormValue("notify_expiry") == "on",
		ExpiryDays:       expiryDays,
		NotifyFailures:   r.FormValue("notify_failures") == "on",
		NotifyAuthBurst:  r.FormValue("notify_auth_burst") == "on",
		SMTPEnabled:      r.FormValue("smtp_enabled") == "on",
		SMTPHost:         strings.TrimSpace(r.FormValue("smtp_host")),
		SMTPUsername:     strings.TrimSpace(r.FormValue("smtp_username")),
		SMTPPassword:     strings.TrimSpace(r.FormValue("smtp_password")),
		SMTPFrom:         strings.TrimSpace(r.FormValue("smtp_from")),
		NotifyEmailTo:    strings.TrimSpace(r.FormValue("notify_email_to")),
		TelegramEnabled:  r.FormValue("telegram_enabled") == "on",
		TelegramBotToken: strings.TrimSpace(r.FormValue("telegram_bot_token")),
		TelegramChatID:   strings.TrimSpace(r.FormValue("telegram_chat_id")),
	}
	settings.SMTPPort, _ = strconv.Atoi(r.FormValue("smtp_port"))
	if settings.SMTPPort <= 0 {
		settings.SMTPPort = 587
	}
	settings.SMTPSecurity = strings.ToLower(strings.TrimSpace(r.FormValue("smtp_security")))
	if settings.SMTPSecurity != "none" && settings.SMTPSecurity != "starttls" && settings.SMTPSecurity != "tls" {
		settings.SMTPSecurity = "starttls"
	}
	if !r.Form.Has("smtp_host") {
		settings.SMTPEnabled = current.SMTPEnabled
		settings.SMTPHost = current.SMTPHost
		settings.SMTPPort = current.SMTPPort
		settings.SMTPSecurity = current.SMTPSecurity
		settings.SMTPUsername = current.SMTPUsername
		settings.SMTPPassword = current.SMTPPassword
		settings.SMTPFrom = current.SMTPFrom
		settings.NotifyEmailTo = current.NotifyEmailTo
	}
	if settings.SMTPPassword == "" {
		settings.SMTPPassword = current.SMTPPassword
	}
	if !r.Form.Has("telegram_chat_id") {
		settings.TelegramEnabled = current.TelegramEnabled
		settings.TelegramBotToken = current.TelegramBotToken
		settings.TelegramChatID = current.TelegramChatID
	}
	if settings.TelegramBotToken == "" {
		settings.TelegramBotToken = current.TelegramBotToken
	}
	if settings.WebhookEnabled {
		if _, err := url.ParseRequestURI(settings.WebhookURL); err != nil {
			h.flash(w, r, "err", "Webhook URL некоректний")
			http.Redirect(w, r, "/admin/notifications", http.StatusSeeOther)
			return
		}
	}
	if settings.SMTPEnabled {
		if settings.SMTPHost == "" || settings.SMTPFrom == "" {
			h.flash(w, r, "err", "Для SMTP вкажіть host і from")
			http.Redirect(w, r, "/admin/notifications", http.StatusSeeOther)
			return
		}
	}
	if settings.TelegramEnabled {
		if settings.TelegramBotToken == "" || settings.TelegramChatID == "" {
			h.flash(w, r, "err", "Для Telegram вкажіть bot token і chat ID")
			http.Redirect(w, r, "/admin/notifications", http.StatusSeeOther)
			return
		}
	}
	if err := appdb.SaveNotificationSettings(h.db, settings); err != nil {
		h.flash(w, r, "err", "Не вдалося зберегти налаштування: "+err.Error())
	} else {
		h.auditSecurity(r, fmt.Sprintf("notifications.save webhook_enabled=%t smtp_enabled=%t smtp_host=%s smtp_security=%s telegram_enabled=%t notify_expiry=%t notify_failures=%t notify_auth_burst=%t expiry_days=%d",
			settings.WebhookEnabled, settings.SMTPEnabled, settings.SMTPHost, settings.SMTPSecurity,
			settings.TelegramEnabled, settings.NotifyExpiry, settings.NotifyFailures, settings.NotifyAuthBurst, settings.ExpiryDays))
		h.flash(w, r, "ok", "Налаштування сповіщень збережено")
	}
	http.Redirect(w, r, "/admin/notifications", http.StatusSeeOther)
}

func (h *Handler) AdminNotificationsTest(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/admin/notifications") {
		return
	}
	settings, err := appdb.GetNotificationSettings(h.db)
	if err != nil {
		h.flash(w, r, "err", "Не вдалося завантажити налаштування: "+err.Error())
		http.Redirect(w, r, "/admin/notifications", http.StatusSeeOther)
		return
	}
	channels := enabledChannels(settings)
	if len(channels) == 0 {
		h.flash(w, r, "err", "Спершу увімкніть і налаштуйте хоча б один канал доставки")
		http.Redirect(w, r, "/admin/notifications", http.StatusSeeOther)
		return
	}
	err = h.sendNotification(r.Context(), "", "system.test", "info", "Step-CA UI test notification", "Тестове надсилання сповіщення з адмін-панелі", map[string]string{
		"remote_addr": r.RemoteAddr,
	})
	if err != nil {
		h.auditSecurity(r, "notifications.test status=failed channels="+strings.Join(channels, ","))
		h.flash(w, r, "err", "Тестове надсилання не вдалося: "+err.Error())
	} else {
		h.auditSecurity(r, "notifications.test status=sent channels="+strings.Join(channels, ","))
		h.flash(w, r, "ok", "Тест надіслано в канали: "+strings.Join(channels, ", "))
	}
	http.Redirect(w, r, "/admin/notifications", http.StatusSeeOther)
}

// NotifyAsync — exported wrapper for background workers outside the package.
func (h *Handler) NotifyAsync(eventKey, eventType, severity, title, message string, meta map[string]string) {
	h.notifyAsync(eventKey, eventType, severity, title, message, meta)
}

func (h *Handler) notifyAsync(eventKey, eventType, severity, title, message string, meta map[string]string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		if err := h.sendNotification(ctx, eventKey, eventType, severity, title, message, meta); err != nil {
			log.Printf("notification %s failed: %v", eventType, err)
		}
	}()
}

const (
	channelWebhook  = "webhook"
	channelEmail    = "email"
	channelTelegram = "telegram"
)

// sendNotification delivers an event to all enabled channels. Each channel
// is logged separately; deduplication by event_key is per channel too.
func (h *Handler) sendNotification(ctx context.Context, eventKey, eventType, severity, title, message string, meta map[string]string) error {
	settings, err := appdb.GetNotificationSettings(h.db)
	if err != nil {
		return err
	}
	if !notificationAllowed(settings, eventType) {
		return nil
	}

	payload := notificationPayload{
		Type:      eventType,
		Severity:  severity,
		Title:     title,
		Message:   message,
		Timestamp: time.Now(),
		Source:    "step-ca-ui",
		Version:   Version,
		Meta:      meta,
	}

	var errs []string
	for _, channel := range enabledChannels(settings) {
		if eventKey != "" && appdb.NotificationEventExists(h.db, eventKey, channel) {
			continue
		}
		var sendErr error
		switch channel {
		case channelWebhook:
			sendErr = sendWebhookNotification(ctx, settings, payload)
		case channelEmail:
			sendErr = sendEmailNotification(ctx, settings, payload)
		case channelTelegram:
			sendErr = sendTelegramNotification(ctx, settings, payload)
		}
		logEntry := &models.NotificationLog{
			EventKey:  eventKey,
			EventType: eventType,
			Channel:   channel,
			Severity:  severity,
			Title:     title,
			Message:   message,
			Success:   sendErr == nil,
		}
		if sendErr != nil {
			logEntry.Error = sendErr.Error()
			errs = append(errs, channel+": "+sendErr.Error())
		}
		_ = appdb.AddNotificationLog(h.db, logEntry)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func enabledChannels(settings *models.NotificationSettings) []string {
	var out []string
	if settings.WebhookEnabled && strings.TrimSpace(settings.WebhookURL) != "" {
		out = append(out, channelWebhook)
	}
	if settings.SMTPEnabled && strings.TrimSpace(settings.SMTPHost) != "" &&
		strings.TrimSpace(settings.SMTPFrom) != "" && len(emailRecipients(settings)) > 0 {
		out = append(out, channelEmail)
	}
	if settings.TelegramEnabled && strings.TrimSpace(settings.TelegramBotToken) != "" &&
		strings.TrimSpace(settings.TelegramChatID) != "" {
		out = append(out, channelTelegram)
	}
	return out
}

func emailRecipients(settings *models.NotificationSettings) []string {
	var out []string
	for _, part := range strings.Split(settings.NotifyEmailTo, ",") {
		if addr := strings.TrimSpace(part); addr != "" {
			out = append(out, addr)
		}
	}
	return out
}

func sendWebhookNotification(ctx context.Context, settings *models.NotificationSettings, payload notificationPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "step-ca-ui/"+Version)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func sendEmailNotification(ctx context.Context, settings *models.NotificationSettings, payload notificationPayload) error {
	subject := fmt.Sprintf("[Step-CA UI][%s] %s", strings.ToUpper(payload.Severity), payload.Title)
	var body strings.Builder
	fmt.Fprintf(&body, "%s\r\n\r\n", payload.Message)
	fmt.Fprintf(&body, "Подія: %s\r\n", payload.Type)
	fmt.Fprintf(&body, "Рівень: %s\r\n", payload.Severity)
	fmt.Fprintf(&body, "Час: %s\r\n", payload.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&body, "Джерело: %s %s\r\n", payload.Source, payload.Version)
	for _, key := range sortedMetaKeys(payload.Meta) {
		fmt.Fprintf(&body, "%s: %s\r\n", key, payload.Meta[key])
	}
	return sendSMTPMail(ctx, settings.SMTPHost, settings.SMTPPort, settings.SMTPSecurity,
		settings.SMTPUsername, settings.SMTPPassword, settings.SMTPFrom,
		emailRecipients(settings), subject, body.String())
}

func sendTelegramNotification(ctx context.Context, settings *models.NotificationSettings, payload notificationPayload) error {
	var text strings.Builder
	fmt.Fprintf(&text, "%s %s\n%s\n", telegramSeverityIcon(payload.Severity), payload.Title, payload.Message)
	fmt.Fprintf(&text, "\nПодія: %s\nЧас: %s\n", payload.Type, payload.Timestamp.Format(time.RFC3339))
	for _, key := range sortedMetaKeys(payload.Meta) {
		fmt.Fprintf(&text, "%s: %s\n", key, payload.Meta[key])
	}

	form := url.Values{}
	form.Set("chat_id", strings.TrimSpace(settings.TelegramChatID))
	form.Set("text", text.String())
	form.Set("disable_web_page_preview", "true")

	endpoint := "https://api.telegram.org/bot" + strings.TrimSpace(settings.TelegramBotToken) + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 7 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr struct {
			Description string `json:"description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Description != "" {
			return fmt.Errorf("telegram API: %s", apiErr.Description)
		}
		return fmt.Errorf("telegram API returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func telegramSeverityIcon(severity string) string {
	switch severity {
	case "error":
		return "[ERROR]"
	case "warn":
		return "[WARN]"
	default:
		return "[INFO]"
	}
}

func sortedMetaKeys(meta map[string]string) []string {
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func notificationAllowed(settings *models.NotificationSettings, eventType string) bool {
	switch {
	case strings.HasPrefix(eventType, "certificate.expir"):
		return settings.NotifyExpiry
	case strings.HasPrefix(eventType, "certificate.") && strings.HasSuffix(eventType, "_failed"):
		return settings.NotifyFailures
	case strings.HasPrefix(eventType, "auth."):
		return settings.NotifyAuthBurst
	default:
		return true
	}
}

func (h *Handler) StartNotificationWorker() {
	go func() {
		h.checkExpiringCertificates(context.Background())
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for range t.C {
			h.checkExpiringCertificates(context.Background())
		}
	}()
}

func (h *Handler) checkExpiringCertificates(ctx context.Context) {
	settings, err := appdb.GetNotificationSettings(h.db)
	if err != nil || !settings.NotifyExpiry || settings.ExpiryDays <= 0 {
		return
	}
	now := time.Now()
	limit := now.Add(time.Duration(settings.ExpiryDays) * 24 * time.Hour)

	certs, err := appdb.GetCerts(h.db, "active")
	if err == nil {
		for _, c := range certs {
			if c.ExpiresAt == nil || c.ExpiresAt.Before(now) || c.ExpiresAt.After(limit) {
				continue
			}
			eventKey := fmt.Sprintf("cert-expiry:%d:%s", c.ID, c.ExpiresAt.Format("2006-01-02"))
			days := int(time.Until(*c.ExpiresAt).Hours() / 24)
			_ = h.sendNotification(ctx, eventKey, "certificate.expiring", "warn",
				"Certificate expires soon",
				fmt.Sprintf("Сертифікат %s (%s) спливає через %d дн.", c.Name, c.Domain, days),
				map[string]string{
					"id":      strconv.Itoa(c.ID),
					"name":    c.Name,
					"domain":  c.Domain,
					"expires": c.ExpiresAt.Format(time.RFC3339),
				})
		}
	}

	// Let's Encrypt certificates live 90 days and are renewed by a separate
	// worker, so their expiry must be watched as well.
	leCerts, err := appdb.GetLECerts(h.db)
	if err != nil {
		return
	}
	for _, c := range leCerts {
		if c.Status != "active" || c.ExpiresAt == nil {
			continue
		}
		if c.ExpiresAt.Before(now) || c.ExpiresAt.After(limit) {
			continue
		}
		eventKey := fmt.Sprintf("le-cert-expiry:%d:%s", c.ID, c.ExpiresAt.Format("2006-01-02"))
		days := int(time.Until(*c.ExpiresAt).Hours() / 24)
		_ = h.sendNotification(ctx, eventKey, "certificate.expiring", "warn",
			"Let's Encrypt certificate expires soon",
			fmt.Sprintf("LE сертифікат %s спливає через %d дн. (автооновлення: %t)", c.Domain, days, c.AutoRenew),
			map[string]string{
				"id":         strconv.Itoa(c.ID),
				"domain":     c.Domain,
				"source":     "lets-encrypt",
				"auto_renew": strconv.FormatBool(c.AutoRenew),
				"expires":    c.ExpiresAt.Format(time.RFC3339),
			})
	}
}
