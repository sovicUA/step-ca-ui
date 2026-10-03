package models

import (
	"encoding/gob"
	"time"
)

func init() {
	gob.Register(FlashMsg{})
	gob.Register([]FlashMsg{})
}

type User struct {
	ID                int
	Username          string
	PasswordHash      string
	Role              string
	IsActive          bool
	CreatedAt         *time.Time
	LastLogin         *time.Time
	LastIP            *string
	DisplayName       string
	Email             string
	Theme             string
	TOTPEnabled       bool
	TOTPSecret        string
	TOTPPendingSecret string
}

type AuthLog struct {
	ID        int
	Username  string
	IP        string
	Success   bool
	Reason    string
	CreatedAt time.Time
}

type Certificate struct {
	ID          int
	Name        string
	Domain      string
	CertPath    string
	KeyPath     string
	IssuedAt    *time.Time
	ExpiresAt   *time.Time
	Serial      string
	Status      string
	KeyType     string
	Provisioner string
	CreatedAt   *time.Time
}

type CAProvisioner struct {
	Name              string
	Type              string
	DefaultDuration   string
	MaxDuration       string
	EncryptedPassword string
	IsSystem          bool
	CreatedAt         time.Time
}

type CertHistory struct {
	ID        int
	Action    string
	CertName  string
	Domain    string
	Details   string
	Username  string
	Role      string
	CreatedAt time.Time
}

type FlashMsg struct {
	Type string // "ok" or "err"
	Text string
}

type SessionInfo struct {
	UserID   int
	Username string
	Role     string
	Theme    string
}

type NotificationSettings struct {
	ID              int
	WebhookEnabled  bool
	WebhookURL      string
	NotifyExpiry    bool
	ExpiryDays      int
	NotifyFailures  bool
	NotifyAuthBurst bool
	SMTPEnabled     bool
	SMTPHost        string
	SMTPPort        int
	SMTPSecurity    string
	SMTPUsername    string
	SMTPPassword    string
	SMTPFrom        string
	// NotifyEmailTo — alert recipients, comma-separated. Empty = the email channel
	// is used only for password reset.
	NotifyEmailTo    string
	TelegramEnabled  bool
	TelegramBotToken string
	TelegramChatID   string
	UpdatedAt        *time.Time
}

type NotificationLog struct {
	ID        int
	EventKey  string
	EventType string
	Channel   string
	Severity  string
	Title     string
	Message   string
	Success   bool
	Error     string
	CreatedAt time.Time
}

type PasswordResetToken struct {
	ID        int
	UserID    int
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// SecuritySettings — global UI security policy.
// Force2FARole: "" (off), "admin" or "manager" — lowest role,
// that must use TOTP.
type SecuritySettings struct {
	Force2FARole string
	UpdatedAt    *time.Time
}

type CASettings struct {
	ID                  int
	CAURL               string
	Provisioner         string
	EncryptedPassword   string
	RootCertPEM         string
	IntermediatePEM     string
	RootFingerprint     string
	IntermediateSubject string
	EnableHSTS          bool
	UpdatedAt           *time.Time
}

type CARuntime struct {
	Mode                string // "bundled" or "external"
	URL                 string
	RootCert            string // path to root_ca.crt
	IntermediateCert    string // path to intermediate_ca.crt
	Provisioner         string
	PasswordFile        string
	HostPathMounted     bool
	Configured          bool
	EnableHSTS          bool
	RootFingerprint     string
	IntermediateSubject string
}
