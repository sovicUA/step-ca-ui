---
name: security-change
description: Make changes to authentication, sessions, CSRF, rate limiting, password reset, 2FA/TOTP, or the admin console. Use when touching security-sensitive code, user management, or audit logging.
---

# Security and Authentication Runbook

Follow this runbook whenever modifying security-sensitive parts of Step-CA UI.

## Sensitive Subsystems

- **Password Hashing & Validation**: `step-ui-go/security/security.go`
  - Passwords hashed with bcrypt (`bcrypt.DefaultCost`).
  - Legacy SHA-256 hashes verified via `subtle.ConstantTimeCompare` and automatically migrated to bcrypt on login.
  - Validation requires: minimum 8 chars, maximum 72 chars, at least 1 digit, 1 letter, and 1 special character.
- **CSRF Defense**: `step-ui-go/handlers/handler.go` and forms
  - POST requests must validate token against session `csrf_token`.
- **Brute-Force Rate Limiting**: `security.RL` in `security.go`
  - 5 failed attempts within 5 minutes results in a 15-minute IP block.
- **2FA / TOTP**: `step-ui-go/handlers/totp.go`
  - Secret stored only after confirmation; recovery codes hashed before storage in `user_recovery_codes`.
- **Password Reset**: `step-ui-go/handlers/password_reset.go`
  - Always return a neutral success message to prevent user enumeration.
  - Tokens have limited TTL, single-use invalidation, and rate limiting.
- **Restricted Admin Console**: `step-ui-go/handlers/admin_console.go`
  - Only execute commands from `adminConsoleCommands()` allowlist.
  - Enforce timeout (`adminConsoleTimeout = 8 * time.Second`) and output truncation (`16 KB`).
  - Log every execution to security audit log.

## Testing & Verification

1. When updating `step-ui-go/security/security.go`, add or update tests in `step-ui-go/security/security_test.go`.
2. Run test suite:
   ```bash
   cd step-ui-go && go test -v ./...
   ```
3. Run linters:
   ```bash
   cd step-ui-go && gofmt -w . && go vet ./...
   ```
4. Verify error and notification texts match the canonical Ukrainian phrasing and its English translation (see `docs/domain.md`).
