# Step-CA UI — Agent Harness

Self-hosted web UI for smallstep `step-ca` private PKI running in 3 Docker Compose containers (`postgres`, `step-ca`, `step-ui`). UI listens on internal port 8443 (mapped to external `${UI_HTTPS_PORT:-443}`), step-ca listens on port 9443.

## Stack Matrix

| Layer | In Stack (Use) | Prohibited (Do NOT Use) |
|---|---|---|
| **Backend** | Go 1.22, `chi/v5`, standard `database/sql` + `lib/pq` | ORM (GORM, etc.), alternate routers (Gin/Echo), Redis |
| **Frontend** | Go `html/template` (SSR), vanilla JS, plain CSS in `static/css/` | React, Vue, SPA frameworks, npm, bundlers, CSS frameworks |
| **Auth** | `gorilla/sessions` encrypted cookie (`step-ui`), session CSRF token | JWT, OAuth/OIDC wrappers |
| **PKI** | `step` CLI (`ca certificate`, `ca revoke`, `ca health`) | Direct ACME to step-ca bypassing CLI, custom cert issuance |
| **Database** | PostgreSQL 16 (`stepui` database) | External migration tools, SQLite in production |
| **Deploy** | Docker Compose, `install.sh` | `docker compose down -v`, unpinned `smallstep/step-ca:latest` |

## Task -> Files Routing Map

- **Routes & middleware**: `step-ui-go/main.go`, `step-ui-go/middleware/middleware.go`
- **HTTP Handlers**: `step-ui-go/handlers/*.go` (`certs.go`, `cert_ops.go`, `auth.go`, `admin.go`, `admin_console.go`, `backup.go`, `health.go`, etc.)
- **HTML Templates**: `step-ui-go/templates/*.html` (base: `base.html`, admin base: `admin_base.html`)
- **Translations**: `step-ui-go/i18n/` (`i18n.go`, English catalog `locales/en.json`)
- **Static Assets**: `step-ui-go/static/css/*.css`, `step-ui-go/static/js/*.js`
- **Database schema & queries**: `step-ui-go/db/*.go` (`db.go`, `provisioners.go`, `le_db.go`, `password_reset.go`, `notifications.go`)
- **Security & cryptography**: `step-ui-go/security/*.go` (bcrypt, rate limiting, password validation)
- **Deployment & scripts**: `docker-compose.yml`, `install.sh`, `provisioner.sh`, `playbooks/provisioners/`, `step-ca-bootstrap.sh`, `step-ui-go/Dockerfile`

## Hard Invariants

1. **CSRF**: Every POST route must validate `csrf_token` via `h.requireCSRF(w, r, redirectTo)` or `h.csrfOK(r)`. Every HTML form must contain `<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">` or `{{$.CSRFToken}}`.
2. **Authorization**: Routes must be gated by `mw.RequireLogin` and `mw.RequireRole` (`viewer` < `manager` < `admin`). Role checks must match route grouping in `main.go`.
3. **Passwords**: Use `security.HashPassword` (bcrypt). Maintain backward compatibility with legacy SHA-256 hashes via `security.VerifyPassword` and transparent rehash on login.
4. **Localization & Copy**: UI text and user-facing messages are in Ukrainian - the source language and the translation key - with an English catalog in `step-ui-go/i18n/locales/en.json`; `<html lang="{{lang}}">` follows the page language (UA / EN switcher, `users.lang`, cookie `step-ui-lang`, `Accept-Language`). Templates wrap text in `{{T "..."}}`; flash messages and errors stay Ukrainian in Go code and the database and are translated when rendered (`{{T .Text}}`, keys with fmt verbs match the formatted text). Every new or changed text needs its English entry in `en.json` (`TestTemplateKeysTranslated`, `TestTemplatesExecute` fail otherwise). Use the typographic apostrophe `’`, never `'`. Canonical security, error, and audit messages ([docs/domain.md](docs/domain.md)) must not be paraphrased.
5. **Admin Console**: Executions are strictly restricted to the predefined allowlist in `handlers/admin_console.go`. Never execute arbitrary shell strings.
6. **Secrets & Privacy**: System health and integrity checks must never leak passwords, tokens, or private keys. Do not scan or commit `.env`, `credentials.txt`, or `step-ui-go/ssl/`.
7. **Backups & Restore**: Backups contain CA private keys and must be treated as sensitive data. Restore is strictly manual per `BACKUP_RESTORE.md` — never implement automated UI restore that overwrites keys.

## Verification Loop

Before finishing any task, run these commands:

```bash
cd step-ui-go && gofmt -w .
cd step-ui-go && go vet ./...
cd step-ui-go && go test ./...
```

For UI changes: verify in browser both the modified view and an adjacent view with the same session state.

## Deep Reference Documentation

- Architecture details: [docs/architecture.md](docs/architecture.md)
- Route and API contracts: [docs/api.md](docs/api.md)
- Domain rules and canonical texts: [docs/domain.md](docs/domain.md)
- Manual restore procedures: [BACKUP_RESTORE.md](BACKUP_RESTORE.md)
