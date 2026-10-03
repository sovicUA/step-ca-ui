package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	appdb "step-ui/db"
)

const (
	adminConsoleTimeout = 8 * time.Second
	adminConsoleMaxOut  = 16 * 1024
)

type adminConsoleCommand struct {
	ID          string
	Label       string
	Description string
	Name        string
	Args        []string
}

type adminConsoleResult struct {
	CommandLine string
	Output      string
	ExitCode    int
	Duration    string
	TimedOut    bool
	Truncated   bool
	Success     bool
}

func (h *Handler) adminConsoleCommands() []adminConsoleCommand {
	ca := h.CA()
	dfPaths := []string{"-h", "/opt/step-ui"}
	if ca.Mode == "bundled" || ca.HostPathMounted {
		if _, err := os.Stat("/home/step"); err == nil {
			dfPaths = append(dfPaths, "/home/step")
		}
	}

	cmds := []adminConsoleCommand{
		{ID: "system.date", Label: "Дата й час", Description: "Поточний час усередині контейнера step-ui", Name: "date"},
		{ID: "system.hostname", Label: "Hostname", Description: "Ім’я контейнера", Name: "hostname"},
		{ID: "system.identity", Label: "Поточний користувач", Description: "UID/GID процесу застосунку", Name: "id"},
		{ID: "system.disk", Label: "Диск", Description: "Вільне місце для каталогів застосунку й CA", Name: "df", Args: dfPaths},
		{ID: "system.processes", Label: "Процеси", Description: "Список процесів усередині контейнера", Name: "ps"},
		{ID: "app.files", Label: "Каталоги застосунку", Description: "Верхній рівень /opt/step-ui", Name: "ls", Args: []string{"-la", "/opt/step-ui"}},
		{ID: "step.version", Label: "step version", Description: "Версія Smallstep CLI усередині контейнера", Name: "step", Args: []string{"version"}},
		{ID: "step.ca.health", Label: "step-ca health", Description: "Перевірка доступності CA з контейнера UI", Name: "step", Args: []string{"ca", "health", "--ca-url", ca.URL, "--root", ca.RootCert}},
		{ID: "openssl.version", Label: "OpenSSL version", Description: "Версія OpenSSL", Name: "openssl", Args: []string{"version", "-a"}},
		{ID: "postgres.ready", Label: "PostgreSQL readiness", Description: "Перевірка доступності PostgreSQL", Name: "pg_isready", Args: []string{"-h", "postgres", "-U", "stepui", "-d", "stepui"}},
	}
	return cmds
}

func (h *Handler) findAdminConsoleCommand(id string) (adminConsoleCommand, bool) {
	for _, c := range h.adminConsoleCommands() {
		if c.ID == id {
			return c, true
		}
	}
	return adminConsoleCommand{}, false
}

func (h *Handler) AdminConsoleGet(w http.ResponseWriter, r *http.Request) {
	data := h.adminConsoleData(w, r)
	h.render(w, "admin_console", data)
}

func (h *Handler) AdminConsolePost(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/admin/console") {
		return
	}

	commandID := strings.TrimSpace(r.FormValue("command_id"))
	data := h.adminConsoleData(w, r)
	data["SelectedCommandID"] = commandID

	if enabled, _ := data["TOTPEnabled"].(bool); !enabled {
		h.auditSecurity(r, "console.denied reason=totp_required command_id="+commandID)
		data["ConsoleError"] = "Консоль доступна лише з увімкненою 2FA. Налаштуйте TOTP у профілі."
		h.render(w, "admin_console", data)
		return
	}

	c, ok := h.findAdminConsoleCommand(commandID)
	if !ok {
		h.auditSecurity(r, "console.denied command_id="+commandID)
		data["ConsoleError"] = "Команди немає в списку дозволених."
		h.render(w, "admin_console", data)
		return
	}

	result := runAdminConsoleCommand(r.Context(), c)
	data["Result"] = result
	h.auditSecurity(r, fmt.Sprintf("console.run id=%s command=%q exit=%d timeout=%t duration=%s",
		c.ID, result.CommandLine, result.ExitCode, result.TimedOut, result.Duration))
	h.render(w, "admin_console", data)
}

func (h *Handler) adminConsoleData(w http.ResponseWriter, r *http.Request) map[string]interface{} {
	data := h.base(w, r, "admin_console")
	data["Commands"] = h.adminConsoleCommands()
	data["Timeout"] = adminConsoleTimeout.String()
	data["MaxOutputKB"] = adminConsoleMaxOut / 1024

	si := h.sessionInfo(r)
	if u, err := appdb.GetUserByID(h.db, si.UserID); err == nil && u != nil {
		data["TOTPEnabled"] = u.TOTPEnabled
	}
	return data
}

func runAdminConsoleCommand(ctx context.Context, c adminConsoleCommand) adminConsoleResult {
	cctx, cancel := context.WithTimeout(ctx, adminConsoleTimeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(cctx, c.Name, c.Args...)
	cmd.Dir = "/opt/step-ui"
	out, err := cmd.CombinedOutput()
	duration := time.Since(start).Round(time.Millisecond)

	exitCode := 0
	if err != nil {
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	timedOut := cctx.Err() == context.DeadlineExceeded
	if timedOut {
		exitCode = -1
	}

	truncated := false
	if len(out) > adminConsoleMaxOut {
		out = append(out[:adminConsoleMaxOut], []byte("\n\n[output truncated]\n")...)
		truncated = true
	}
	text := strings.TrimRight(string(bytes.ToValidUTF8(out, []byte("?"))), "\r\n")
	if text == "" && err != nil {
		text = err.Error()
	}
	if timedOut {
		text = strings.TrimSpace(text + "\ncommand timed out")
	}

	return adminConsoleResult{
		CommandLine: commandLine(c),
		Output:      text,
		ExitCode:    exitCode,
		Duration:    duration.String(),
		TimedOut:    timedOut,
		Truncated:   truncated,
		Success:     err == nil && !timedOut,
	}
}

func commandLine(c adminConsoleCommand) string {
	parts := append([]string{c.Name}, c.Args...)
	return strings.Join(parts, " ")
}
