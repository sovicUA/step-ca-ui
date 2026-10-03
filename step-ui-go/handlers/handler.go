package handlers

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"step-ui/config"
	appdb "step-ui/db"
	"step-ui/i18n"
	"step-ui/models"
	"step-ui/security"
)

var StartedAt time.Time

// Versioning - overridden with ldflags at build time
var (
	Version   = "1.7.0"
	BuildDate = "2026-06-02"
	GitCommit = "unknown"
)

type Handler struct {
	db       *sql.DB
	cfg      *config.Config
	store    *sessions.CookieStore
	tmpls    map[string]map[string]*template.Template // language -> page -> template
	resolver *CAResolver
}

func New(db *sql.DB, cfg *config.Config, store *sessions.CookieStore) *Handler {
	h := &Handler{db: db, cfg: cfg, store: store, tmpls: make(map[string]map[string]*template.Template)}
	res, err := NewCAResolver(h)
	if err != nil {
		log.Printf("[handler] warning initializing CAResolver: %v", err)
	}
	h.resolver = res
	h.loadTemplates()
	return h
}

func (h *Handler) CA() models.CARuntime {
	if h.resolver == nil {
		mode := h.cfg.CAMode
		if mode == "" {
			mode = "bundled"
		}
		return models.CARuntime{
			Mode:             mode,
			URL:              h.cfg.CAURL,
			RootCert:         h.cfg.RootCert,
			IntermediateCert: h.intermediateCertPath(),
			Provisioner:      h.cfg.Provisioner,
			PasswordFile:     h.cfg.PasswordFile,
			Configured:       true,
		}
	}
	return h.resolver.Runtime()
}

// loadTemplates parses every page once per language: the template function T is bound to that language
// (html/template cannot be cloned with other functions after it has been executed).
func (h *Handler) loadTemplates() {
	for _, l := range i18n.Langs {
		h.tmpls[l.Code] = h.parseTemplates(h.templateFuncs(l.Code))
	}
}

func (h *Handler) parseTemplates(funcs template.FuncMap) map[string]*template.Template {
	tmpls := make(map[string]*template.Template)
	pages := []string{
		"home",
		"dashboard",
		"certificates",
		"certificate_detail",
		"issue",
		"import",
		"provisioners",
		"history",
		"admin",
		"profile",
		"le_dashboard",
		"le_issue",
		"le_settings",
		"le_logs",
		"admin_users",
		"admin_user_profile",
		"admin_users_temp",
		"admin_activity",
		"admin_security",
		"admin_console",
		"admin_about",
		"admin_integrity",
		"admin_backup",
		"admin_notifications",
		"admin_ca",
		"profile_2fa",
	}
	for _, page := range pages {
		baseFile := "templates/base.html"
		if len(page) >= 6 && page[:6] == "admin_" || page == "admin" {
			baseFile = "templates/admin_base.html"
		}
		t, err := template.New("base.html").Funcs(funcs).ParseFiles(
			baseFile,
			fmt.Sprintf("templates/%s.html", page),
		)
		if err != nil {
			log.Printf("template error (%s): %v", page, err)
			continue
		}
		tmpls[page] = t
	}
	for _, page := range []string{"login", "forgot_password", "reset_password"} {
		file := fmt.Sprintf("templates/%s.html", page)
		if t, err := template.New(fmt.Sprintf("%s.html", page)).Funcs(funcs).ParseFiles(file); err == nil {
			tmpls[page] = t
		} else {
			log.Printf("%s template error: %v", page, err)
		}
	}
	return tmpls
}

func (h *Handler) templateFuncs(lang string) template.FuncMap {
	return template.FuncMap{
		// T translates Ukrainian UI text (a literal or a value such as a flash message) into the page language
		"T":     func(s string) string { return i18n.T(lang, s) },
		"lang":  func() string { return lang },
		"langs": func() []i18n.Lang { return i18n.Langs },
		"daysLeft": func(t *time.Time) int {
			if t == nil {
				return 999
			}
			return int(time.Until(*t).Hours() / 24)
		},
		"badgeClass": func(t *time.Time) string {
			if t == nil {
				return "ok"
			}
			d := int(time.Until(*t).Hours() / 24)
			if d <= 0 {
				return "danger"
			}
			if d <= 30 {
				return "warn"
			}
			return "ok"
		},
		"fmtTime": func(t *time.Time) string {
			if t == nil {
				return "—"
			}
			return t.Local().Format("2006-01-02 15:04")
		},
		"fmtLog": func(t time.Time) string {
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"hasRole": func(role, minRole string) bool {
			levels := map[string]int{"viewer": 1, "manager": 2, "admin": 3}
			return levels[role] >= levels[minRole]
		},
		"isActive": func(page, current string) string {
			if page == current {
				return "active"
			}
			return ""
		},
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"deref": func(s *string) string {
			if s == nil {
				return "—"
			}
			return *s
		},
		"contains": func(arr []string, v string) bool {
			for _, s := range arr {
				if s == v {
					return true
				}
			}
			return false
		},
		"seq": func(start, end int) []int {
			var s []int
			for i := start; i <= end; i++ {
				s = append(s, i)
			}
			return s
		},
		"securityEventLabel": securityEventLabel,
		"securityEventBadge": securityEventBadge,
	}
}

func (h *Handler) sess(r *http.Request) *sessions.Session {
	s, err := h.store.Get(r, "step-ui")
	if err != nil {
		log.Printf("session decode failed: remote=%s host=%s path=%s err=%v", r.RemoteAddr, r.Host, r.URL.Path, err)
	}
	return s
}

func (h *Handler) sessionInfo(r *http.Request) *models.SessionInfo {
	s := h.sess(r)
	id, _ := s.Values["user_id"].(int)
	username, _ := s.Values["username"].(string)
	role, _ := s.Values["role"].(string)
	theme := "dark"
	lang := ""
	if id > 0 {
		if u, err := appdb.GetUserByID(h.db, id); err == nil && u != nil {
			if u.Theme != "" {
				theme = u.Theme
			}
			if i18n.Supported(u.Lang) {
				lang = u.Lang
			}
		}
	}
	if lang == "" {
		lang = i18n.FromRequest(r)
	}
	return &models.SessionInfo{UserID: id, Username: username, Role: role, Theme: theme, Lang: lang}
}

// lang is the interface language of the request: the user's choice, else the language cookie / browser.
func (h *Handler) lang(r *http.Request) string {
	return h.sessionInfo(r).Lang
}

// SetLang switches the interface language (/lang/{code}): a cookie for everybody, and the profile of a
// logged-in user; then back to the page the switcher was clicked on.
func (h *Handler) SetLang(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	if i18n.Supported(code) {
		http.SetCookie(w, &http.Cookie{
			Name: i18n.CookieName, Value: code, Path: "/", MaxAge: 365 * 24 * 3600,
			HttpOnly: true, Secure: h.cfg.SessionSecure, SameSite: http.SameSiteLaxMode,
		})
		if id, _ := h.sess(r).Values["user_id"].(int); id > 0 {
			if err := appdb.UpdateUserLang(h.db, id, code); err != nil {
				log.Printf("lang: update user %d: %v", id, err)
			}
		}
	}
	http.Redirect(w, r, localReturnPath(r), http.StatusSeeOther)
}

// localReturnPath is the path of the Referer when it is this site, else "/" (no open redirects).
func localReturnPath(r *http.Request) string {
	ref, err := url.Parse(r.Referer())
	if err != nil || ref.Host != r.Host || ref.Path == "" || ref.Path[0] != '/' {
		return "/"
	}
	if ref.RawQuery != "" {
		return ref.Path + "?" + ref.RawQuery
	}
	return ref.Path
}

func (h *Handler) flash(w http.ResponseWriter, r *http.Request, t, text string) {
	s := h.sess(r)
	s.AddFlash(models.FlashMsg{Type: t, Text: text})
	s.Save(r, w)
}

func (h *Handler) popFlash(w http.ResponseWriter, r *http.Request) []models.FlashMsg {
	s := h.sess(r)
	flashes := s.Flashes()
	s.Save(r, w)
	var msgs []models.FlashMsg
	for _, f := range flashes {
		if m, ok := f.(models.FlashMsg); ok {
			msgs = append(msgs, m)
		}
	}
	return msgs
}

func (h *Handler) csrf(w http.ResponseWriter, r *http.Request) string {
	s, err := h.store.Get(r, "step-ui")
	if err != nil {
		log.Printf("session reset after decode failure: remote=%s host=%s path=%s err=%v", r.RemoteAddr, r.Host, r.URL.Path, err)
		s, _ = h.store.New(r, "step-ui")
	}
	token, ok := s.Values["csrf_token"].(string)
	if !ok || token == "" {
		token = security.GenerateToken()
		s.Values["csrf_token"] = token
		s.Save(r, w)
	}
	return token
}

func (h *Handler) csrfOK(r *http.Request) bool {
	s := h.sess(r)
	token := r.FormValue("csrf_token")
	sess, _ := s.Values["csrf_token"].(string)
	return token != "" && token == sess
}

func (h *Handler) requireCSRF(w http.ResponseWriter, r *http.Request, redirectTo string) bool {
	if h.csrfOK(r) {
		return true
	}
	h.flash(w, r, "err", "Помилка сесії. Оновіть сторінку.")
	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
	return false
}

func (h *Handler) base(w http.ResponseWriter, r *http.Request, activePage string) map[string]interface{} {
	si := h.sessionInfo(r)
	return map[string]interface{}{
		"Session":    si,
		"Lang":       si.Lang,
		"Msgs":       h.popFlash(w, r),
		"ActivePage": activePage,
		"CSRFToken":  h.csrf(w, r),
		"CARuntime":  h.CA(),
	}
}

func (h *Handler) render(w http.ResponseWriter, page string, data map[string]interface{}) {
	lang, _ := data["Lang"].(string)
	if !i18n.Supported(lang) {
		lang = i18n.Default
	}
	tmpl, ok := h.tmpls[lang][page]
	if !ok {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	name := "layout"
	if page == "login" || page == "forgot_password" || page == "reset_password" {
		name = page + ".html"
	} else if page == "admin" || (len(page) >= 6 && page[:6] == "admin_") {
		name = "admin_layout"
	}
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}
