---
name: add-http-feature
description: Add or modify an HTTP route, handler, and template in the Step-CA UI project. Use when creating a new page, adding an action endpoint, or updating web UI forms.
---

# Adding or Modifying HTTP Features

Follow this runbook when introducing or altering HTTP endpoints in Step-CA UI.

## Step-by-Step Procedure

### 1. Register Route in Router
Open `step-ui-go/main.go` and place the route in the appropriate group:
- **Public**: Outside `r.Group(func(r chi.Router) { r.Use(mw.RequireLogin(store)) ... })`
- **Authenticated (any user)**: Inside `RequireLogin` group
- **Manager (min role manager)**: Inside `RequireRole("manager", store)` group
- **Admin (min role admin)**: Inside `RequireRole("admin", store)` group

### 2. Implement Handler
In the corresponding file in `step-ui-go/handlers/`:
```go
func (h *Handler) FeatureGet(w http.ResponseWriter, r *http.Request) {
    data := h.base(w, r, "feature")
    // populate data
    h.render(w, "feature", data)
}

func (h *Handler) FeaturePost(w http.ResponseWriter, r *http.Request) {
    if !h.requireCSRF(w, r, "/feature") {
        return
    }
    // process form values and execute DB or step operations
    h.flash(w, r, "ok", "Операция успешно выполнена")
    http.Redirect(w, r, "/feature", http.StatusSeeOther)
}
```

### 3. Register Template in Loader
If introducing a new HTML view, edit `step-ui-go/handlers/handler.go`:
- Append the template name into `pages` inside `loadTemplates()`.
- Note: Pages starting with `admin_` or named `"admin"` use `templates/admin_base.html`; all others use `templates/base.html`.

### 4. Create or Update Template
Create `step-ui-go/templates/<name>.html`:
- Use `{{define "content"}} ... {{end}}`.
- Include `<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">` on every form.
- Use Ukrainian labels wrapped in `{{T "..."}}` (English entries in `i18n/locales/en.json`) and existing styles from `static/css/components.css`.

### 5. Verification
Run standard checks:
```bash
cd step-ui-go && gofmt -w .
cd step-ui-go && go vet ./...
cd step-ui-go && go test ./...
```
Verify the feature in browser along with an adjacent page to ensure navigation and session state remain intact.
