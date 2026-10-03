package i18n

import (
	"net/http/httptest"
	"testing"
)

func TestT(t *testing.T) {
	cases := []struct{ lang, in, want string }{
		{"uk", "Зберегти", "Зберегти"},
		{"en", "Зберегти", "Save"},
		{"en", "  Зберегти  ", "  Save  "},
		{"en", "unknown text", "unknown text"},
		// Concatenated / formatted messages are recognized by their pattern keys
		{"en", "Користувач bob створений", "User bob created"},
		{"en", "Сертифікат app для app.example.lan випущено (EC:P-256)!", "Certificate app for app.example.lan issued (EC:P-256)!"},
		{"en", "Неправильний логін або пароль. Лишилось спроб: 3", "Wrong login or password. Attempts left: 3"},
		{"en", "1д 2г 3хв", "1d 2h 3m"},
		// Values are translated too
		{"en", "Помилка: провізіонер ui не зареєстровано в UI", "Error: provisioner ui is not registered in the UI"},
	}
	for _, c := range cases {
		if got := T(c.lang, c.in); got != c.want {
			t.Errorf("T(%s, %q) = %q, want %q", c.lang, c.in, got, c.want)
		}
	}
}

func TestFromRequest(t *testing.T) {
	cases := []struct{ cookie, accept, want string }{
		{"", "", Default},
		{"", "en-US,en;q=0.9", "en"},
		{"", "uk-UA,uk;q=0.9,en;q=0.8", "uk"},
		{"", "de-DE,de;q=0.9", Default},
		{"en", "uk", "en"},
		{"xx", "en", "en"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if c.accept != "" {
			r.Header.Set("Accept-Language", c.accept)
		}
		if c.cookie != "" {
			r.Header.Set("Cookie", CookieName+"="+c.cookie)
		}
		if got := FromRequest(r); got != c.want {
			t.Errorf("FromRequest(cookie=%q, accept=%q) = %q, want %q", c.cookie, c.accept, got, c.want)
		}
	}
}
