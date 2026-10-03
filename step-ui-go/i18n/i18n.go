// Package i18n translates the user interface. Ukrainian is the source language: the UI text in templates and
// Go code is Ukrainian and serves as the message key; locales/<lang>.json maps it to the other languages.
//
// A key may contain fmt verbs (%s, %d, %v, ...): then any text produced from it - by fmt.Sprintf or by
// concatenation - is recognized as well and its values are carried into the translation. So messages can be
// stored and passed around in Ukrainian (flash messages, audit records) and translated only when rendered.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Source is the language the UI text is written in.
const Source = "uk"

// Default is used when neither the user nor the browser asks for a supported language.
const Default = "uk"

// Lang describes a supported language for the language switcher.
type Lang struct {
	Code  string // BCP 47 code, also the html lang attribute
	Short string // label of the switcher
	Name  string // name of the language in that language
}

// Langs are the supported languages, in switcher order.
var Langs = []Lang{
	{Code: "uk", Short: "UA", Name: "Українська"},
	{Code: "en", Short: "EN", Name: "English"},
}

//go:embed locales/*.json
var localeFS embed.FS

type pattern struct {
	re  *regexp.Regexp
	out string // translation with every verb turned into %s (explicit indexes kept)
}

type catalog struct {
	exact    map[string]string
	patterns []pattern
}

var catalogs = map[string]*catalog{}

var verbRe = regexp.MustCompile(`%(\[\d+\])?[-+# 0-9.]*[a-zA-Z%]`)

func init() {
	for _, l := range Langs {
		if l.Code == Source {
			continue
		}
		data, err := localeFS.ReadFile("locales/" + l.Code + ".json")
		if err != nil {
			panic(fmt.Sprintf("i18n: no catalog for %s: %v", l.Code, err))
		}
		m := map[string]string{}
		if err := json.Unmarshal(data, &m); err != nil {
			panic(fmt.Sprintf("i18n: bad catalog %s: %v", l.Code, err))
		}
		catalogs[l.Code] = build(m)
	}
}

func build(m map[string]string) *catalog {
	c := &catalog{exact: m}
	keys := make([]string, 0, len(m))
	for k := range m {
		if verbRe.MatchString(strings.ReplaceAll(k, "%%", "")) {
			keys = append(keys, k)
		}
	}
	// Longer (more specific) patterns first
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		var sb strings.Builder
		sb.WriteString("^")
		last := 0
		for _, loc := range verbRe.FindAllStringIndex(k, -1) {
			sb.WriteString(regexp.QuoteMeta(k[last:loc[0]]))
			if k[loc[0]:loc[1]] == "%%" {
				sb.WriteString("%")
			} else {
				sb.WriteString("(.*?)")
			}
			last = loc[1]
		}
		sb.WriteString(regexp.QuoteMeta(k[last:]))
		sb.WriteString("$")
		re, err := regexp.Compile("(?s)" + sb.String())
		if err != nil {
			continue
		}
		out := verbRe.ReplaceAllStringFunc(m[k], func(v string) string {
			if v == "%%" {
				return v
			}
			idx := verbRe.FindStringSubmatch(v)[1]
			return "%" + idx + "s"
		})
		c.patterns = append(c.patterns, pattern{re: re, out: out})
	}
	return c
}

// Supported reports whether code is a supported language.
func Supported(code string) bool {
	for _, l := range Langs {
		if l.Code == code {
			return true
		}
	}
	return false
}

// T translates s (Ukrainian) into lang. Unknown text is returned unchanged.
func T(lang, s string) string {
	if lang == Source || s == "" {
		return s
	}
	c := catalogs[lang]
	if c == nil {
		return s
	}
	if t, ok := c.exact[s]; ok && t != "" {
		return t
	}
	// Surrounding whitespace is not part of a key
	if trimmed := strings.TrimSpace(s); trimmed != s {
		if t := T(lang, trimmed); t != trimmed {
			return strings.Replace(s, trimmed, t, 1)
		}
	}
	for _, p := range c.patterns {
		if m := p.re.FindStringSubmatch(s); m != nil {
			args := make([]any, 0, len(m)-1)
			for _, v := range m[1:] {
				args = append(args, T(lang, v))
			}
			return fmt.Sprintf(p.out, args...)
		}
	}
	return s
}

// Tf translates format into lang and then formats it.
func Tf(lang, format string, args ...any) string {
	return fmt.Sprintf(T(lang, format), args...)
}

// CookieName stores the language of visitors who are not logged in.
const CookieName = "step-ui-lang"

// FromRequest picks the language from the cookie, then from Accept-Language, else Default.
func FromRequest(r *http.Request) string {
	if c, err := r.Cookie(CookieName); err == nil && Supported(c.Value) {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		base := strings.SplitN(tag, "-", 2)[0]
		if Supported(base) {
			return base
		}
	}
	return Default
}

// Keys returns the keys of a language catalog (for tests).
func Keys(lang string) map[string]string {
	if c := catalogs[lang]; c != nil {
		return c.exact
	}
	return nil
}
