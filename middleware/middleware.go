package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"black-hat/i18n"
)

// contextKey is a private key type for request-scoped values.
type contextKey string

const (
	// LangKey stores the resolved language in the request context.
	LangKey contextKey = "lang"
	// DirKey stores the text direction ("ltr"/"rtl") in the request context.
	DirKey contextKey = "dir"
)

// LangFrom returns the language stored in the request context (default "en").
func LangFrom(r *http.Request) string {
	if v, ok := r.Context().Value(LangKey).(string); ok && v != "" {
		return v
	}
	return "en"
}

// DirFrom returns the text direction stored in the request context.
func DirFrom(r *http.Request) string {
	if v, ok := r.Context().Value(DirKey).(string); ok && v != "" {
		return v
	}
	return "ltr"
}

// ClientIP returns the real client IP. Vercel and other proxies set
// X-Forwarded-For; fall back to the socket address when absent.
func ClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// I18nMiddleware resolves the language from query, cookie or Accept-Language,
// stores it in the request context and sets the lang cookie.
func I18nMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := r.URL.Query().Get("lang")
		if lang == "" {
			if c, err := r.Cookie("lang"); err == nil {
				lang = c.Value
			}
		}
		if lang == "" {
			lang = i18n.DetectFromHeader(r.Header.Get("Accept-Language"))
		}
		translator := i18n.GetInstance()
		if lang == "" || !translator.IsValidLang(lang) {
			lang = "en"
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, LangKey, lang)
		ctx = context.WithValue(ctx, DirKey, translator.GetDir(lang))

		http.SetCookie(w, &http.Cookie{
			Name:    "lang",
			Value:   lang,
			Path:    "/",
			Expires: time.Now().Add(365 * 24 * time.Hour),
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SecurityHeaders adds hardening headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// Recover catches panics from downstream handlers so a single bad request can
// never crash the whole server (the equivalent of Fiber's recover middleware).
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered: %v", rec)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
