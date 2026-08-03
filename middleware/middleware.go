package middleware

import (
	"time"

	"black-hat/i18n"

	"github.com/gofiber/fiber/v2"
)

func I18nMiddleware(c *fiber.Ctx) error {
	lang := c.Query("lang")
	if lang == "" {
		lang = c.Cookies("lang")
	}
	if lang == "" {
		lang = i18n.DetectFromHeader(c.Get("Accept-Language"))
	}
	translator := i18n.GetInstance()
	if lang == "" || !translator.IsValidLang(lang) {
		lang = "en"
	}

	c.Locals("lang", lang)
	c.Locals("dir", translator.GetDir(lang))
	c.Locals("translator", translator)

	c.Cookie(&fiber.Cookie{
		Name:    "lang",
		Value:   lang,
		Expires: time.Now().Add(365 * 24 * time.Hour),
	})

	return c.Next()
}

func SecurityHeaders(c *fiber.Ctx) error {
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("X-Frame-Options", "DENY")
	c.Set("X-XSS-Protection", "1; mode=block")
	c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	return c.Next()
}
