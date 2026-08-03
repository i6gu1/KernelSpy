package i18n

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

type Translator struct {
	translations map[string]map[string]string
	mu           sync.RWMutex
}

var (
	instance *Translator
	once     sync.Once
)

func GetInstance() *Translator {
	once.Do(func() {
		instance = &Translator{
			translations: make(map[string]map[string]string),
		}
		instance.loadAll()
	})
	return instance
}

func (t *Translator) loadAll() {
	langs := []string{"en", "ar", "ru", "fr", "es"}
	for _, lang := range langs {
		data, err := os.ReadFile("i18n/" + lang + ".json")
		if err != nil {
			continue
		}
		var translations map[string]string
		if err := json.Unmarshal(data, &translations); err != nil {
			continue
		}
		t.translations[lang] = translations
	}
}

func (t *Translator) Translate(lang, key string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if translations, ok := t.translations[lang]; ok {
		if val, ok := translations[key]; ok {
			return val
		}
	}
	if translations, ok := t.translations["en"]; ok {
		if val, ok := translations[key]; ok {
			return val
		}
	}
	return key
}

func (t *Translator) GetDir(lang string) string {
	if lang == "ar" {
		return "rtl"
	}
	return "ltr"
}

func (t *Translator) IsValidLang(lang string) bool {
	validLangs := []string{"en", "ar", "ru", "fr", "es"}
	for _, l := range validLangs {
		if l == lang {
			return true
		}
	}
	return false
}

func DetectFromHeader(acceptLang string) string {
	if acceptLang == "" {
		return ""
	}
	langs := strings.Split(acceptLang, ",")
	for _, l := range langs {
		parts := strings.SplitN(strings.TrimSpace(l), ";", 2)
		lang := strings.TrimSpace(parts[0])
		if len(lang) >= 2 {
			lang = strings.ToLower(lang[:2])
			if lang == "zh" || lang == "ja" || lang == "ko" {
				continue
			}
			return lang
		}
	}
	return ""
}
