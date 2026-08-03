const i18n = {
    currentLang: localStorage.getItem('lang') || 'en',
    translations: {},
    
    async loadTranslations(lang) {
        try {
            const response = await fetch(`/static/i18n/${lang}.json`);
            if (response.ok) {
                this.translations[lang] = await response.json();
            }
        } catch (error) {
            console.error(`Failed to load translations for ${lang}`);
        }
    },
    
    t(key) {
        const lang = this.currentLang;
        if (this.translations[lang] && this.translations[lang][key]) {
            return this.translations[lang][key];
        }
        if (this.translations['en'] && this.translations['en'][key]) {
            return this.translations['en'][key];
        }
        return key;
    },
    
    setLanguage(lang) {
        this.currentLang = lang;
        localStorage.setItem('lang', lang);
        document.cookie = `lang=${lang};path=/;max-age=31536000`;
        
        if (lang === 'ar') {
            document.documentElement.dir = 'rtl';
            document.documentElement.lang = 'ar';
        } else {
            document.documentElement.dir = 'ltr';
            document.documentElement.lang = lang;
        }
        
        this.updatePageContent();
        window.location.reload();
    },
    
    updatePageContent() {
        document.querySelectorAll('[data-i18n]').forEach(element => {
            const key = element.getAttribute('data-i18n');
            const translation = this.t(key);
            if (translation) {
                element.textContent = translation;
            }
        });
        
        document.querySelectorAll('[data-i18n-placeholder]').forEach(element => {
            const key = element.getAttribute('data-i18n-placeholder');
            element.placeholder = this.t(key);
        });
    },
    
    getLangName(lang) {
        const names = {
            'en': 'English',
            'ar': 'العربية',
            'ru': 'Русский',
            'fr': 'Français',
            'es': 'Español'
        };
        return names[lang] || lang;
    },
    
    getDir() {
        return this.currentLang === 'ar' ? 'rtl' : 'ltr';
    }
};

document.addEventListener('DOMContentLoaded', () => {
    document.documentElement.dir = i18n.getDir();
    
    i18n.loadTranslations(i18n.currentLang).then(() => {
        i18n.updatePageContent();
    });
});

document.addEventListener('alpine:init', () => {
    Alpine.data('languageSwitcher', () => ({
        isOpen: false,
        currentLang: i18n.currentLang,
        
        toggle() {
            this.isOpen = !this.isOpen;
        },
        
        select(lang) {
            i18n.setLanguage(lang);
            this.currentLang = lang;
            this.isOpen = false;
        },
        
        getCurrentName() {
            return i18n.getLangName(this.currentLang);
        },
        
        getLanguages() {
            return [
                { code: 'en', name: 'English', dir: 'ltr' },
                { code: 'ar', name: 'العربية', dir: 'rtl' },
                { code: 'ru', name: 'Русский', dir: 'ltr' },
                { code: 'fr', name: 'Français', dir: 'ltr' },
                { code: 'es', name: 'Español', dir: 'ltr' }
            ];
        }
    }));
});
