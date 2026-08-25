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

// KernelSpyDesktop: bridge for the desktop app's native folder picker. The
// picker and the in-place scanner live behind HTTP endpoints served by the
// local engine, so this works in the WebView2 window and in a normal browser
// pointed at the local port alike.
if (window.KERNELSPY_DESKTOP) {
    window.KernelSpyDesktop = {
        async scanFolder() {
            try {
                const pickRes = await fetch('/api/desktop/pick-folder', { method: 'POST' });
                const pick = await pickRes.json();
                if (pick.error || pick.cancelled || !pick.path) return;

                const scanRes = await fetch('/api/desktop/analyze-folder', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: pick.path })
                });
                const scan = await scanRes.json();
                if (scan.error) { alert(scan.error); return; }

                window.location.href = '/analysis/' + scan.analysis_id;
            } catch (err) {
                console.error('Local folder scan failed:', err);
                alert('Failed to start the local scan.');
            }
        }
    };
}

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
