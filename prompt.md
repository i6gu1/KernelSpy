# Black Hat - Full Project Build Prompt

> **Project Name:** Black Hat
> **Type:** Code Analysis Platform
> **Purpose:** Analyze software projects and detect security issues, performance problems, code quality issues, and generate professional reports.

---

## CRITICAL RULES - MUST FOLLOW

1. **Color Scheme:** ONLY BLACK (#000000) background with WHITE (#FFFFFF) text. NO other colors allowed except for severity indicators (Critical=Red, High=Orange, Medium=Yellow, Low=Blue, Info=Gray).
2. **NO AI MENTIONS:** Never use the word "AI" or "Artificial Intelligence" anywhere in the project.
3. **NO FALSE CLAIMS:** Never write "100% secure", "Detects every vulnerability", "Finds all bugs", "Complete protection". Use "Detect common issues", "Identify potential risks", "Static code analysis", "Actionable recommendations".
4. **MULTI-LANGUAGE SUPPORT:** Support 5 languages: English (default), Arabic, Russian, French, Spanish.
5. **RTL SUPPORT:** Arabic must use Right-to-Left (RTL) layout with proper text alignment and mirrored UI elements.
6. **EXACT TEXT PROVIDED:** Use ONLY the exact text provided in the Text Content section below for each language. Do not modify, rephrase, or add any user-facing text.
7. **Images:** Place all images in `ui/pic/` folder. Use artistic image placement throughout the design.
8. **Animations:** Add smooth CSS animations for a premium feel worth $4000+.
9. **Premium Design:** The website must look like a $4000+ premium product - luxurious, professional, and polished.

---

## TECHNOLOGY STACK

### Backend
- **Language:** Go (Golang)
- **Framework:** Fiber (Express-like framework for Go)
- **Why:** Extremely fast, single binary, no node_modules, low RAM usage, perfect for concurrent analysis operations

### Frontend
- **Template Engine:** Go Templates (html/template)
- **Interactivity:** HTMX for dynamic content
- **Enhancement:** Alpine.js for richer UI interactions
- **Styling:** Custom CSS (NO Bootstrap, NO Tailwind, NO external CSS frameworks)
- **Internationalization:** Custom i18n system with JSON translation files
- **NO React, NO Next.js, NO Vue**

### Database
- **Primary:** PostgreSQL
  - Stores: Users, Projects, Analysis Results, Reports
- **Cache:** Redis
  - Used for: Long-running analysis caching, session management

### Analysis Tools (Installed via Docker)
1. **Semgrep** - Security scanning (XSS, SQL Injection, Command Injection, SSRF, Secrets, Hardcoded Passwords)
2. **Trivy** - Dependency vulnerabilities, Docker images, CVEs
3. **Gitleaks** - API Keys, AWS Keys, Tokens, Passwords
4. **ESLint** - JavaScript/TypeScript analysis
5. **golangci-lint** - Go analysis
6. **Bandit** - Python analysis
7. **Clippy** - Rust analysis
8. **PMD** - Java analysis
9. **PHPStan** - PHP analysis

### Infrastructure
- **Container:** Docker (for running analysis tools in sandboxed environments)
- **Git Integration:** Go git libraries for repository cloning
- **Concurrency:** Go Goroutines for parallel tool execution
- **Deployment:** Render.com compatible

---

## PROJECT FILE STRUCTURE

```
black-hat/
├── main.go                          # Application entry point
├── go.mod                           # Go module definition
├── go.sum                           # Go module checksums
├── Dockerfile                       # Docker configuration for deployment
├── docker-compose.yml               # Local development setup
├── .dockerignore                    # Docker ignore file
├── .gitignore                       # Git ignore file
├── render.yaml                      # Render deployment configuration
├── README.md                        # Project documentation
├── LICENSE                          # MIT License
│
├── config/
│   ├── config.go                    # Configuration loading
│   └── config.example.env           # Example environment variables
│
├── i18n/                            # Internationalization folder
│   ├── i18n.go                      # i18n loader and helper functions
│   ├── en.json                      # English translations
│   ├── ar.json                      # Arabic translations
│   ├── ru.json                      # Russian translations
│   ├── fr.json                      # French translations
│   └── es.json                      # Spanish translations
│
├── handlers/
│   ├── home.go                      # Home page handler
│   ├── upload.go                    # File upload handler
│   ├── analysis.go                  # Analysis page handler
│   ├── dashboard.go                 # Dashboard handler
│   ├── reports.go                   # Report generation handler
│   └── api.go                       # API endpoints
│
├── models/
│   ├── project.go                   # Project model
│   ├── analysis.go                  # Analysis results model
│   ├── finding.go                   # Security/Quality findings model
│   └── report.go                    # Report model
│
├── services/
│   ├── analyzer.go                  # Main analysis orchestrator
│   ├── semgrep.go                   # Semgrep integration
│   ├── trivy.go                     # Trivy integration
│   ├── gitleaks.go                  # Gitleaks integration
│   ├── eslint.go                    # ESLint integration
│   ├── golangci.go                  # golangci-lint integration
│   ├── bandit.go                    # Bandit integration
│   ├── clippy.go                    # Clippy integration
│   ├── pmd.go                       # PMD integration
│   ├── phpstan.go                   # PHPStan integration
│   ├── detector.go                  # Language/Framework detector
│   ├── extractor.go                 # ZIP extraction service
│   └── reporter.go                  # Report generation service
│
├── database/
│   ├── postgres.go                   # PostgreSQL connection and migrations
│   └── redis.go                     # Redis connection
│
├── middleware/
│   └── middleware.go                 # HTTP middleware
│
├── templates/
│   ├── layouts/
│   │   └── base.html                # Base layout template
│   ├── partials/
│   │   ├── header.html              # Navigation header
│   │   ├── footer.html              # Footer with developer info
│   │   ├── hero.html                # Hero section
│   │   ├── features.html            # Features section
│   │   ├── how-it-works.html        # How it works section
│   │   └── stats.html               # Statistics section
│   ├── pages/
│   │   ├── home.html                # Landing page
│   │   ├── upload.html              # Upload page
│   │   ├── analysis.html            # Analysis progress page
│   │   ├── results.html             # Analysis results page
│   │   └── report.html              # Report view page
│   └── components/
│       ├── security-card.html       # Security finding card
│       ├── quality-card.html        # Quality issue card
│       ├── dependency-card.html     # Dependency vulnerability card
│       ├── severity-badge.html      # Severity indicator badge
│       ├── progress-bar.html        # Analysis progress bar
│       ├── stat-card.html           # Statistics card
│       └── language-switcher.html   # Language selector dropdown
│
├── static/
│   ├── css/
│   │   ├── main.css                 # Main styles
│   │   ├── animations.css           # Animation definitions
│   │   ├── responsive.css           # Responsive design
│   │   └── rtl.css                  # RTL styles for Arabic
│   ├── js/
│   │   ├── alpine.js                # Alpine.js (local copy)
│   │   └── app.js                   # Custom JavaScript with i18n
│   └── ui/
│       └── pic/                     # Images folder
│           ├── logo.svg             # Black Hat logo
│           ├── hero-bg.svg          # Hero background pattern
│           ├── security-icon.svg    # Security feature icon
│           ├── quality-icon.svg     # Quality feature icon
│           ├── dependency-icon.svg  # Dependency feature icon
│           ├── report-icon.svg      # Report feature icon
│           ├── upload-icon.svg      # Upload illustration
│           ├── github-icon.svg      # GitHub icon for footer
│           └── instagram-icon.svg   # Instagram icon for footer
│
└── uploads/                         # Temporary upload directory
    └── .gitkeep
```

---

## INTERNATIONALIZATION (i18n)

### Supported Languages
| Language | Code | Direction | Default |
|----------|------|-----------|---------|
| English | en | LTR | Yes |
| Arabic | ar | RTL | No |
| Russian | ru | LTR | No |
| French | fr | LTR | No |
| Spanish | es | LTR | No |

### Language Switcher Implementation

**Location:** Top-right corner of the header, next to navigation links.

**Design:**
```html
<!-- Language Switcher Component -->
<div class="language-switcher" x-data="{ open: false }">
    <button @click="open = !open" class="lang-btn">
        <span x-text="getCurrentLangName()"></span>
        <svg class="arrow" :class="{ 'rotate': open }">...</svg>
    </button>
    <div x-show="open" @click.away="open = false" class="lang-dropdown">
        <a href="#" @click.prevent="setLang('en')">English</a>
        <a href="#" @click.prevent="setLang('ar')">العربية</a>
        <a href="#" @click.prevent="setLang('ru')">Русский</a>
        <a href="#" @click.prevent="setLang('fr')">Français</a>
        <a href="#" @click.prevent="setLang('es')">Español</a>
    </div>
</div>
```

### i18n Go Implementation

```go
// i18n/i18n.go
package i18n

import (
    "encoding/json"
    "os"
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
        json.Unmarshal(data, &translations)
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
    // Fallback to English
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
```

### Middleware for Language Detection

```go
// middleware/i18n.go
func I18nMiddleware(c *fiber.Ctx) error {
    // 1. Check query parameter ?lang=ar
    // 2. Check cookie
    // 3. Check Accept-Language header
    // 4. Default to English
    
    lang := c.Query("lang")
    if lang == "" {
        lang = c.Cookies("lang")
    }
    if lang == "" {
        lang = detectFromHeader(c.Get("Accept-Language"))
    }
    if lang == "" || !isValidLang(lang) {
        lang = "en"
    }
    
    // Set language in context
    c.Locals("lang", lang)
    c.Locals("dir", i18n.GetInstance().GetDir(lang))
    
    // Set cookie for persistence
    c.Cookie(&fiber.Cookie{
        Name:    "lang",
        Value:   lang,
        Expires: time.Now().Add(365 * 24 * time.Hour),
    })
    
    return c.Next()
}
```

### RTL Support (Arabic)

```css
/* rtl.css - Loaded only for Arabic */
[dir="rtl"] {
    direction: rtl;
    text-align: right;
}

[dir="rtl"] .nav-links {
    flex-direction: row-reverse;
}

[dir="rtl"] .feature-card {
    text-align: right;
}

[dir="rtl"] .sidebar {
    margin-right: 0;
    margin-left: 1rem;
}

[dir="rtl"] table th,
[dir="rtl"] table td {
    text-align: right;
}

[dir="rtl"] .severity-badge {
    margin-right: 0;
    margin-left: 0.5rem;
}

/* Mirror animations for RTL */
[dir="rtl"] .slide-in {
    animation-name: slideInRight;
}

@keyframes slideInRight {
    from {
        opacity: 0;
        transform: translateX(50px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}
```

---

## EXACT TEXT CONTENT FOR THE WEBSITE

> **IMPORTANT:** Use ONLY these exact texts. Do not modify, rephrase, or add any extra text.

---

## TRANSLATION FILES

### en.json (English)
```json
{
    "nav.home": "Home",
    "nav.features": "Features",
    "nav.howItWorks": "How It Works",
    "nav.upload": "Upload",
    "nav.dashboard": "Dashboard",
    
    "hero.title": "Analyze Your Code. Improve Quality. Detect Risks.",
    "hero.description": "Upload your project or connect a Git repository to analyze code quality, security issues, dependency vulnerabilities, and project structure using trusted analysis tools.",
    "hero.analyzeProject": "Analyze Project",
    "hero.connectRepo": "Connect Repository",
    "hero.viewSample": "View Sample Report",
    
    "features.title": "Features",
    "features.security.title": "Security Analysis",
    "features.security.description": "Scan your project for common security issues, exposed secrets, and known dependency vulnerabilities.",
    "features.quality.title": "Code Quality",
    "features.quality.description": "Identify maintainability issues, duplicated code, unused files, and coding best practices.",
    "features.dependency.title": "Dependency Analysis",
    "features.dependency.description": "Review third-party packages and detect publicly known vulnerabilities.",
    "features.reports.title": "Reports",
    "features.reports.description": "Export detailed reports in PDF, HTML, or JSON formats.",
    
    "howItWorks.title": "How It Works",
    "howItWorks.step1.title": "Step 1",
    "howItWorks.step1.description": "Upload a ZIP archive or connect your repository.",
    "howItWorks.step2.title": "Step 2",
    "howItWorks.step2.description": "The project is analyzed using multiple static analysis tools.",
    "howItWorks.step3.title": "Step 3",
    "howItWorks.step3.description": "Results are collected into a single report.",
    "howItWorks.step4.title": "Step 4",
    "howItWorks.step4.description": "Review findings and prioritize improvements.",
    
    "upload.title": "Upload Project",
    "upload.dragDrop": "Drag and drop your ZIP archive here",
    "upload.or": "or",
    "upload.chooseFile": "Choose File",
    "upload.maxSize": "Maximum upload size: 50MB",
    "upload.supportedFormat": "Supported archive format: ZIP",
    
    "analysis.title": "Project Analysis",
    "analysis.preparing": "Preparing...",
    "analysis.extracting": "Extracting project...",
    "analysis.running": "Running analyzers...",
    "analysis.collecting": "Collecting results...",
    "analysis.generating": "Generating report...",
    "analysis.completed": "Analysis completed.",
    
    "dashboard.title": "Analysis Summary",
    "dashboard.securityFindings": "Security Findings",
    "dashboard.qualityIssues": "Code Quality Issues",
    "dashboard.dependencyVulns": "Dependency Vulnerabilities",
    "dashboard.filesScanned": "Files Scanned",
    "dashboard.supportedLanguages": "Supported Languages",
    "dashboard.analysisDuration": "Analysis Duration",
    
    "security.title": "Security Findings",
    "security.possibleIssues": "Possible Security Issues",
    "security.severity.critical": "Critical",
    "security.severity.high": "High",
    "security.severity.medium": "Medium",
    "security.severity.low": "Low",
    "security.severity.info": "Informational",
    "security.columns.rule": "Rule",
    "security.columns.file": "File",
    "security.columns.line": "Line",
    "security.columns.severity": "Severity",
    "security.columns.description": "Description",
    "security.columns.recommendation": "Recommendation",
    
    "quality.title": "Code Quality",
    "quality.maintainability": "Maintainability",
    "quality.metrics.duplicated": "Duplicated Code",
    "quality.metrics.unusedImports": "Unused Imports",
    "quality.metrics.unusedVars": "Unused Variables",
    "quality.metrics.deadCode": "Dead Code",
    "quality.metrics.longFunctions": "Long Functions",
    "quality.metrics.largeFiles": "Large Files",
    "quality.metrics.complexFunctions": "Complex Functions",
    "quality.metrics.styleIssues": "Style Issues",
    
    "dependencies.title": "Dependency Analysis",
    "dependencies.columns.package": "Package",
    "dependencies.columns.installed": "Installed Version",
    "dependencies.columns.patched": "Patched Version",
    "dependencies.columns.severity": "Severity",
    "dependencies.columns.reference": "Reference",
    
    "projectInfo.title": "Project Information",
    "projectInfo.structure": "Project Structure",
    "projectInfo.languages": "Programming Languages",
    "projectInfo.frameworks": "Framework Detection",
    "projectInfo.configFiles": "Configuration Files",
    "projectInfo.totalFiles": "Total Files",
    "projectInfo.totalLines": "Total Lines of Code",
    "projectInfo.largestFiles": "Largest Files",
    
    "reports.title": "Download Report",
    "reports.pdf": "Export as PDF",
    "reports.html": "Export as HTML",
    "reports.json": "Export as JSON",
    
    "empty.title": "No analysis available.",
    "empty.description": "Upload a project to begin.",
    
    "errors.uploadFailed": "Upload failed.",
    "errors.unsupportedArchive": "Unsupported archive.",
    "errors.analysisFailed": "Analysis failed.",
    "errors.unableToAnalyze": "Unable to analyze the project.",
    "errors.tryAgain": "Please try again later.",
    
    "success.uploaded": "Project uploaded successfully.",
    "success.analysisCompleted": "Analysis completed successfully.",
    "success.reportGenerated": "Report generated successfully.",
    
    "footer.tagline": "Built for developers.",
    "footer.poweredBy": "Powered by trusted static analysis tools.",
    "footer.privacy": "Privacy first.",
    "footer.processNote": "Your project is processed only for analysis.",
    "footer.developedBy": "Developed by The L house",
    "footer.developer1": "Mohammed Aloush",
    "footer.developer2": "AbdulRahman Bakir",
    "footer.developer3": "Maria Mohammed",
    "footer.openSource": "Open Source Project",
    "footer.github": "GitHub",
    "footer.email": "Email",
    "footer.instagram": "Instagram"
}
```

### ar.json (Arabic)
```json
{
    "nav.home": "الرئيسية",
    "nav.features": "المميزات",
    "nav.howItWorks": "كيف يعمل",
    "nav.upload": "رفع مشروع",
    "nav.dashboard": "لوحة التحكم",
    
    "hero.title": "حلل كودك. حسّن الجودة. اكتشف المخاطر.",
    "hero.description": "ارفع مشروعك أو اربط مستودع Git لتحليل جودة الكود، مشاكل الأمان، ثغرات التبعيات، وهيكل المشروع باستخدام أدوات تحليل موثوقة.",
    "hero.analyzeProject": "تحليل المشروع",
    "hero.connectRepo": "ربط المستودع",
    "hero.viewSample": "عرض تقرير تجريبي",
    
    "features.title": "المميزات",
    "features.security.title": "تحليل الأمان",
    "features.security.description": "فحص مشروعك بحثاً عن مشاكل الأمان الشائعة، الأسرار المكشوفة، وثغرات التبعيات المعروفة.",
    "features.quality.title": "جودة الكود",
    "features.quality.description": "تحديد مشاكل الصيانة، الكود المكرر، الملفات غير المستخدمة، وأفضل ممارسات البرمجة.",
    "features.dependency.title": "تحليل التبعيات",
    "features.dependency.description": "مراجعة الحزم الخارجية واكتشاف الثغرات المعروفة علنياً.",
    "features.reports.title": "التقارير",
    "features.reports.description": "تصدير تقارير مفصلة بصيغ PDF أو HTML أو JSON.",
    
    "howItWorks.title": "كيف يعمل",
    "howItWorks.step1.title": "الخطوة 1",
    "howItWorks.step1.description": "ارفع أرشيف ZIP أو اربط مستودعك.",
    "howItWorks.step2.title": "الخطوة 2",
    "howItWorks.step2.description": "يتم تحليل المشروع باستخدام أدوات تحليل ثابت متعددة.",
    "howItWorks.step3.title": "الخطوة 3",
    "howItWorks.step3.description": "تُجمع النتائج في تقرير واحد.",
    "howItWorks.step4.title": "الخطوة 4",
    "howItWorks.step4.description": "راجع النتائج وحدد أولويات التحسين.",
    
    "upload.title": "رفع مشروع",
    "upload.dragDrop": "اسحب وأفلت أرشيف ZIP هنا",
    "upload.or": "أو",
    "upload.chooseFile": "اختر ملف",
    "upload.maxSize": "الحد الأقصى لحجم الرفع: 50 ميجابايت",
    "upload.supportedFormat": "صيغة الأرشيف المدعومة: ZIP",
    
    "analysis.title": "تحليل المشروع",
    "analysis.preparing": "جاري التحضير...",
    "analysis.extracting": "جاري استخراج المشروع...",
    "analysis.running": "جاري تشغيل محللات...",
    "analysis.collecting": "جاري جمع النتائج...",
    "analysis.generating": "جاري إنشاء التقرير...",
    "analysis.completed": "اكتمل التحليل.",
    
    "dashboard.title": "ملخص التحليل",
    "dashboard.securityFindings": "نتائج الأمان",
    "dashboard.qualityIssues": "مشاكل جودة الكود",
    "dashboard.dependencyVulns": "ثغرات التبعيات",
    "dashboard.filesScanned": "الملفات المفحوصة",
    "dashboard.supportedLanguages": "اللغات المدعومة",
    "dashboard.analysisDuration": "مدة التحليل",
    
    "security.title": "نتائج الأمان",
    "security.possibleIssues": "مشاكل أمنية محتملة",
    "security.severity.critical": "حرج",
    "security.severity.high": "عالي",
    "security.severity.medium": "متوسط",
    "security.severity.low": "منخفض",
    "security.severity.info": "معلومة",
    "security.columns.rule": "القاعدة",
    "security.columns.file": "الملف",
    "security.columns.line": "السطر",
    "security.columns.severity": "الخطورة",
    "security.columns.description": "الوصف",
    "security.columns.recommendation": "التوصية",
    
    "quality.title": "جودة الكود",
    "quality.maintainability": "قابلية الصيانة",
    "quality.metrics.duplicated": "كود مكرر",
    "quality.metrics.unusedImports": "استيرادات غير مستخدمة",
    "quality.metrics.unusedVars": "متغيرات غير مستخدمة",
    "quality.metrics.deadCode": "كود ميت",
    "quality.metrics.longFunctions": "دوال طويلة",
    "quality.metrics.largeFiles": "ملفات كبيرة",
    "quality.metrics.complexFunctions": "دوال معقدة",
    "quality.metrics.styleIssues": "مشاكل الأسلوب",
    
    "dependencies.title": "تحليل التبعيات",
    "dependencies.columns.package": "الحزمة",
    "dependencies.columns.installed": "الإصدار المثبت",
    "dependencies.columns.patched": "الإصدار المُصحح",
    "dependencies.columns.severity": "الخطورة",
    "dependencies.columns.reference": "المرجع",
    
    "projectInfo.title": "معلومات المشروع",
    "projectInfo.structure": "هيكل المشروع",
    "projectInfo.languages": "لغات البرمجة",
    "projectInfo.frameworks": "كشف الأطر",
    "projectInfo.configFiles": "ملفات الإعدادات",
    "projectInfo.totalFiles": "إجمالي الملفات",
    "projectInfo.totalLines": "إجمالي أسطر الكود",
    "projectInfo.largestFiles": "الملفات الأكبر",
    
    "reports.title": "تحميل التقرير",
    "reports.pdf": "تصدير كـ PDF",
    "reports.html": "تصدير كـ HTML",
    "reports.json": "تصدير كـ JSON",
    
    "empty.title": "لا يوجد تحليل متاح.",
    "empty.description": "ارفع مشروعًا للبدء.",
    
    "errors.uploadFailed": "فشل الرفع.",
    "errors.unsupportedArchive": "أرشيف غير مدعوم.",
    "errors.analysisFailed": "فشل التحليل.",
    "errors.unableToAnalyze": "تعذر تحليل المشروع.",
    "errors.tryAgain": "يرجى المحاولة لاحقاً.",
    
    "success.uploaded": "تم رفع المشروع بنجاح.",
    "success.analysisCompleted": "اكتمل التحليل بنجاح.",
    "success.reportGenerated": "تم إنشاء التقرير بنجاح.",
    
    "footer.tagline": "صُمم للمطورين.",
    "footer.poweredBy": "مدعوم بأدوات تحليل ثابت موثوقة.",
    "footer.privacy": "الخصوصية أولاً.",
    "footer.processNote": "مشروعك يُعالج فقط لأغراض التحليل.",
    "footer.developedBy": "تم البرمجة بواسطة The L house",
    "footer.developer1": "محمد علوش",
    "footer.developer2": "عبدالرحمن بكير",
    "footer.developer3": "ماريا محمد",
    "footer.openSource": "مشروع مفتوح المصدر",
    "footer.github": "جيت هاب",
    "footer.email": "البريد الإلكتروني",
    "footer.instagram": "انستغرام"
}
```

### ru.json (Russian)
```json
{
    "nav.home": "Главная",
    "nav.features": "Возможности",
    "nav.howItWorks": "Как это работает",
    "nav.upload": "Загрузить",
    "nav.dashboard": "Панель управления",
    
    "hero.title": "Анализируйте код. Улучшайте качество. Обнаруживайте риски.",
    "hero.description": "Загрузите проект или подключите репозиторий Git для анализа качества кода, проблем безопасности, уязвимостей зависимостей и структуры проекта с использованием проверенных инструментов анализа.",
    "hero.analyzeProject": "Анализировать проект",
    "hero.connectRepo": "Подключить репозиторий",
    "hero.viewSample": "Посмотреть пример отчёта",
    
    "features.title": "Возможности",
    "features.security.title": "Анализ безопасности",
    "features.security.description": "Сканирование проекта на наличие распространённых проблем безопасности, открытых секретов и известных уязвимостей зависимостей.",
    "features.quality.title": "Качество кода",
    "features.quality.description": "Выявление проблем с поддерживаемостью, дублированным кодом, неиспользуемыми файлами и лучшими практиками программирования.",
    "features.dependency.title": "Анализ зависимостей",
    "features.dependency.description": "Проверка сторонних пакетов и обнаружение публично известных уязвимостей.",
    "features.reports.title": "Отчёты",
    "features.reports.description": "Экспорт подробных отчётов в форматах PDF, HTML или JSON.",
    
    "howItWorks.title": "Как это работает",
    "howItWorks.step1.title": "Шаг 1",
    "howItWorks.step1.description": "Загрузите архив ZIP или подключите свой репозиторий.",
    "howItWorks.step2.title": "Шаг 2",
    "howItWorks.step2.description": "Проект анализируется с использованием нескольких инструментов статического анализа.",
    "howItWorks.step3.title": "Шаг 3",
    "howItWorks.step3.description": "Результаты собираются в один отчёт.",
    "howItWorks.step4.title": "Шаг 4",
    "howItWorks.step4.description": "Просмотрите результаты и определите приоритеты улучшений.",
    
    "upload.title": "Загрузка проекта",
    "upload.dragDrop": "Перетащите архив ZIP сюда",
    "upload.or": "или",
    "upload.chooseFile": "Выберите файл",
    "upload.maxSize": "Максимальный размер: 50 МБ",
    "upload.supportedFormat": "Поддерживаемый формат: ZIP",
    
    "analysis.title": "Анализ проекта",
    "analysis.preparing": "Подготовка...",
    "analysis.extracting": "Извлечение проекта...",
    "analysis.running": "Запуск анализаторов...",
    "analysis.collecting": "Сбор результатов...",
    "analysis.generating": "Создание отчёта...",
    "analysis.completed": "Анализ завершён.",
    
    "dashboard.title": "Сводка анализа",
    "dashboard.securityFindings": "Результаты безопасности",
    "dashboard.qualityIssues": "Проблемы качества кода",
    "dashboard.dependencyVulns": "Уязвимости зависимостей",
    "dashboard.filesScanned": "Просканированные файлы",
    "dashboard.supportedLanguages": "Поддерживаемые языки",
    "dashboard.analysisDuration": "Длительность анализа",
    
    "security.title": "Результаты безопасности",
    "security.possibleIssues": "Возможные проблемы безопасности",
    "security.severity.critical": "Критический",
    "security.severity.high": "Высокий",
    "security.severity.medium": "Средний",
    "security.severity.low": "Низкий",
    "security.severity.info": "Информационный",
    "security.columns.rule": "Правило",
    "security.columns.file": "Файл",
    "security.columns.line": "Строка",
    "security.columns.severity": "Серьёзность",
    "security.columns.description": "Описание",
    "security.columns.recommendation": "Рекомендация",
    
    "quality.title": "Качество кода",
    "quality.maintainability": "Поддерживаемость",
    "quality.metrics.duplicated": "Дублированный код",
    "quality.metrics.unusedImports": "Неиспользуемые импорты",
    "quality.metrics.unusedVars": "Неиспользуемые переменные",
    "quality.metrics.deadCode": "Мёртвый код",
    "quality.metrics.longFunctions": "Длинные функции",
    "quality.metrics.largeFiles": "Большие файлы",
    "quality.metrics.complexFunctions": "Сложные функции",
    "quality.metrics.styleIssues": "Проблемы стиля",
    
    "dependencies.title": "Анализ зависимостей",
    "dependencies.columns.package": "Пакет",
    "dependencies.columns.installed": "Установленная версия",
    "dependencies.columns.patched": "Исправленная версия",
    "dependencies.columns.severity": "Серьёзность",
    "dependencies.columns.reference": "Ссылка",
    
    "projectInfo.title": "Информация о проекте",
    "projectInfo.structure": "Структура проекта",
    "projectInfo.languages": "Языки программирования",
    "projectInfo.frameworks": "Обнаружение фреймворков",
    "projectInfo.configFiles": "Файлы конфигурации",
    "projectInfo.totalFiles": "Всего файлов",
    "projectInfo.totalLines": "Всего строк кода",
    "projectInfo.largestFiles": "Крупнейшие файлы",
    
    "reports.title": "Скачать отчёт",
    "reports.pdf": "Экспорт в PDF",
    "reports.html": "Экспорт в HTML",
    "reports.json": "Экспорт в JSON",
    
    "empty.title": "Анализ недоступен.",
    "empty.description": "Загрузите проект для начала.",
    
    "errors.uploadFailed": "Ошибка загрузки.",
    "errors.unsupportedArchive": "Неподдерживаемый архив.",
    "errors.analysisFailed": "Ошибка анализа.",
    "errors.unableToAnalyze": "Не удалось проанализировать проект.",
    "errors.tryAgain": "Пожалуйста, попробуйте позже.",
    
    "success.uploaded": "Проект успешно загружен.",
    "success.analysisCompleted": "Анализ успешно завершён.",
    "success.reportGenerated": "Отчёт успешно создан.",
    
    "footer.tagline": "Создано для разработчиков.",
    "footer.poweredBy": "Работает на проверенных инструментах статического анализа.",
    "footer.privacy": "Конфиденциальность прежде всего.",
    "footer.processNote": "Ваш проект обрабатывается только для анализа.",
    "footer.developedBy": "Разработано The L house",
    "footer.developer1": "Mohammed Aloush",
    "footer.developer2": "AbdulRahman Bakir",
    "footer.developer3": "Maria Mohammed",
    "footer.openSource": "Открытый исходный код",
    "footer.github": "GitHub",
    "footer.email": "Email",
    "footer.instagram": "Instagram"
}
```

### fr.json (French)
```json
{
    "nav.home": "Accueil",
    "nav.features": "Fonctionnalités",
    "nav.howItWorks": "Comment ça marche",
    "nav.upload": "Téléverser",
    "nav.dashboard": "Tableau de bord",
    
    "hero.title": "Analysez votre code. Améliorez la qualité. Détectez les risques.",
    "hero.description": "Téléversez votre projet ou connectez un dépôt Git pour analyser la qualité du code, les problèmes de sécurité, les vulnérabilités des dépendances et la structure du projet en utilisant des outils d'analyse de confiance.",
    "hero.analyzeProject": "Analyser le projet",
    "hero.connectRepo": "Connecter le dépôt",
    "hero.viewSample": "Voir un rapport exemple",
    
    "features.title": "Fonctionnalités",
    "features.security.title": "Analyse de sécurité",
    "features.security.description": "Scanner votre projet pour les problèmes de sécurité courants, les secrets exposés et les vulnérabilités connues des dépendances.",
    "features.quality.title": "Qualité du code",
    "features.quality.description": "Identifier les problèmes de maintenabilité, le code dupliqué, les fichiers inutilisés et les meilleures pratiques de codage.",
    "features.dependency.title": "Analyse des dépendances",
    "features.dependency.description": "Examiner les packages tiers et détecter les vulnérabilités publiquement connues.",
    "features.reports.title": "Rapports",
    "features.reports.description": "Exporter des rapports détaillés aux formats PDF, HTML ou JSON.",
    
    "howItWorks.title": "Comment ça marche",
    "howItWorks.step1.title": "Étape 1",
    "howItWorks.step1.description": "Téléversez une archive ZIP ou connectez votre dépôt.",
    "howItWorks.step2.title": "Étape 2",
    "howItWorks.step2.description": "Le projet est analysé en utilisant plusieurs outils d'analyse statique.",
    "howItWorks.step3.title": "Étape 3",
    "howItWorks.step3.description": "Les résultats sont collectés dans un seul rapport.",
    "howItWorks.step4.title": "Étape 4",
    "howItWorks.step4.description": "Examinez les résultats et priorisez les améliorations.",
    
    "upload.title": "Téléverser un projet",
    "upload.dragDrop": "Glissez et déposez votre archive ZIP ici",
    "upload.or": "ou",
    "upload.chooseFile": "Choisir un fichier",
    "upload.maxSize": "Taille maximale: 50 Mo",
    "upload.supportedFormat": "Format supporté: ZIP",
    
    "analysis.title": "Analyse du projet",
    "analysis.preparing": "Préparation...",
    "analysis.extracting": "Extraction du projet...",
    "analysis.running": "Exécution des analyseurs...",
    "analysis.collecting": "Collecte des résultats...",
    "analysis.generating": "Génération du rapport...",
    "analysis.completed": "Analyse terminée.",
    
    "dashboard.title": "Résumé de l'analyse",
    "dashboard.securityFindings": "Résultats de sécurité",
    "dashboard.qualityIssues": "Problèmes de qualité du code",
    "dashboard.dependencyVulns": "Vulnérabilités des dépendances",
    "dashboard.filesScanned": "Fichiers analysés",
    "dashboard.supportedLanguages": "Langages supportés",
    "dashboard.analysisDuration": "Durée de l'analyse",
    
    "security.title": "Résultats de sécurité",
    "security.possibleIssues": "Problèmes de sécurité possibles",
    "security.severity.critical": "Critique",
    "security.severity.high": "Élevé",
    "security.severity.medium": "Moyen",
    "security.severity.low": "Faible",
    "security.severity.info": "Informationnel",
    "security.columns.rule": "Règle",
    "security.columns.file": "Fichier",
    "security.columns.line": "Ligne",
    "security.columns.severity": "Gravité",
    "security.columns.description": "Description",
    "security.columns.recommendation": "Recommandation",
    
    "quality.title": "Qualité du code",
    "quality.maintainability": "Maintenabilité",
    "quality.metrics.duplicated": "Code dupliqué",
    "quality.metrics.unusedImports": "Imports inutilisés",
    "quality.metrics.unusedVars": "Variables inutilisées",
    "quality.metrics.deadCode": "Code mort",
    "quality.metrics.longFunctions": "Fonctions longues",
    "quality.metrics.largeFiles": "Fichiers volumineux",
    "quality.metrics.complexFunctions": "Fonctions complexes",
    "quality.metrics.styleIssues": "Problèmes de style",
    
    "dependencies.title": "Analyse des dépendances",
    "dependencies.columns.package": "Package",
    "dependencies.columns.installed": "Version installée",
    "dependencies.columns.patched": "Version corrigée",
    "dependencies.columns.severity": "Gravité",
    "dependencies.columns.reference": "Référence",
    
    "projectInfo.title": "Informations du projet",
    "projectInfo.structure": "Structure du projet",
    "projectInfo.languages": "Langages de programmation",
    "projectInfo.frameworks": "Détection de frameworks",
    "projectInfo.configFiles": "Fichiers de configuration",
    "projectInfo.totalFiles": "Total des fichiers",
    "projectInfo.totalLines": "Total des lignes de code",
    "projectInfo.largestFiles": "Plus grands fichiers",
    
    "reports.title": "Télécharger le rapport",
    "reports.pdf": "Exporter en PDF",
    "reports.html": "Exporter en HTML",
    "reports.json": "Exporter en JSON",
    
    "empty.title": "Aucune analyse disponible.",
    "empty.description": "Téléversez un projet pour commencer.",
    
    "errors.uploadFailed": "Échec du téléversement.",
    "errors.unsupportedArchive": "Archive non supportée.",
    "errors.analysisFailed": "Échec de l'analyse.",
    "errors.unableToAnalyze": "Impossible d'analyser le projet.",
    "errors.tryAgain": "Veuillez réessayer plus tard.",
    
    "success.uploaded": "Projet téléversé avec succès.",
    "success.analysisCompleted": "Analyse terminée avec succès.",
    "success.reportGenerated": "Rapport généré avec succès.",
    
    "footer.tagline": "Conçu pour les développeurs.",
    "footer.poweredBy": "Propulsé par des outils d'analyse statique de confiance.",
    "footer.privacy": "Confidentialité d'abord.",
    "footer.processNote": "Votre projet est traité uniquement pour l'analyse.",
    "footer.developedBy": "Développé par The L house",
    "footer.developer1": "Mohammed Aloush",
    "footer.developer2": "AbdulRahman Bakir",
    "footer.developer3": "Maria Mohammed",
    "footer.openSource": "Projet open source",
    "footer.github": "GitHub",
    "footer.email": "Email",
    "footer.instagram": "Instagram"
}
```

### es.json (Spanish)
```json
{
    "nav.home": "Inicio",
    "nav.features": "Características",
    "nav.howItWorks": "Cómo funciona",
    "nav.upload": "Subir",
    "nav.dashboard": "Panel de control",
    
    "hero.title": "Analiza tu código. Mejora la calidad. Detecta riesgos.",
    "hero.description": "Sube tu proyecto o conecta un repositorio Git para analizar la calidad del código, problemas de seguridad, vulnerabilidades de dependencias y la estructura del proyecto utilizando herramientas de análisis confiables.",
    "hero.analyzeProject": "Analizar proyecto",
    "hero.connectRepo": "Conectar repositorio",
    "hero.viewSample": "Ver informe de ejemplo",
    
    "features.title": "Características",
    "features.security.title": "Análisis de seguridad",
    "features.security.description": "Escanear tu proyecto en busca de problemas de seguridad comunes, secretos expuestos y vulnerabilidades conocidas de dependencias.",
    "features.quality.title": "Calidad del código",
    "features.quality.description": "Identificar problemas de mantenibilidad, código duplicado, archivos no utilizados y mejores prácticas de programación.",
    "features.dependency.title": "Análisis de dependencias",
    "features.dependency.description": "Revisar paquetes de terceros y detectar vulnerabilidades públicamente conocidas.",
    "features.reports.title": "Informes",
    "features.reports.description": "Exportar informes detallados en formatos PDF, HTML o JSON.",
    
    "howItWorks.title": "Cómo funciona",
    "howItWorks.step1.title": "Paso 1",
    "howItWorks.step1.description": "Sube un archivo ZIP o conecta tu repositorio.",
    "howItWorks.step2.title": "Paso 2",
    "howItWorks.step2.description": "El proyecto se analiza utilizando múltiples herramientas de análisis estático.",
    "howItWorks.step3.title": "Paso 3",
    "howItWorks.step3.description": "Los resultados se recopilan en un solo informe.",
    "howItWorks.step4.title": "Paso 4",
    "howItWorks.step4.description": "Revisa los hallazgos y prioriza las mejoras.",
    
    "upload.title": "Subir proyecto",
    "upload.dragDrop": "Arrastra y suelta tu archivo ZIP aquí",
    "upload.or": "o",
    "upload.chooseFile": "Seleccionar archivo",
    "upload.maxSize": "Tamaño máximo: 50 MB",
    "upload.supportedFormat": "Formato soportado: ZIP",
    
    "analysis.title": "Análisis del proyecto",
    "analysis.preparing": "Preparando...",
    "analysis.extracting": "Extrayendo proyecto...",
    "analysis.running": "Ejecutando analizadores...",
    "analysis.collecting": "Recopilando resultados...",
    "analysis.generating": "Generando informe...",
    "analysis.completed": "Análisis completado.",
    
    "dashboard.title": "Resumen del análisis",
    "dashboard.securityFindings": "Hallazgos de seguridad",
    "dashboard.qualityIssues": "Problemas de calidad del código",
    "dashboard.dependencyVulns": "Vulnerabilidades de dependencias",
    "dashboard.filesScanned": "Archivos escaneados",
    "dashboard.supportedLanguages": "Lenguajes soportados",
    "dashboard.analysisDuration": "Duración del análisis",
    
    "security.title": "Hallazgos de seguridad",
    "security.possibleIssues": "Posibles problemas de seguridad",
    "security.severity.critical": "Crítico",
    "security.severity.high": "Alto",
    "security.severity.medium": "Medio",
    "security.severity.low": "Bajo",
    "security.severity.info": "Informativo",
    "security.columns.rule": "Regla",
    "security.columns.file": "Archivo",
    "security.columns.line": "Línea",
    "security.columns.severity": "Gravedad",
    "security.columns.description": "Descripción",
    "security.columns.recommendation": "Recomendación",
    
    "quality.title": "Calidad del código",
    "quality.maintainability": "Mantenibilidad",
    "quality.metrics.duplicated": "Código duplicado",
    "quality.metrics.unusedImports": "Importaciones no utilizadas",
    "quality.metrics.unusedVars": "Variables no utilizadas",
    "quality.metrics.deadCode": "Código muerto",
    "quality.metrics.longFunctions": "Funciones largas",
    "quality.metrics.largeFiles": "Archivos grandes",
    "quality.metrics.complexFunctions": "Funciones complejas",
    "quality.metrics.styleIssues": "Problemas de estilo",
    
    "dependencies.title": "Análisis de dependencias",
    "dependencies.columns.package": "Paquete",
    "dependencies.columns.installed": "Versión instalada",
    "dependencies.columns.patched": "Versión corregida",
    "dependencies.columns.severity": "Gravedad",
    "dependencies.columns.reference": "Referencia",
    
    "projectInfo.title": "Información del proyecto",
    "projectInfo.structure": "Estructura del proyecto",
    "projectInfo.languages": "Lenguajes de programación",
    "projectInfo.frameworks": "Detección de frameworks",
    "projectInfo.configFiles": "Archivos de configuración",
    "projectInfo.totalFiles": "Total de archivos",
    "projectInfo.totalLines": "Total de líneas de código",
    "projectInfo.largestFiles": "Archivos más grandes",
    
    "reports.title": "Descargar informe",
    "reports.pdf": "Exportar como PDF",
    "reports.html": "Exportar como HTML",
    "reports.json": "Exportar como JSON",
    
    "empty.title": "No hay análisis disponible.",
    "empty.description": "Sube un proyecto para comenzar.",
    
    "errors.uploadFailed": "Error al subir.",
    "errors.unsupportedArchive": "Archivo no soportado.",
    "errors.analysisFailed": "Error en el análisis.",
    "errors.unableToAnalyze": "No se pudo analizar el proyecto.",
    "errors.tryAgain": "Por favor, intenta de nuevo más tarde.",
    
    "success.uploaded": "Proyecto subido exitosamente.",
    "success.analysisCompleted": "Análisis completado exitosamente.",
    "success.reportGenerated": "Informe generado exitosamente.",
    
    "footer.tagline": "Diseñado para desarrolladores.",
    "footer.poweredBy": "Impulsado por herramientas de análisis estático confiables.",
    "footer.privacy": "Privacidad primero.",
    "footer.processNote": "Tu proyecto se procesa solo para análisis.",
    "footer.developedBy": "Desarrollado por The L house",
    "footer.developer1": "Mohammed Aloush",
    "footer.developer2": "AbdulRahman Bakir",
    "footer.developer3": "Maria Mohammed",
    "footer.openSource": "Proyecto de código abierto",
    "footer.github": "GitHub",
    "footer.email": "Email",
    "footer.instagram": "Instagram"
}
```

---

## Landing Page - Hero Section

**Main Title:**
```
Analyze Your Code. Improve Quality. Detect Risks.
```

**Description:**
```
Upload your project or connect a Git repository to analyze code quality, security issues, dependency vulnerabilities, and project structure using trusted analysis tools.
```

**Buttons:**
```
Analyze Project
Connect Repository
View Sample Report
```

### Landing Page - Features Section

**Feature 1 - Security Analysis:**
```
Security Analysis
Scan your project for common security issues, exposed secrets, and known dependency vulnerabilities.
```

**Feature 2 - Code Quality:**
```
Code Quality
Identify maintainability issues, duplicated code, unused files, and coding best practices.
```

**Feature 3 - Dependency Analysis:**
```
Dependency Analysis
Review third-party packages and detect publicly known vulnerabilities.
```

**Feature 4 - Reports:**
```
Reports
Export detailed reports in PDF, HTML, or JSON formats.
```

### Landing Page - How It Works Section

**Step 1:**
```
Step 1
Upload a ZIP archive or connect your repository.
```

**Step 2:**
```
Step 2
The project is analyzed using multiple static analysis tools.
```

**Step 3:**
```
Step 3
Results are collected into a single report.
```

**Step 4:**
```
Step 4
Review findings and prioritize improvements.
```

### Upload Page

**Header:**
```
Upload Project
```

**Drag and Drop Zone:**
```
Drag and drop your ZIP archive here
or
Choose File
Maximum upload size: 50MB
Supported archive format: ZIP
```

### Analysis Page

**Header:**
```
Project Analysis
```

**Status Messages:**
```
Preparing...
Extracting project...
Running analyzers...
Collecting results...
Generating report...
Analysis completed.
```

### Results Page - Dashboard

**Overview Section:**
```
Analysis Summary
```

**Stat Cards:**
```
Security Findings
Code Quality Issues
Dependency Vulnerabilities
Files Scanned
Supported Languages
Analysis Duration
```

### Results Page - Security Section

**Section Header:**
```
Security Findings
Possible Security Issues
```

**Severity Levels:**
```
Critical
High
Medium
Low
Informational
```

**Table Columns:**
```
Rule
File
Line
Severity
Description
Recommendation
```

### Results Page - Code Quality Section

**Section Header:**
```
Code Quality
Maintainability
```

**Quality Metrics:**
```
Duplicated Code
Unused Imports
Unused Variables
Dead Code
Long Functions
Large Files
Complex Functions
Style Issues
```

### Results Page - Dependencies Section

**Section Header:**
```
Dependency Analysis
```

**Table Columns:**
```
Package
Installed Version
Patched Version
Severity
Reference
```

### Results Page - Project Information Section

**Section Header:**
```
Project Information
```

**Project Details:**
```
Project Structure
Programming Languages
Framework Detection
Configuration Files
Total Files
Total Lines of Code
Largest Files
```

### Reports Section

**Download Section:**
```
Download Report
Export as PDF
Export as HTML
Export as JSON
```

### Empty State

```
No analysis available.
Upload a project to begin.
```

### Error Messages

```
Upload failed.
Unsupported archive.
Analysis failed.
Unable to analyze the project.
Please try again later.
```

### Success Messages

```
Project uploaded successfully.
Analysis completed successfully.
Report generated successfully.
```

### Footer Content

**Tagline:**
```
Built for developers.
Powered by trusted static analysis tools.
Privacy first.
Your project is processed only for analysis.
```

**Developer Credit:**
```
Developed by The L house
```

**Developer Names:**
```
Mohammed Aloush
AbdulRahman Bakir
Maria Mohammed
```

**Open Source Notice:**
```
Open Source Project
```

**Links:**
```
GitHub: https://github.com/i6gu1/Black-hat
Email: nvapps@proton.me
Instagram: @izgu_
```

---

## DESIGN SPECIFICATIONS

### Color Palette (STRICT)
```css
:root {
    --bg-primary: #000000;        /* Main background - PURE BLACK */
    --bg-secondary: #0a0a0a;      /* Card backgrounds */
    --bg-tertiary: #111111;       /* Hover states */
    --text-primary: #ffffff;      /* Main text - PURE WHITE */
    --text-secondary: #a0a0a0;    /* Secondary text */
    --text-muted: #666666;        /* Muted text */
    --border-color: #1a1a1a;      /* Borders */
    --accent: #ffffff;            /* Accent - white */
    
    /* Severity Colors (only exceptions to black/white) */
    --critical: #ff0000;          /* Critical severity */
    --high: #ff6600;              /* High severity */
    --medium: #ffcc00;            /* Medium severity */
    --low: #0066ff;               /* Low severity */
    --info: #666666;              /* Informational */
}
```

### Typography
```css
/* Use system fonts for performance */
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;

/* Headings */
h1 { font-size: 3.5rem; font-weight: 800; letter-spacing: -0.02em; }
h2 { font-size: 2.5rem; font-weight: 700; letter-spacing: -0.01em; }
h3 { font-size: 1.5rem; font-weight: 600; }

/* Body */
body { font-size: 1rem; line-height: 1.6; }

/* Code */
code { font-family: 'SF Mono', 'Fira Code', monospace; }
```

### Animations (Premium Feel)

```css
/* Fade In Up Animation */
@keyframes fadeInUp {
    from {
        opacity: 0;
        transform: translateY(30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

/* Fade In Animation */
@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

/* Slide In Left */
@keyframes slideInLeft {
    from {
        opacity: 0;
        transform: translateX(-50px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

/* Pulse Animation for Icons */
@keyframes pulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.05); }
}

/* Glow Effect */
@keyframes glow {
    0%, 100% { box-shadow: 0 0 5px rgba(255,255,255,0.1); }
    50% { box-shadow: 0 0 20px rgba(255,255,255,0.2); }
}

/* Progress Bar Animation */
@keyframes progress {
    from { width: 0%; }
    to { width: 100%; }
}

/* Apply animations to elements */
.animate-fade-in-up {
    animation: fadeInUp 0.6s ease-out forwards;
}

.animate-fade-in {
    animation: fadeIn 0.5s ease-out forwards;
}

.animate-slide-in-left {
    animation: slideInLeft 0.6s ease-out forwards;
}

/* Staggered animations for cards */
.card:nth-child(1) { animation-delay: 0.1s; }
.card:nth-child(2) { animation-delay: 0.2s; }
.card:nth-child(3) { animation-delay: 0.3s; }
.card:nth-child(4) { animation-delay: 0.4s; }

/* Hover effects */
.card:hover {
    transform: translateY(-5px);
    box-shadow: 0 10px 40px rgba(255,255,255,0.1);
    transition: all 0.3s ease;
}

/* Smooth scroll */
html {
    scroll-behavior: smooth;
}
```

### UI Elements Styling

**Cards:**
```css
.card {
    background: #0a0a0a;
    border: 1px solid #1a1a1a;
    border-radius: 12px;
    padding: 2rem;
    transition: all 0.3s ease;
}

.card:hover {
    border-color: #333333;
    box-shadow: 0 8px 32px rgba(255,255,255,0.05);
}
```

**Buttons:**
```css
.btn-primary {
    background: #ffffff;
    color: #000000;
    padding: 12px 24px;
    border-radius: 8px;
    font-weight: 600;
    transition: all 0.3s ease;
}

.btn-primary:hover {
    background: #e0e0e0;
    transform: translateY(-2px);
}

.btn-secondary {
    background: transparent;
    color: #ffffff;
    border: 1px solid #333333;
    padding: 12px 24px;
    border-radius: 8px;
    transition: all 0.3s ease;
}

.btn-secondary:hover {
    border-color: #ffffff;
}
```

**Tables:**
```css
table {
    width: 100%;
    border-collapse: collapse;
}

th {
    background: #0a0a0a;
    color: #ffffff;
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #1a1a1a;
}

td {
    padding: 12px;
    border-bottom: 1px solid #111111;
}

tr:hover {
    background: #0a0a0a;
}
```

**Severity Badges:**
```css
.badge-critical { background: #ff0000; color: #ffffff; }
.badge-high { background: #ff6600; color: #ffffff; }
.badge-medium { background: #ffcc00; color: #000000; }
.badge-low { background: #0066ff; color: #ffffff; }
.badge-info { background: #666666; color: #ffffff; }
```

---

## BACKEND IMPLEMENTATION DETAILS

### main.go
```go
package main

import (
    "log"
    "os"
    
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/compress"
    "github.com/gofiber/fiber/v2/middleware/logger"
    "github.com/gofiber/fiber/v2/middleware/recover"
)

func main() {
    app := fiber.New(fiber.Config{
        AppName:      "Black Hat",
        ServerHeader: "Black Hat",
    })
    
    // Middleware
    app.Use(logger.New())
    app.Use(recover.New())
    app.Use(compress.New())
    
    // Static files
    app.Static("/static", "./static")
    
    // Routes
    setupRoutes(app)
    
    // Start server
    port := os.Getenv("PORT")
    if port == "" {
        port = "3000"
    }
    
    log.Fatal(app.Listen(":" + port))
}
```

### Database Schema (PostgreSQL)

```sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Projects table
CREATE TABLE projects (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    source_type VARCHAR(50) NOT NULL, -- 'zip' or 'git'
    source_url VARCHAR(500),
    file_path VARCHAR(500),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Analysis results table
CREATE TABLE analyses (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES projects(id),
    status VARCHAR(50) NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    files_scanned INTEGER,
    languages_detected TEXT[],
    frameworks_detected TEXT[]
);

-- Security findings table
CREATE TABLE security_findings (
    id SERIAL PRIMARY KEY,
    analysis_id INTEGER REFERENCES analyses(id),
    rule VARCHAR(255) NOT NULL,
    file_path VARCHAR(500),
    line_number INTEGER,
    severity VARCHAR(50) NOT NULL,
    description TEXT,
    recommendation TEXT,
    tool VARCHAR(100)
);

-- Code quality findings table
CREATE TABLE quality_findings (
    id SERIAL PRIMARY KEY,
    analysis_id INTEGER REFERENCES analyses(id),
    category VARCHAR(100) NOT NULL,
    file_path VARCHAR(500),
    line_number INTEGER,
    severity VARCHAR(50),
    description TEXT,
    tool VARCHAR(100)
);

-- Dependency vulnerabilities table
CREATE TABLE dependency_vulnerabilities (
    id SERIAL PRIMARY KEY,
    analysis_id INTEGER REFERENCES analyses(id),
    package_name VARCHAR(255) NOT NULL,
    installed_version VARCHAR(100),
    patched_version VARCHAR(100),
    severity VARCHAR(50),
    reference_url VARCHAR(500),
    tool VARCHAR(100)
);

-- Reports table
CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    analysis_id INTEGER REFERENCES analyses(id),
    format VARCHAR(20) NOT NULL, -- 'pdf', 'html', 'json'
    file_path VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Analysis Service Implementation

The analyzer service should:
1. Detect project language/framework
2. Run appropriate tools in parallel using Goroutines
3. Parse tool outputs into standardized format
4. Store results in database
5. Generate reports

```go
// Pseudocode for analyzer
func AnalyzeProject(projectID int) error {
    // 1. Get project from database
    project := GetProject(projectID)
    
    // 2. Detect language/framework
    langs := DetectLanguages(project.FilePath)
    
    // 3. Run tools in parallel
    var wg sync.WaitGroup
    results := make(chan AnalysisResult)
    
    // Always run these
    wg.Add(3)
    go func() { defer wg.Done(); runSemgrep(project.FilePath, results) }()
    go func() { defer wg.Done(); runTrivy(project.FilePath, results) }()
    go func() { defer wg.Done(); runGitleaks(project.FilePath, results) }()
    
    // Language-specific tools
    for _, lang := range langs {
        switch lang {
        case "javascript":
            wg.Add(1)
            go func() { defer wg.Done(); runESLint(project.FilePath, results) }()
        case "go":
            wg.Add(1)
            go func() { defer wg.Done(); runGolangCI(project.FilePath, results) }()
        // ... other languages
        }
    }
    
    // 4. Wait and collect results
    go func() {
        wg.Wait()
        close(results)
    }()
    
    // 5. Store results and generate report
    for result := range results {
        StoreResult(projectID, result)
    }
    
    GenerateReport(projectID)
    
    return nil
}
```

---

## FRONTEND IMPLEMENTATION DETAILS

### Template Structure

**base.html** - Main layout with:
- Head section with meta tags, CSS links
- Navigation header
- Content block
- Footer with developer info
- Script tags

**home.html** - Landing page with:
- Hero section with animated title and description
- Features grid (4 cards with icons)
- How it works section (4 steps)
- Call to action section

**upload.html** - Upload page with:
- Drag and drop zone
- File input
- Progress indicator

**analysis.html** - Analysis progress with:
- Status messages
- Progress bar
- Animated icons

**results.html** - Dashboard with:
- Summary cards
- Security findings table
- Code quality metrics
- Dependency vulnerabilities
- Project information
- Report download section

### HTMX Integration

```html
<!-- Upload form -->
<form hx-post="/api/upload" 
      hx-target="#upload-result" 
      hx-indicator="#loading">
    <input type="file" name="project" accept=".zip">
    <button type="submit">Analyze Project</button>
</form>

<!-- Analysis progress polling -->
<div hx-get="/api/analysis/status/123" 
     hx-trigger="every 2s" 
     hx-target="#status">
</div>

<!-- Results tabs -->
<div class="tabs">
    <button hx-get="/api/results/security/123" 
            hx-target="#results-content">Security</button>
    <button hx-get="/api/results/quality/123" 
            hx-target="#results-content">Quality</button>
    <button hx-get="/api/results/dependencies/123" 
            hx-target="#results-content">Dependencies</button>
</div>
```

### JavaScript i18n Implementation (app.js)

```javascript
// static/js/app.js
const i18n = {
    currentLang: localStorage.getItem('lang') || 'en',
    translations: {},
    
    async loadTranslations(lang) {
        try {
            const response = await fetch(`/static/i18n/${lang}.json`);
            this.translations[lang] = await response.json();
        } catch (error) {
            console.error(`Failed to load translations for ${lang}`);
        }
    },
    
    t(key) {
        const lang = this.currentLang;
        if (this.translations[lang] && this.translations[lang][key]) {
            return this.translations[lang][key];
        }
        // Fallback to English
        if (this.translations['en'] && this.translations['en'][key]) {
            return this.translations['en'][key];
        }
        return key;
    },
    
    setLanguage(lang) {
        this.currentLang = lang;
        localStorage.setItem('lang', lang);
        document.cookie = `lang=${lang};path=/;max-age=31536000`;
        
        // Set text direction
        if (lang === 'ar') {
            document.documentElement.dir = 'rtl';
            document.documentElement.lang = 'ar';
        } else {
            document.documentElement.dir = 'ltr';
            document.documentElement.lang = lang;
        }
        
        // Update all translatable elements
        this.updatePageContent();
        
        // Reload page to apply changes
        window.location.reload();
    },
    
    updatePageContent() {
        document.querySelectorAll('[data-i18n]').forEach(element => {
            const key = element.getAttribute('data-i18n');
            element.textContent = this.t(key);
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

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Set initial direction
    document.documentElement.dir = i18n.getDir();
    
    // Load translations and update content
    i18n.loadTranslations(i18n.currentLang).then(() => {
        i18n.updatePageContent();
    });
});

// Alpine.js language switcher component
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
```

### Language Switcher HTML Component

```html
<!-- templates/components/language-switcher.html -->
<div class="language-switcher" x-data="languageSwitcher">
    <button @click="toggle()" class="lang-btn" aria-label="Change language">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="2" y1="12" x2="22" y2="12"></line>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
        </svg>
        <span x-text="getCurrentName()"></span>
        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ 'rotate-180': isOpen }" class="transition-transform">
            <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
    </button>
    
    <div x-show="isOpen" 
         x-transition:enter="transition ease-out duration-200"
         x-transition:enter-start="opacity-0 transform -translate-y-2"
         x-transition:enter-end="opacity-100 transform translate-y-0"
         x-transition:leave="transition ease-in duration-150"
         x-transition:leave-start="opacity-100"
         x-transition:leave-end="opacity-0"
         @click.away="isOpen = false"
         class="lang-dropdown">
        <template x-for="lang in getLanguages()" :key="lang.code">
            <a href="#" 
               @click.prevent="select(lang.code)"
               :class="{ 'active': currentLang === lang.code }"
               class="lang-option">
                <span x-text="lang.name"></span>
                <svg x-show="currentLang === lang.code" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="20 6 9 17 4 12"></polyline>
                </svg>
            </a>
        </template>
    </div>
</div>

<style>
.language-switcher {
    position: relative;
}

.lang-btn {
    display: flex;
    align-items: center;
    gap: 8px;
    background: transparent;
    border: 1px solid #333;
    color: #fff;
    padding: 8px 12px;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.3s ease;
    font-size: 14px;
}

.lang-btn:hover {
    border-color: #fff;
    background: #111;
}

.lang-dropdown {
    position: absolute;
    top: 100%;
    right: 0;
    margin-top: 8px;
    background: #0a0a0a;
    border: 1px solid #1a1a1a;
    border-radius: 8px;
    min-width: 150px;
    z-index: 1000;
    overflow: hidden;
}

[dir="rtl"] .lang-dropdown {
    right: auto;
    left: 0;
}

.lang-option {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    color: #a0a0a0;
    text-decoration: none;
    transition: all 0.2s ease;
}

.lang-option:hover {
    background: #111;
    color: #fff;
}

.lang-option.active {
    color: #fff;
    background: #111;
}

.rotate-180 {
    transform: rotate(180deg);
}
</style>
```

---

## DEPLOYMENT CONFIGURATION

### Dockerfile

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install git and required tools
RUN apk add --no-cache git

# Copy go mod file
COPY go.mod go ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o black-hat .

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

# Install analysis tools
RUN apk add --no-cache semgrep trivy git

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/black-hat .
COPY --from=builder /app/static ./static
COPY --from=builder /app/templates ./templates

# Expose port
EXPOSE 3000

# Run the application
CMD ["./black-hat"]
```

### render.yaml (Render.com Deployment)

```yaml
services:
  - type: web
    name: black-hat
    env: docker
    dockerfilePath: ./Dockerfile
    envVars:
      - key: DATABASE_URL
        fromDatabase:
          name: black-hat-db
          property: connectionString
      - key: REDIS_URL
        fromDatabase:
          name: black-hat-redis
          property: connectionString
      - key: PORT
        value: 3000
    healthCheckPath: /health
    autoDeploy: true

databases:
  - name: black-hat-db
    plan: starter
    databaseName: blackhat
    user: blackhat
    
  - name: black-hat-redis
    plan: starter
```

### docker-compose.yml (Local Development)

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgres://blackhat:blackhat@db:5432/blackhat?sslmode=disable
      - REDIS_URL=redis:6379
      - PORT=3000
    depends_on:
      - db
      - redis
    volumes:
      - ./uploads:/app/uploads

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=blackhat
      - POSTGRES_PASSWORD=blackhat
      - POSTGRES_DB=blackhat
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### .env.example

```env
# Server
PORT=3000
ENV=production

# Database
DATABASE_URL=postgres://user:password@localhost:5432/blackhat?sslmode=disable

# Redis
REDIS_URL=localhost:6379

# Upload
MAX_UPLOAD_SIZE=52428800  # 50MB in bytes
UPLOAD_DIR=./uploads

# Analysis
ANALYSIS_TIMEOUT=600  # 10 minutes in seconds
MAX_CONCURRENT_ANALYSES=5
```

### .gitignore

```
# Binaries
/black-hat
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary
*.test

# Output
*.out

# Go workspace
go.work

# IDE
.idea/
.vscode/
*.swp
*.swo

# Environment
.env
.env.local

# Uploads (keep structure)
uploads/*
!uploads/.gitkeep

# OS
.DS_Store
Thumbs.db

# Docker
docker-compose.override.yml
```

---

## IMPLEMENTATION CHECKLIST

### Phase 1: Project Setup
- [ ] Initialize Go module
- [ ] Create project structure
- [ ] Set up Fiber server
- [ ] Configure PostgreSQL connection
- [ ] Configure Redis connection
- [ ] Create database migrations
- [ ] Set up static file serving

### Phase 2: Internationalization (i18n)
- [ ] Create i18n folder structure
- [ ] Implement i18n.go loader
- [ ] Create en.json translation file
- [ ] Create ar.json translation file (RTL)
- [ ] Create ru.json translation file
- [ ] Create fr.json translation file
- [ ] Create es.json translation file
- [ ] Add language detection middleware
- [ ] Create language switcher component
- [ ] Implement RTL CSS support
- [ ] Add language cookie persistence

### Phase 3: Core Features
- [ ] Implement file upload handler
- [ ] Implement ZIP extraction
- [ ] Create language detector
- [ ] Implement analysis orchestrator
- [ ] Create Semgrep integration
- [ ] Create Trivy integration
- [ ] Create Gitleaks integration
- [ ] Create language-specific linters

### Phase 4: Frontend
- [ ] Create base HTML template with i18n support
- [ ] Build landing page (all languages)
- [ ] Build upload page (all languages)
- [ ] Build analysis progress page (all languages)
- [ ] Build results dashboard (all languages)
- [ ] Add animations and styling
- [ ] Implement HTMX interactions
- [ ] Add language switcher to header

### Phase 5: Reports
- [ ] Implement PDF export
- [ ] Implement HTML export
- [ ] Implement JSON export

### Phase 6: Deployment
- [ ] Create Dockerfile
- [ ] Create docker-compose.yml
- [ ] Create render.yaml
- [ ] Test deployment
- [ ] Create README.md

---

## FINAL NOTES

1. **Quality Standard:** This project must look and feel like a $4000+ premium product
2. **Performance:** Optimize for speed - use goroutines, caching, and efficient queries
3. **Security:** Sanitize all inputs, use prepared statements, validate file types
4. **Error Handling:** Graceful error handling with user-friendly messages
5. **Logging:** Comprehensive logging for debugging and monitoring
6. **Testing:** Include unit tests for critical functions
7. **Documentation:** Clear README with setup instructions
8. **i18n:** All 5 languages must be fully supported with exact translations provided
9. **RTL:** Arabic must have proper Right-to-Left layout with mirrored UI elements
10. **Language Persistence:** User language preference saved in cookie and localStorage

---

*This prompt provides complete specifications for building the Black Hat code analysis platform with multi-language support (English, Arabic, Russian, French, Spanish). Follow all rules, use exact texts provided, maintain the premium black-and-white aesthetic, and ensure proper RTL support for Arabic.*
