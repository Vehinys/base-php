// Point d'entrée principal — charge le CSS Tailwind v4 + composants
import './styles/app.css';

// ─── Menu mobile ──────────────────────────────────────────────────────────────
(function () {
    const btn = document.getElementById('mobileMenuBtn');
    const menu = document.getElementById('mobileMenu');
    if (!btn || !menu) return;

    btn.addEventListener('click', function () {
        const isOpen = menu.classList.toggle('open');
        btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        const label = isOpen ? btn.dataset.labelClose : btn.dataset.labelOpen;
        if (label) btn.setAttribute('aria-label', label);
        if (isOpen) {
            const firstLink = menu.querySelector('a, button');
            if (firstLink) firstLink.focus();
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && menu.classList.contains('open')) {
            menu.classList.remove('open');
            btn.setAttribute('aria-expanded', 'false');
            if (btn.dataset.labelOpen) btn.setAttribute('aria-label', btn.dataset.labelOpen);
            btn.focus();
        }
    });
}());

// ─── Dropdown utilisateur ─────────────────────────────────────────────────────
(function () {
    const btn = document.getElementById('userDropdownBtn');
    const dropdown = document.getElementById('userDropdown');
    if (!btn || !dropdown) return;

    btn.addEventListener('click', function (e) {
        e.stopPropagation();
        const isOpen = dropdown.classList.toggle('open');
        btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });

    document.addEventListener('click', function (e) {
        if (dropdown.classList.contains('open') && !dropdown.contains(e.target)) {
            dropdown.classList.remove('open');
            btn.setAttribute('aria-expanded', 'false');
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && dropdown.classList.contains('open')) {
            dropdown.classList.remove('open');
            btn.setAttribute('aria-expanded', 'false');
            btn.focus();
        }
    });
}());

// ─── Indicateur de force du mot de passe ─────────────────────────────────────
(function () {
    const input = document.querySelector('[data-strength-input]');
    if (!input) return;

    const list = input.closest('div')?.querySelector('.pw-requirements');
    if (!list) return;

    const checks = {
        length: (v) => v.length >= 12,
        lower:  (v) => /[a-z]/.test(v),
        upper:  (v) => /[A-Z]/.test(v),
        digit:  (v) => /[0-9]/.test(v),
    };

    input.addEventListener('input', function () {
        const val = input.value;
        list.classList.toggle('visible', val.length > 0);
        list.querySelectorAll('li[data-req]').forEach(function (li) {
            const key = li.dataset.req;
            const pass = checks[key]?.(val) ?? false;
            li.classList.toggle('ok', pass);
            li.classList.toggle('fail', val.length > 0 && !pass);
        });
    });
}());

// ─── Bannière de consentement cookies ────────────────────────────────────────
(function () {
    const FONT_URL = 'https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400;12..96,600;12..96,700;12..96,800&family=DM+Sans:wght@400;500;600&display=swap';
    const KEY = 'cookie_consent';

    function loadFonts() {
        if (document.querySelector('link[data-gfonts]')) return;
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.setAttribute('data-gfonts', '');
        link.href = FONT_URL;
        document.head.appendChild(link);
    }

    const consent = localStorage.getItem(KEY);

    if (consent === 'all') {
        loadFonts();
        return;
    }

    if (consent === 'essential') {
        return;
    }

    // Pas de consentement enregistré — afficher la bannière
    const banner = document.getElementById('cookieBanner');
    if (!banner) return;

    banner.classList.add('visible');

    document.getElementById('cookieAcceptAll')?.addEventListener('click', function () {
        localStorage.setItem(KEY, 'all');
        banner.classList.remove('visible');
        loadFonts();
    });

    document.getElementById('cookieEssential')?.addEventListener('click', function () {
        localStorage.setItem(KEY, 'essential');
        banner.classList.remove('visible');
    });
}());
