// Point d'entrée principal — charge le CSS Tailwind v4 + composants
import './styles/app.css';

// ─── Menu mobile ──────────────────────────────────────────────────────────────
// Les labels d'accessibilité sont lus depuis les data-attributes Twig
// pour garder les traductions dans les fichiers YAML (pas dans le JS)
(function () {
    const btn = document.getElementById('mobileMenuBtn');
    const menu = document.getElementById('mobileMenu');
    if (!btn || !menu) return;

    btn.addEventListener('click', function () {
        const isOpen = menu.classList.toggle('open');
        btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        // Met à jour le label pour les lecteurs d'écran
        const label = isOpen ? btn.dataset.labelClose : btn.dataset.labelOpen;
        if (label) btn.setAttribute('aria-label', label);
        // Focus le premier lien du menu quand il s'ouvre (accessibilité clavier)
        if (isOpen) {
            const firstLink = menu.querySelector('a, button');
            if (firstLink) firstLink.focus();
        }
    });

    // Fermeture via Escape — remet le focus sur le bouton (WCAG 2.1 success criterion 1.4.13)
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
// Ferme le dropdown si le clic se produit en dehors de celui-ci
document.addEventListener('click', function (e) {
    const dropdown = document.getElementById('userDropdown');
    if (dropdown && !dropdown.contains(e.target)) {
        dropdown.classList.remove('open');
        // Réinitialise aria-expanded pour les lecteurs d'écran
        const toggle = dropdown.querySelector('[aria-haspopup]');
        if (toggle) toggle.setAttribute('aria-expanded', 'false');
    }
});

// Fermeture du dropdown via Escape
document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    const dropdown = document.getElementById('userDropdown');
    if (dropdown && dropdown.classList.contains('open')) {
        dropdown.classList.remove('open');
        const toggle = dropdown.querySelector('[aria-haspopup]');
        if (toggle) {
            toggle.setAttribute('aria-expanded', 'false');
            toggle.focus();
        }
    }
});
