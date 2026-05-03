# base-php — CLAUDE.md

## Stack

- **PHP** 8.4 · **Symfony** 7.4 LTS · **Doctrine** ORM · **MariaDB** (Laragon)
- **Auth** : email/password (Argon2) + OAuth Google + OAuth Discord (KnpU OAuth2 Client Bundle)
- **CSS** : Tailwind v4 via Webpack Encore + PostCSS
- **i18n** : symfony/translation — FR (défaut) + EN — session + Accept-Language
- **Tests** : PHPUnit unit + functional (Panther e2e remplacé par WebTestCase)
- **CI** : GitHub Actions (`.github/workflows/ci.yml`)
- **Qualité** : PHPStan level 6 + PHP-CS-Fixer (@Symfony risky)

## Commandes

```bash
# Dev
export PATH="/c/Program Files/nodejs:$PATH"
npm run dev           # compile assets (watch)
npm run build         # compile pour prod
php bin/console server:run  # si Symfony CLI installée

# Base de données
php bin/console doctrine:database:create
php bin/console doctrine:migrations:migrate
php bin/console doctrine:migrations:diff   # génère une migration

# Tests
vendor/bin/phpunit                          # tous les tests
vendor/bin/phpunit --exclude-group e2e      # sans Panther
vendor/bin/phpunit tests/Unit               # unitaires seuls

# Qualité
vendor/bin/php-cs-fixer fix                 # formatter
vendor/bin/php-cs-fixer fix --dry-run       # vérifier sans modifier
vendor/bin/phpstan analyse                  # analyse statique

# Traductions
php bin/console translation:extract --force --locale fr
php bin/console translation:extract --force --locale en
```

## Conventions

- Namespace racine : `App\`
- Controllers : `src/Controller/`
- Authenticators : `src/Security/`
- Abonnés d'événements : `src/EventSubscriber/`
- Traductions : `translations/messages.fr.yaml` et `messages.en.yaml`
- Templates : `templates/` — héritage de `base.html.twig`
- Assets : `assets/app.js` → `assets/styles/app.css` (CSS variables dans `@theme`)
- Commits conventionnels : `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`

## Points d'attention

- **PHP CLI** : utiliser le PHP WinGet (`php` en PATH) — Laragon PHP 8.1 n'est pas utilisé ici
- **Composer** : `php /c/laragon/bin/composer/composer-new.phar <cmd>` si `composer` n'est pas en PATH
- **npm** : ajouter `/c/Program Files/nodejs` au PATH si npm introuvable
- **OAuth Discord** : package `wohali/oauth2-discord-new` — méthode `getAvatarUrl()` à vérifier si l'API Discord change
- **CSP** : si ajout de CDN externe, mettre à jour `config/packages/nelmio_security.yaml`
- **login_throttling** : 5 tentatives / 15 min — nécessite `symfony/rate-limiter` (déjà installé)
- **Sitemap** : route `/sitemap.xml` — ajouter les nouvelles pages indexables dans `SitemapController`
- **Erreurs** : pages 404/500 dans `templates/bundles/TwigBundle/Exception/`
- **Locale** : `LocaleSubscriber` priorité 20 sur `KernelEvents::REQUEST` — avant le firewall (prio 8)

## Standards actifs

A11Y RGAA AAA · Sécurité (headers, argon2, CSRF, sessions) · Perf (assets hashés, font preload) · SEO (meta, OG, canonical, lang)
