# base-php

Starter Symfony 7.4 — auth complète, i18n FR/EN, CI GitHub Actions, Tailwind v4.

## Prérequis

- PHP 8.2+ avec extensions : `pdo_mysql`, `intl`, `mbstring`, `openssl`, `zip`, `sodium`
- Composer 2.x
- Node 20+ et npm
- MariaDB / MySQL (Laragon ou autre)

## Installation

```bash
git clone <repo> base-php && cd base-php
cp .env.example .env.local
# Éditer .env.local : DATABASE_URL, APP_SECRET, GOOGLE_*, DISCORD_*

composer install
npm install

php bin/console doctrine:database:create
php bin/console doctrine:migrations:migrate

npm run dev
```

## Lancer en développement

Avec Laragon : ouvrir `http://base-php.test` après avoir configuré le virtual host.

```bash
npm run dev   # compile et surveille les assets
```

## Build production

```bash
npm run build
composer dump-env prod
php bin/console cache:clear --env=prod
```

## Tests

```bash
vendor/bin/phpunit --testdox                  # tous les tests
vendor/bin/phpunit --exclude-group e2e        # sans Panther
```

## CI

GitHub Actions lance automatiquement sur push/PR vers `main` et `develop` :
- PHP-CS-Fixer (dry run)
- PHPStan level 6
- PHPUnit unit + functional
- PHPUnit e2e (Panther, non bloquant)

## OAuth — Configuration

### Google
1. [Google Cloud Console](https://console.cloud.google.com) → Identifiants → OAuth 2.0
2. Redirect URI : `http://base-php.test/connect/google/check`
3. Copier Client ID et Client Secret dans `.env.local`

### Discord
1. [Discord Developer Portal](https://discord.com/developers/applications)
2. OAuth2 → Redirect : `http://base-php.test/connect/discord/check`
3. Scopes : `identify email`
4. Copier Client ID et Client Secret dans `.env.local`

## Structure

```
src/
  Controller/     HomeController, SecurityController, LocaleController
  Entity/         User
  Form/           RegistrationFormType
  Security/       AppAuthenticator, GoogleAuthenticator, DiscordAuthenticator
  EventSubscriber/ LocaleSubscriber
translations/     messages.fr.yaml, messages.en.yaml
templates/        base.html.twig, home/, security/
assets/           app.js, styles/app.css (Tailwind v4)
.github/workflows/ ci.yml
```
