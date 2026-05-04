<?php

/**
 * Tests fonctionnels (smoke tests) du contrôleur de sécurité.
 *
 * Catégorie "fonctionnel" : ces tests utilisent WebTestCase, qui démarre le kernel Symfony
 * complet, envoie de vraies requêtes HTTP et valide les réponses. Ils couvrent l'ensemble
 * de la stack (routeur, contrôleur, template) sans base de données réelle (APP_ENV=test).
 *
 * Ces tests sont des smoke tests : ils vérifient que les pages chargent (HTTP 200)
 * et que les éléments de formulaire critiques sont présents dans le DOM.
 * Ils ne testent pas l'authentification complète ni les flux de soumission de formulaire.
 *
 * Pourquoi pas de base de données :
 *   Les pages testées (/login, /register, /) sont publiques et ne nécessitent pas
 *   d'utilisateur en session. La configuration APP_ENV=test dans phpunit.xml.dist
 *   peut utiliser une base in-memory ou SQLite pour les tests qui en ont besoin.
 *
 * Ajout de tests futurs à prévoir :
 *   - Soumission du formulaire de login avec credentials valides
 *   - Soumission du formulaire d'inscription (fixtures nécessaires)
 *   - Vérification du token de vérification
 *   - Rate limiting (5 tentatives)
 */

declare(strict_types=1);

namespace App\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Smoke tests pour les routes de sécurité accessibles publiquement.
 */
class SecurityControllerTest extends WebTestCase
{
    /**
     * Vérifie que la page de connexion répond HTTP 200 et contient le formulaire e-mail/password.
     */
    public function testLoginPageLoads(): void
    {
        $client = static::createClient();
        $client->request('GET', '/login');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('form');
        $this->assertSelectorExists('input[type="email"]');
        $this->assertSelectorExists('input[type="password"]');
    }

    /**
     * Vérifie que la page d'inscription répond HTTP 200 et contient un formulaire.
     */
    public function testRegisterPageLoads(): void
    {
        $client = static::createClient();
        $client->request('GET', '/register');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('form');
    }

    /**
     * Vérifie que la page d'accueil répond HTTP 200.
     */
    public function testHomePageLoads(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        $this->assertResponseIsSuccessful();
    }

    /**
     * Vérifie que le changement de locale EN déclenche une redirection (302).
     * LocaleController stocke la locale en session et redirige vers Referer.
     */
    public function testLocaleSwitchToEn(): void
    {
        $client = static::createClient();
        $client->request('GET', '/locale/en');

        $this->assertResponseRedirects();
    }

    /**
     * Vérifie que le changement de locale FR déclenche une redirection (302).
     */
    public function testLocaleSwitchToFr(): void
    {
        $client = static::createClient();
        $client->request('GET', '/locale/fr');

        $this->assertResponseRedirects();
    }

    /**
     * Vérifie que la page de connexion contient les liens OAuth Google et Discord.
     * Garantit que les routes /connect/google et /connect/discord sont enregistrées.
     */
    public function testLoginPageHasGoogleAndDiscordLinks(): void
    {
        $client = static::createClient();
        $client->request('GET', '/login');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('a[href*="connect/google"]');
        $this->assertSelectorExists('a[href*="connect/discord"]');
    }
}
