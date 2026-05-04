<?php

/**
 * Tests E2E (End-to-End) de la page d'accueil et des éléments globaux.
 *
 * Nomenclature E2E dans ce projet :
 *   Ces tests utilisent WebTestCase (pas Panther/navigateur réel) mais sont classés E2E
 *   car ils vérifient le rendu HTML complet d'une page, incluant le layout de base.html.twig
 *   (navigation, sélecteur de langue, structure accessible).
 *
 *   Pour des tests E2E avec vrai navigateur (JS, cookies), Symfony Panther serait nécessaire
 *   (cf. commentaire dans CLAUDE.md : "WebTestCase remplace Panther e2e").
 *
 * Ce qui est testé :
 *   - Présence des éléments structurels de la page (h1, nav)
 *   - Présence du sélecteur de langue (hreflang fr/en)
 *   - Présence des boutons OAuth sur /login (Google, Discord)
 *
 * Ces tests servent de régression visuelle légère : ils détectent la suppression accidentelle
 * d'éléments critiques du DOM sans nécessiter d'exécuter un vrai navigateur.
 */

declare(strict_types=1);

namespace App\Tests\E2E;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Tests du rendu HTML des pages publiques clés.
 */
class HomeTest extends WebTestCase
{
    /**
     * Vérifie que la page d'accueil rend correctement les éléments structurels de base.
     * h1 = titre principal de la page (hero heading). nav = barre de navigation du header.
     */
    public function testHomepageRendersHeadline(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('h1');
        $this->assertSelectorExists('nav');
    }

    /**
     * Vérifie que le sélecteur de langue est présent sur la page d'accueil.
     * Les attributs hreflang sont utilisés pour la détection des alternatives linguistiques
     * par les moteurs de recherche et le test vérifie leur présence dans le DOM.
     */
    public function testLanguageSwitcherIsVisible(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('a[hreflang="fr"]');
        $this->assertSelectorExists('a[hreflang="en"]');
    }

    /**
     * Vérifie que les boutons OAuth Google et Discord sont présents sur la page de connexion.
     * Détecte une régression si les routes OAuth sont supprimées ou mal configurées.
     */
    public function testLoginPageHasOAuthButtons(): void
    {
        $client = static::createClient();
        $client->request('GET', '/login');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('a[href*="connect/google"]');
        $this->assertSelectorExists('a[href*="connect/discord"]');
    }
}
