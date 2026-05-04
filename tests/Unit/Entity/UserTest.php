<?php

/**
 * Tests unitaires de l'entité User.
 *
 * Ces tests couvrent uniquement la logique pure de l'entité PHP — sans base de données,
 * sans kernel Symfony, sans dépendances externes. Ils s'exécutent avec PHPUnit::TestCase
 * (et non WebTestCase) pour être ultrarapides.
 *
 * Ce qui est testé :
 *   - Comportement des méthodes de l'entité (getRoles, getUserIdentifier, eraseCredentials)
 *   - Valeurs par défaut à la construction (createdAt, isVerified, rôles)
 *   - Setters/getters pour les champs OAuth (googleId, discordId)
 *
 * Ce qui n'est PAS testé ici (à couvrir en tests fonctionnels ou d'intégration) :
 *   - Persistance Doctrine (contraintes de colonne, unicité de l'email)
 *   - Hashage du mot de passe (nécessite UserPasswordHasherInterface)
 *   - Flux d'authentification complet
 */

declare(strict_types=1);

namespace App\Tests\Unit\Entity;

use App\Entity\User;
use PHPUnit\Framework\TestCase;

/**
 * Tests unitaires de l'entité User — logique métier pure sans infrastructure.
 */
class UserTest extends TestCase
{
    /**
     * ROLE_USER doit toujours être présent, même si le tableau roles est vide en base.
     * getRoles() l'ajoute systématiquement via array_unique(['ROLE_USER', ...$this->roles]).
     */
    public function testDefaultRoleIsUser(): void
    {
        $user = new User();
        $this->assertContains('ROLE_USER', $user->getRoles());
    }

    /**
     * getRoles() doit dédupliquer les rôles — ROLE_USER ne doit apparaître qu'une fois
     * même s'il est présent à la fois dans le tableau stocké et ajouté par défaut.
     */
    public function testRolesAreUnique(): void
    {
        $user = new User();
        $user->setRoles(['ROLE_USER', 'ROLE_USER']);
        $this->assertCount(1, $user->getRoles());
    }

    /**
     * getUserIdentifier() est l'interface UserInterface Symfony — doit retourner l'e-mail.
     * Utilisé par les providers et les sessions pour identifier l'utilisateur.
     */
    public function testGetUserIdentifierReturnsEmail(): void
    {
        $user = (new User())->setEmail('test@example.com');
        $this->assertSame('test@example.com', $user->getUserIdentifier());
    }

    /**
     * createdAt est initialisé dans le constructeur de User.
     * Ce test garantit qu'aucune migration de schéma ne casse cette initialisation.
     */
    public function testCreatedAtIsSetOnConstruct(): void
    {
        $user = new User();
        $this->assertInstanceOf(\DateTimeInterface::class, $user->getCreatedAt());
    }

    /**
     * eraseCredentials() est appelé par Symfony après l'authentification pour supprimer
     * les données sensibles temporaires (mot de passe en clair, etc.).
     * Dans notre implémentation, cette méthode est vide — elle ne doit pas effacer le hash.
     */
    public function testEraseCredentialsDoesNothing(): void
    {
        $user = (new User())->setPassword('hash');
        $user->eraseCredentials();
        $this->assertSame('hash', $user->getPassword());
    }

    /**
     * Vérifie les setters/getters des identifiants OAuth.
     * Ces champs sont nullable — null = compte non lié à ce provider.
     */
    public function testOAuthIds(): void
    {
        $user = new User();
        $user->setGoogleId('google_123');
        $user->setDiscordId('discord_456');

        $this->assertSame('google_123', $user->getGoogleId());
        $this->assertSame('discord_456', $user->getDiscordId());
    }

    /**
     * isVerified est false par défaut — un compte créé via formulaire n'est pas vérifié
     * tant que l'utilisateur n'a pas cliqué sur le lien de vérification envoyé par e-mail.
     * Les comptes OAuth sont immédiatement vérifiés par leurs authenticators.
     */
    public function testIsVerifiedDefaultFalse(): void
    {
        $user = new User();
        $this->assertFalse($user->isVerified());
    }
}
