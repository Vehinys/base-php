<?php

/**
 * Abonné qui trace automatiquement les événements de sécurité critiques.
 *
 * Ce subscriber écoute les événements Symfony Security et délègue la persistance
 * à AuditLogger (SecurityLog en base + canal Monolog "security").
 *
 * Événements couverts :
 *   - LoginSuccessEvent  → login.success  (toutes méthodes : email, Google, Discord)
 *   - LoginFailureEvent  → login.failure  (tentative rejetée)
 *   - LogoutEvent        → logout         (déconnexion explicite ou expiration session)
 *
 * Résolution du provider :
 *   Le nom de la classe de l'authenticator est utilisé pour déterminer la méthode
 *   d'authentification (google, discord, email). Cette approche évite de coupler
 *   le subscriber aux classes concrètes par import direct.
 *
 * Sécurité login.failure :
 *   L'e-mail tenté est extrait du payload de la requête (champ 'email').
 *   Il est stocké dans extra uniquement s'il est non-vide (array_filter).
 *   La raison de l'échec vient de getMessageKey() — clé de traduction, pas le message
 *   localisé, ce qui garantit une valeur stable pour les outils de monitoring.
 */

declare(strict_types=1);

namespace App\EventSubscriber;

use App\Entity\User;
use App\Service\AuditLogger;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * Trace les connexions, échecs et déconnexions via AuditLogger.
 *
 * Tous les événements sont loggués indépendamment du firewall actif,
 * ce qui couvre à la fois l'auth locale (email/password) et OAuth (Google, Discord).
 */
class SecurityAuditSubscriber implements EventSubscriberInterface
{
    /**
     * @param AuditLogger $auditLogger Service de persistance des entrées d'audit
     */
    public function __construct(private readonly AuditLogger $auditLogger)
    {
    }

    /**
     * Déclare les trois événements de sécurité écoutés.
     *
     * @return array<class-string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
            LoginFailureEvent::class => 'onLoginFailure',
            LogoutEvent::class => 'onLogout',
        ];
    }

    /**
     * Loggue une connexion réussie avec la méthode d'authentification utilisée.
     *
     * @param LoginSuccessEvent $event Événement déclenché après validation des credentials
     */
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getAuthenticatedToken()->getUser();
        $authenticatorClass = \get_class($event->getAuthenticator());
        $provider = $this->resolveProvider($authenticatorClass);

        $this->auditLogger->log(
            'login.success',
            $user instanceof User ? $user : null,
            $event->getRequest(),
            ['provider' => $provider]
        );
    }

    /**
     * Loggue une tentative de connexion échouée.
     *
     * L'e-mail tenté et la clé de raison sont enregistrés dans le champ extra.
     * array_filter() supprime les valeurs null/vides pour garder l'entrée propre.
     *
     * @param LoginFailureEvent $event Événement déclenché après rejet de l'authentification
     */
    public function onLoginFailure(LoginFailureEvent $event): void
    {
        $email = $event->getRequest()->getPayload()->getString('email', '');

        $this->auditLogger->log(
            'login.failure',
            null,
            $event->getRequest(),
            array_filter([
                'attempted_email' => $email ?: null,
                'reason' => $event->getException()->getMessageKey(),
            ])
        );
    }

    /**
     * Loggue une déconnexion (explicite via /logout ou expiration de session).
     *
     * Le token peut être null si la session a déjà expiré avant le LogoutEvent.
     *
     * @param LogoutEvent $event Événement déclenché lors de la déconnexion
     */
    public function onLogout(LogoutEvent $event): void
    {
        $token = $event->getToken();
        $user = $token?->getUser();

        $this->auditLogger->log(
            'logout',
            $user instanceof User ? $user : null,
            $event->getRequest()
        );
    }

    /**
     * Détermine le fournisseur d'identité à partir du nom de classe de l'authenticator.
     *
     * La correspondance par str_contains() est intentionnellement lâche : elle résiste
     * aux renommages de namespace tant que "Google" ou "Discord" reste dans le nom de classe.
     *
     * @param string $class FQCN de l'authenticator (ex. App\Security\GoogleAuthenticator)
     *
     * @return string 'google' | 'discord' | 'email'
     */
    private function resolveProvider(string $class): string
    {
        return match (true) {
            str_contains($class, 'Google') => 'google',
            str_contains($class, 'Discord') => 'discord',
            default => 'email',
        };
    }
}
