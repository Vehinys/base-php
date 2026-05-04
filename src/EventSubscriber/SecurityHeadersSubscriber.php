<?php

/**
 * Abonné complémentaire à NelmioSecurityBundle pour les en-têtes de sécurité HTTP.
 *
 * NelmioSecurityBundle couvre : CSP, X-Frame-Options, HSTS, X-Content-Type-Options,
 * X-XSS-Protection et Referrer-Policy (configurés dans nelmio_security.yaml).
 *
 * Ce subscriber ajoute Permissions-Policy, non géré nativement par NelmioSecurityBundle.
 * Il est conservé séparé de PermissionsPolicySubscriber pour historique ; les deux
 * subscribers font le même travail — si des doublons d'en-tête apparaissent, supprimer l'un.
 *
 * @deprecated Fonctionnellement redondant avec PermissionsPolicySubscriber.
 *             À conserver ou supprimer après vérification qu'une seule instance suffit.
 */

declare(strict_types=1);

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Ajoute les en-têtes de sécurité HTTP manquants à NelmioSecurityBundle.
 * Permissions-Policy restreint l'accès aux API sensibles du navigateur.
 */
class SecurityHeadersSubscriber implements EventSubscriberInterface
{
    /**
     * Injecte Permissions-Policy sur toutes les réponses principales.
     *
     * @param ResponseEvent $event Événement déclenché avant l'envoi de la réponse HTTP
     */
    public function onKernelResponse(ResponseEvent $event): void
    {
        // N'intervenir que sur la réponse principale (pas les sous-requêtes)
        if (!$event->isMainRequest()) {
            return;
        }

        $event->getResponse()->headers->set(
            'Permissions-Policy',
            // Désactiver toutes les APIs sensibles non utilisées par l'application
            'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()'
        );
    }

    /**
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::RESPONSE => 'onKernelResponse'];
    }
}
