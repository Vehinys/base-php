<?php

/**
 * Abonné qui injecte l'en-tête HTTP Permissions-Policy sur chaque réponse principale.
 *
 * Permissions-Policy (successeur de Feature-Policy) permet au serveur de désactiver
 * explicitement des API navigateur sensibles que l'application n'utilise pas.
 * Cela réduit la surface d'attaque en cas d'injection de script tiers.
 *
 * Directives appliquées :
 *   - camera=()         → aucun iframe ni script ne peut demander la caméra
 *   - microphone=()     → idem pour le micro
 *   - geolocation=()    → localisation désactivée
 *   - payment=()        → Payment Request API désactivée
 *   - usb=()            → WebUSB désactivé
 *   - interest-cohort=() → opt-out FLoC Google (remplacé par Topics API, mais toujours utile)
 *
 * Note : NelmioSecurityBundle gère CSP, X-Frame-Options, HSTS et XCTO.
 * Permissions-Policy n'est pas encore supporté nativement par NelmioSecurityBundle,
 * d'où ce subscriber dédié.
 *
 * Priorité 10 sur KernelEvents::RESPONSE : s'exécute après la majorité des listeners
 * mais assez tôt pour ne pas être écrasé par un éventuel listener de cache.
 */

declare(strict_types=1);

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Ajoute l'en-tête Permissions-Policy à toutes les réponses HTTP principales.
 *
 * Seule la requête principale reçoit cet en-tête (isMainRequest()) ; les sous-requêtes
 * Symfony (fragments ESI, forward) l'ignorent pour éviter les doublons.
 */
class PermissionsPolicySubscriber implements EventSubscriberInterface
{
    /**
     * Valeur complète de l'en-tête Permissions-Policy.
     * Chaque directive vide () interdit l'API à toutes les origines (page + iframes).
     */
    private const POLICY = 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()';

    /**
     * Déclare l'abonnement à KernelEvents::RESPONSE avec priorité 10.
     *
     * @return array<string, array<int, int|string>>
     */
    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::RESPONSE => ['onKernelResponse', 10]];
    }

    /**
     * Injecte l'en-tête Permissions-Policy sur la réponse principale.
     *
     * @param ResponseEvent $event Événement déclenché avant l'envoi de la réponse au client
     */
    public function onKernelResponse(ResponseEvent $event): void
    {
        // Les sous-requêtes (fragments, ESI) ne nécessitent pas cet en-tête
        if (!$event->isMainRequest()) {
            return;
        }

        $event->getResponse()->headers->set('Permissions-Policy', self::POLICY);
    }
}
