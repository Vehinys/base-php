<?php

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

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::RESPONSE => 'onKernelResponse'];
    }
}
