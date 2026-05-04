<?php

/**
 * Abonné chargé de restaurer la locale de l'utilisateur à chaque requête.
 *
 * Symfony réinitialise la locale à la valeur par défaut (framework.yaml > default_locale)
 * au début de chaque requête. Ce subscriber lit la clé '_locale' stockée en session
 * lors du changement de langue (LocaleController) et la réapplique sur la Request,
 * ce qui garantit que toutes les traductions, formats de date et de nombre sont
 * cohérents avec la préférence mémorisée de l'utilisateur.
 *
 * Priorité 20 sur KernelEvents::REQUEST :
 *   - Avant le firewall Symfony (priorité 8) → la locale est déjà connue pendant l'auth
 *   - Avant le routeur (priorité 32) si des routes sont i18n-préfixées (non utilisé ici)
 *
 * Limitation : hasPreviousSession() renvoie false sur la toute première requête d'un
 * visiteur → la locale par défaut ('fr') est appliquée jusqu'à ce qu'une session existe.
 * C'est le comportement attendu (pas de session créée inutilement pour les robots).
 */

declare(strict_types=1);

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Restaure la locale depuis la session Symfony sur chaque requête entrante.
 *
 * Sans ce subscriber, la locale serait réinitialisée à la valeur de default_locale
 * dans framework.yaml à chaque requête, ignorant le choix de langue de l'utilisateur.
 */
class LocaleSubscriber implements EventSubscriberInterface
{
    /**
     * @param string $defaultLocale Locale par défaut si aucune n'est stockée en session
     *                              (injectée depuis le paramètre `kernel.default_locale`)
     */
    public function __construct(private string $defaultLocale = 'fr')
    {
    }

    /**
     * Applique la locale de session sur la requête avant tout traitement Symfony.
     *
     * @param RequestEvent $event Événement KernelEvents::REQUEST déclenché à chaque requête
     */
    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        // hasPreviousSession() évite d'initialiser une session inutile sur les requêtes sans cookie
        if (!$request->hasPreviousSession()) {
            return;
        }

        $locale = $request->getSession()->get('_locale', $this->defaultLocale);
        $request->setLocale($locale);
    }

    /**
     * Déclare les événements écoutés et leurs priorités.
     *
     * Priorité 20 : s'exécute avant le firewall (prio 8) pour que la locale soit
     * connue dès la phase d'authentification (messages d'erreur traduits, etc.).
     *
     * @return array<string, array<int, array<int, int|string>>>
     */
    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => [['onKernelRequest', 20]]];
    }
}
