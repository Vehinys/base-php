<?php

/**
 * Contrôleur de changement de langue (locale).
 *
 * Gère le sélecteur FR/EN présent dans la navigation.
 * La locale choisie est persistée en session et appliquée
 * à chaque requête par LocaleSubscriber (prio 20).
 */

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Permet à l'utilisateur de basculer entre les langues supportées.
 *
 * Langues disponibles : fr (défaut), en.
 * L'ajout d'une nouvelle langue nécessite :
 *   1. L'étendre dans le `requirements` de la route
 *   2. Créer le fichier translations/messages.<locale>.yaml
 *   3. Ajouter le sélecteur dans base.html.twig
 */
class LocaleController extends AbstractController
{
    /**
     * Change la locale active et redirige vers la page précédente.
     *
     * La locale est stockée en session (clé `_locale`) et lue à chaque
     * requête par LocaleSubscriber. Le paramètre `referer` permet un retour
     * transparent sans perdre le contexte de navigation.
     *
     * @param string  $locale  Code de langue validé par le `requirements` de la route (fr|en)
     * @param Request $request Requête courante — fournit la session et l'en-tête Referer
     */
    #[Route('/locale/{locale}', name: 'app_locale', requirements: ['locale' => 'fr|en'])]
    public function switchLocale(string $locale, Request $request): RedirectResponse
    {
        // Persiste le choix en session — lu par LocaleSubscriber sur chaque requête
        $request->getSession()->set('_locale', $locale);

        // Retour sur la page d'origine ; fallback sur l'accueil si Referer absent
        $referer = $request->headers->get('referer', $this->generateUrl('app_home'));

        return $this->redirect($referer);
    }
}
