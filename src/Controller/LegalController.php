<?php

/**
 * Contrôleur des pages légales obligatoires.
 *
 * Regroupe les quatre documents imposés par le droit français
 * et les obligations RGPD pour un site destiné à des utilisateurs européens :
 *
 *   - Mentions légales (loi LCEN 2004)
 *   - Politique de confidentialité (RGPD art. 13)
 *   - Conditions générales d'utilisation
 *   - Gestion des cookies (directive ePrivacy / LCEN art. 32-II)
 *
 * Toutes les routes sont préfixées par /legal (défini au niveau de la classe).
 */

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Sert les pages légales statiques du site.
 *
 * Ces pages ne nécessitent aucun traitement serveur : le contenu
 * est entièrement dans les templates Twig. Elles sont accessibles
 * sans authentification et indexables (robots: index,follow).
 */
#[Route('/legal', name: 'legal_')]
class LegalController extends AbstractController
{
    /**
     * Mentions légales — identité de l'éditeur et de l'hébergeur.
     * Obligatoires en France pour tout site accessible au public (loi LCEN).
     */
    #[Route('/mentions-legales', name: 'mentions')]
    public function mentions(): Response
    {
        return $this->render('legal/mentions.html.twig');
    }

    /**
     * Politique de confidentialité — informations sur le traitement des données personnelles.
     * Exigée par le RGPD (art. 13) dès lors que des données sont collectées (ex. inscription).
     */
    #[Route('/politique-de-confidentialite', name: 'privacy')]
    public function privacy(): Response
    {
        return $this->render('legal/privacy.html.twig');
    }

    /**
     * Conditions générales d'utilisation — règles d'usage du service.
     * Définit la relation contractuelle entre l'éditeur et l'utilisateur.
     */
    #[Route('/conditions-generales-utilisation', name: 'cgu')]
    public function cgu(): Response
    {
        return $this->render('legal/cgu.html.twig');
    }

    /**
     * Page de gestion des cookies — explication des traceurs déposés.
     * Requise par la directive ePrivacy et les lignes directrices CNIL 2020.
     * La bannière de consentement (base.html.twig) renvoie vers cette page.
     */
    #[Route('/gestion-des-cookies', name: 'cookies')]
    public function cookies(): Response
    {
        return $this->render('legal/cookies.html.twig');
    }
}
