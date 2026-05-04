<?php

/**
 * Contrôleur de la page d'accueil publique.
 *
 * Responsabilité unique : servir la page principale du site.
 * Aucune logique métier ici — tout est dans le template Twig.
 */

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Gère la route racine "/" de l'application.
 *
 * La page d'accueil est entièrement statique côté PHP :
 * le contenu dynamique (statut de connexion, langue) est géré
 * directement dans Twig via app.user et app.request.locale.
 */
class HomeController extends AbstractController
{
    /**
     * Affiche la page d'accueil.
     *
     * Route publique — accessible sans authentification.
     * Le template adapte le contenu selon l'état de connexion de l'utilisateur.
     */
    #[Route('/', name: 'app_home')]
    public function index(): Response
    {
        return $this->render('home/index.html.twig');
    }
}
