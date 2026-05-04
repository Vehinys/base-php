<?php

/**
 * Contrôleur du sitemap XML.
 *
 * Génère dynamiquement le fichier sitemap.xml déclarant les pages
 * indexables du site à l'intention des moteurs de recherche (Google,
 * Bing, etc.). Le fichier est référencé dans robots.txt.
 *
 * Pages exclues intentionnellement : auth, reset-password, locale,
 * connect (OAuth), verify — ces routes ne sont pas indexables.
 */

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Génère le sitemap XML des pages publiques indexables.
 *
 * Pour ajouter une nouvelle page au sitemap, il suffit d'ajouter
 * une entrée dans le tableau $urls avec la route, la priorité (0.0–1.0)
 * et la fréquence de changement estimée.
 */
class SitemapController extends AbstractController
{
    /**
     * Génère et renvoie le sitemap XML.
     *
     * Le Content-Type est forcé à application/xml pour que les robots
     * l'interprètent correctement indépendamment de la configuration serveur.
     * Le cache HTTP de 24h évite une régénération inutile à chaque crawl.
     */
    #[Route('/sitemap.xml', name: 'app_sitemap', defaults: ['_format' => 'xml'])]
    public function index(): Response
    {
        // Déclaration des pages indexables avec leur métadonnée SEO
        // priority : importance relative (1.0 = plus importante)
        // changefreq : estimation de la fréquence de modification
        $urls = [
            ['route' => 'app_home',        'priority' => '1.0', 'changefreq' => 'weekly'],
            ['route' => 'legal_mentions',  'priority' => '0.3', 'changefreq' => 'yearly'],
            ['route' => 'legal_privacy',   'priority' => '0.3', 'changefreq' => 'yearly'],
            ['route' => 'legal_cgu',       'priority' => '0.3', 'changefreq' => 'yearly'],
            ['route' => 'legal_cookies',   'priority' => '0.3', 'changefreq' => 'yearly'],
        ];

        // Résolution des routes en URLs absolues — exigées par le protocole sitemap
        $entries = array_map(
            fn (array $item) => [
                'loc'        => $this->generateUrl($item['route'], [], UrlGeneratorInterface::ABSOLUTE_URL),
                'priority'   => $item['priority'],
                'changefreq' => $item['changefreq'],
                'lastmod'    => date('Y-m-d'),
            ],
            $urls
        );

        $response = $this->render('sitemap/index.xml.twig', ['entries' => $entries]);

        // Force le type MIME XML — certains serveurs renvoient text/html par défaut
        $response->headers->set('Content-Type', 'application/xml; charset=UTF-8');

        // Cache navigateur et CDN de 24h — le sitemap ne change pas à chaque requête
        $response->headers->set('Cache-Control', 'public, max-age=86400');

        return $response;
    }
}
