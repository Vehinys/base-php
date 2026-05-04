<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class SitemapController extends AbstractController
{
    // Génère le sitemap XML des pages indexables — exclut auth, logout, locale, connect
    #[Route('/sitemap.xml', name: 'app_sitemap', defaults: ['_format' => 'xml'])]
    public function index(): Response
    {
        $urls = [
            ['route' => 'app_home',        'priority' => '1.0', 'changefreq' => 'weekly'],
            ['route' => 'legal_mentions',  'priority' => '0.3', 'changefreq' => 'yearly'],
            ['route' => 'legal_privacy',   'priority' => '0.3', 'changefreq' => 'yearly'],
            ['route' => 'legal_cgu',       'priority' => '0.3', 'changefreq' => 'yearly'],
            ['route' => 'legal_cookies',   'priority' => '0.3', 'changefreq' => 'yearly'],
        ];

        // Génère les URLs absolues pour chaque route
        $entries = array_map(
            fn (array $item) => [
                'loc' => $this->generateUrl($item['route'], [], UrlGeneratorInterface::ABSOLUTE_URL),
                'priority' => $item['priority'],
                'changefreq' => $item['changefreq'],
                'lastmod' => date('Y-m-d'),
            ],
            $urls
        );

        $response = $this->render('sitemap/index.xml.twig', ['entries' => $entries]);
        $response->headers->set('Content-Type', 'application/xml; charset=UTF-8');
        // Cache 24h côté navigateur et CDN — le sitemap change rarement
        $response->headers->set('Cache-Control', 'public, max-age=86400');

        return $response;
    }
}
