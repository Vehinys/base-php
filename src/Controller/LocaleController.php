<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

class LocaleController extends AbstractController
{
    #[Route('/locale/{locale}', name: 'app_locale', requirements: ['locale' => 'fr|en'])]
    public function switchLocale(string $locale, Request $request): RedirectResponse
    {
        $request->getSession()->set('_locale', $locale);
        $referer = $request->headers->get('referer', $this->generateUrl('app_home'));

        return $this->redirect($referer);
    }
}
