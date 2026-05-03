<?php

declare(strict_types=1);

namespace App\Tests\E2E;

use Symfony\Component\Panther\PantherTestCase;

class HomeTest extends PantherTestCase
{
    public function testHomepageRendersHeadline(): void
    {
        $client = static::createPantherClient();
        $crawler = $client->request('GET', '/');

        $this->assertSelectorIsVisible('h1');
        $this->assertSelectorExists('nav');
    }

    public function testLanguageSwitcherIsVisible(): void
    {
        $client = static::createPantherClient();
        $client->request('GET', '/');

        $this->assertSelectorExists('a[hreflang="fr"]');
        $this->assertSelectorExists('a[hreflang="en"]');
    }

    public function testLoginPageHasOAuthButtons(): void
    {
        $client = static::createPantherClient();
        $client->request('GET', '/login');

        $this->assertSelectorIsVisible('a[href*="connect/google"]');
        $this->assertSelectorIsVisible('a[href*="connect/discord"]');
    }
}
