<?php

declare(strict_types=1);

namespace App\Tests\E2E;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class HomeTest extends WebTestCase
{
    public function testHomepageRendersHeadline(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('h1');
        $this->assertSelectorExists('nav');
    }

    public function testLanguageSwitcherIsVisible(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('a[hreflang="fr"]');
        $this->assertSelectorExists('a[hreflang="en"]');
    }

    public function testLoginPageHasOAuthButtons(): void
    {
        $client = static::createClient();
        $client->request('GET', '/login');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('a[href*="connect/google"]');
        $this->assertSelectorExists('a[href*="connect/discord"]');
    }
}
