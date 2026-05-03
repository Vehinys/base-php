<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class SecurityControllerTest extends WebTestCase
{
    public function testLoginPageLoads(): void
    {
        $client = static::createClient();
        $client->request('GET', '/login');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('form');
        $this->assertSelectorExists('input[type="email"]');
        $this->assertSelectorExists('input[type="password"]');
    }

    public function testRegisterPageLoads(): void
    {
        $client = static::createClient();
        $client->request('GET', '/register');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('form');
    }

    public function testHomePageLoads(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        $this->assertResponseIsSuccessful();
    }

    public function testLocaleSwitchToEn(): void
    {
        $client = static::createClient();
        $client->request('GET', '/locale/en');

        $this->assertResponseRedirects();
    }

    public function testLocaleSwitchToFr(): void
    {
        $client = static::createClient();
        $client->request('GET', '/locale/fr');

        $this->assertResponseRedirects();
    }

    public function testLoginPageHasGoogleAndDiscordLinks(): void
    {
        $client = static::createClient();
        $client->request('GET', '/login');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorExists('a[href*="connect/google"]');
        $this->assertSelectorExists('a[href*="connect/discord"]');
    }
}
