<?php

declare(strict_types=1);

namespace App\Tests\Unit\Entity;

use App\Entity\User;
use PHPUnit\Framework\TestCase;

class UserTest extends TestCase
{
    public function testDefaultRoleIsUser(): void
    {
        $user = new User();
        $this->assertContains('ROLE_USER', $user->getRoles());
    }

    public function testRolesAreUnique(): void
    {
        $user = new User();
        $user->setRoles(['ROLE_USER', 'ROLE_USER']);
        $this->assertCount(1, $user->getRoles());
    }

    public function testGetUserIdentifierReturnsEmail(): void
    {
        $user = (new User())->setEmail('test@example.com');
        $this->assertSame('test@example.com', $user->getUserIdentifier());
    }

    public function testCreatedAtIsSetOnConstruct(): void
    {
        $user = new User();
        $this->assertInstanceOf(\DateTimeInterface::class, $user->getCreatedAt());
    }

    public function testEraseCredentialsDoesNothing(): void
    {
        $user = (new User())->setPassword('hash');
        $user->eraseCredentials();
        $this->assertSame('hash', $user->getPassword());
    }

    public function testOAuthIds(): void
    {
        $user = new User();
        $user->setGoogleId('google_123');
        $user->setDiscordId('discord_456');

        $this->assertSame('google_123', $user->getGoogleId());
        $this->assertSame('discord_456', $user->getDiscordId());
    }

    public function testIsVerifiedDefaultFalse(): void
    {
        $user = new User();
        $this->assertFalse($user->isVerified());
    }
}
