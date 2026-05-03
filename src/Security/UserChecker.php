<?php

declare(strict_types=1);

namespace App\Security;

use App\Entity\User;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class UserChecker implements UserCheckerInterface
{
    public function checkPreAuth(UserInterface $user): void
    {
        if (!$user instanceof User) {
            return;
        }

        // Bloque la connexion tant que l'e-mail local n'est pas vérifié
        // Les comptes OAuth (Google, Discord) ont isVerified=true dès l'inscription
        if (!$user->isVerified()) {
            throw new CustomUserMessageAccountStatusException('auth.email_not_verified');
        }
    }

    public function checkPostAuth(UserInterface $user, ?TokenInterface $token = null): void
    {
        // Rien à vérifier après auth — validité gérée en pré-auth
    }
}
