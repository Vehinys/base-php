<?php

/**
 * Vérificateur de l'état du compte utilisateur avant et après authentification.
 *
 * Symfony appelle UserChecker en deux temps dans le flux d'authentification :
 *   1. checkPreAuth()  — avant la vérification du mot de passe
 *   2. checkPostAuth() — après validation des credentials
 *
 * Ce checker est enregistré dans security.yaml (user_checker: App\Security\UserChecker)
 * et s'applique uniquement au firewall `main` (connexion locale).
 * Les authenticators OAuth (Google, Discord) ne passent pas par ce checker
 * car ils ne sont pas des "form authenticators" classiques et parce qu'ils
 * forcent isVerified=true dès la première connexion.
 */

declare(strict_types=1);

namespace App\Security;

use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Bloque la connexion des comptes locaux dont l'e-mail n'a pas été vérifié.
 *
 * Lorsque l'authentification échoue via ce checker, Symfony génère un
 * CustomUserMessageAccountStatusException dont le message (clé de traduction
 * 'auth.email_not_verified') est affiché dans le template login.html.twig.
 * Ce même template propose un bouton de renvoi de l'e-mail de vérification.
 */
class UserChecker implements UserCheckerInterface
{
    /**
     * Vérifie l'état du compte AVANT la validation du mot de passe.
     *
     * Bloquer en pré-auth (plutôt qu'en post-auth) est plus sûr : on ne
     * révèle pas si le mot de passe est correct pour un compte non vérifié,
     * ce qui limite l'énumération d'informations sur les comptes.
     *
     * @param UserInterface $user L'utilisateur chargé depuis la base de données
     *
     * @throws CustomUserMessageAccountStatusException Si l'e-mail n'est pas encore vérifié
     */
    public function checkPreAuth(UserInterface $user): void
    {
        if (!$user instanceof User) {
            // Ignore les utilisateurs non-App (ex. in-memory users pour les tests)
            return;
        }

        if (!$user->isVerified()) {
            // Le message 'auth.email_not_verified' est traité comme une clé de traduction
            // dans le template login.html.twig pour afficher un message localisé
            throw new CustomUserMessageAccountStatusException('auth.email_not_verified');
        }
    }

    /**
     * Vérifications à effectuer APRÈS l'authentification réussie.
     *
     * Aucune vérification post-auth nécessaire dans notre cas :
     * la validité du compte est entièrement gérée en pré-auth.
     * Cette méthode doit exister pour satisfaire l'interface UserCheckerInterface.
     *
     * @param UserInterface       $user  L'utilisateur authentifié
     * @param TokenInterface|null $token Le token d'authentification (Symfony 6.2+)
     */
    public function checkPostAuth(UserInterface $user, ?TokenInterface $token = null): void
    {
        // Aucune vérification requise en post-auth
    }
}
