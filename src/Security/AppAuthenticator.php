<?php

/**
 * Authenticator principal pour la connexion par e-mail et mot de passe.
 *
 * Étend AbstractLoginFormAuthenticator qui gère automatiquement :
 *   - la détection des requêtes de login (méthode POST sur LOGIN_ROUTE)
 *   - la redirection vers le formulaire de connexion si l'accès est refusé
 *   - la gestion de TargetPathTrait pour la redirection post-login
 *
 * Le rate limiting (5 tentatives / 15 min) est configuré dans security.yaml
 * via `login_throttling` et géré nativement par le firewall Symfony.
 */

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * Gère l'authentification locale par e-mail et mot de passe.
 *
 * Flux d'authentification :
 *   1. L'utilisateur soumet le formulaire /login (POST)
 *   2. authenticate() construit un Passport avec les badges de validation
 *   3. Symfony valide le CSRF, vérifie le mot de passe (argon2), charge le User
 *   4. UserChecker::checkPreAuth() vérifie que l'e-mail est vérifié
 *   5. onAuthenticationSuccess() redirige vers la page d'origine ou l'accueil
 *
 * En cas d'échec, Symfony déclenche LoginFailureEvent → SecurityAuditSubscriber loggue.
 */
class AppAuthenticator extends AbstractLoginFormAuthenticator
{
    /**
     * TargetPathTrait mémorise l'URL protégée visitée avant la redirection vers /login.
     * Permet de renvoyer l'utilisateur sur sa page d'origine après connexion réussie.
     */
    use TargetPathTrait;

    /** Nom de la route du formulaire de connexion — utilisé par AbstractLoginFormAuthenticator. */
    public const LOGIN_ROUTE = 'app_login';

    /**
     * @param UrlGeneratorInterface $urlGenerator Générateur d'URL Symfony pour les redirections
     */
    public function __construct(private UrlGeneratorInterface $urlGenerator)
    {
    }

    /**
     * Construit le Passport d'authentification à partir des données du formulaire.
     *
     * Le Passport contient trois éléments :
     *   - UserBadge : identifie l'utilisateur par son e-mail
     *   - PasswordCredentials : le mot de passe en clair à vérifier contre le hash argon2
     *   - CsrfTokenBadge : valide le token _csrf_token du formulaire (anti-CSRF)
     *   - RememberMeBadge : active le cookie persistant si la case "Se souvenir" est cochée
     *
     * @param Request $request Requête POST du formulaire de connexion
     */
    public function authenticate(Request $request): Passport
    {
        $email = $request->getPayload()->getString('email');

        // Stocke l'e-mail en session pour le repopuler dans le formulaire après un échec
        $request->getSession()->set(SecurityRequestAttributes::LAST_USERNAME, $email);

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($request->getPayload()->getString('password')),
            [
                // Valide le jeton _csrf_token soumis avec le formulaire de connexion
                new CsrfTokenBadge('authenticate', $request->getPayload()->getString('_csrf_token')),
                // Active le cookie remember-me si la case est cochée (durée: 7 jours via security.yaml)
                new RememberMeBadge(),
            ]
        );
    }

    /**
     * Redirige l'utilisateur après une authentification réussie.
     *
     * Priorité de redirection :
     *   1. URL d'origine mémorisée par TargetPathTrait (page protégée visitée avant login)
     *   2. Page d'accueil par défaut
     *
     * @param Request        $request      Requête courante
     * @param TokenInterface $token        Token d'authentification contenant l'utilisateur
     * @param string         $firewallName Nom du firewall actif (ex. "main")
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('app_home'));
    }

    /**
     * Retourne l'URL du formulaire de connexion.
     *
     * Utilisée par AbstractLoginFormAuthenticator pour rediriger vers /login
     * lorsqu'une ressource protégée est accédée sans authentification.
     */
    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}
