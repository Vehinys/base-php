<?php

/**
 * Authenticator OAuth2 pour la connexion via Discord.
 *
 * Implémente le flux Authorization Code OAuth2 via KnpU OAuth2 Client Bundle.
 * Le scope `identify` est requis (username, avatar) ; le scope `email` est
 * demandé mais peut être refusé par l'utilisateur Discord.
 *
 * Particularité Discord vs Google :
 *   - L'e-mail n'est pas garanti (scope optionnel refusable)
 *   - L'avatar est un hash CDN, pas une URL directe
 *   - Le compte Discord peut ne pas avoir d'e-mail vérifié côté Discord
 *
 * Stratégie de lookup (identique à Google) :
 *   1. Par discordId → compte déjà lié
 *   2. Par email (si disponible) → compte local existant à lier
 *   3. Création d'un nouveau compte (avec e-mail de fallback @discord.invalid si absent)
 */

declare(strict_types=1);

namespace App\Security;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Wohali\OAuth2\Client\Provider\DiscordResourceOwner;

/**
 * Gère l'authentification OAuth2 via Discord.
 *
 * SelfValidatingPassport : la preuve d'identité est le token Discord,
 * pas un mot de passe à vérifier localement.
 */
class DiscordAuthenticator extends OAuth2Authenticator
{
    /**
     * @param ClientRegistry         $clientRegistry Registre des clients OAuth2 (KnpU)
     * @param EntityManagerInterface $em             Entity Manager Doctrine pour la persistance
     * @param RouterInterface        $router         Routeur Symfony pour les redirections
     */
    public function __construct(
        private ClientRegistry $clientRegistry,
        private EntityManagerInterface $em,
        private RouterInterface $router,
    ) {
    }

    /**
     * Active cet authenticator uniquement sur la route de callback Discord.
     */
    public function supports(Request $request): ?bool
    {
        return 'connect_discord_check' === $request->attributes->get('_route');
    }

    /**
     * Récupère les infos Discord et construit le Passport d'authentification.
     *
     * Construction de l'URL avatar :
     *   - Si avatarHash != null → CDN Discord : https://cdn.discordapp.com/avatars/{id}/{hash}.png
     *   - Si avatarHash == null → Discord utilise un avatar par défaut générique,
     *     on stocke null (le template affiche l'initiale du nom comme fallback)
     *
     * @param Request $request Requête callback Discord avec le paramètre `code`
     */
    public function authenticate(Request $request): Passport
    {
        $client = $this->clientRegistry->getClient('discord');
        $accessToken = $this->fetchAccessToken($client);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function () use ($accessToken, $client) {
                /** @var DiscordResourceOwner $discordUser */
                $discordUser = $client->fetchUserFromToken($accessToken);
                $email = $discordUser->getEmail();
                $repo = $this->em->getRepository(User::class);

                // Priorité à l'ID Discord ; fallback email uniquement si le scope 'email' a été accordé
                $user = $repo->findOneBy(['discordId' => (string) $discordUser->getId()])
                    ?? ($email ? $repo->findOneBy(['email' => $email]) : null);

                if (!$user) {
                    // Fallback e-mail : @discord.invalid si l'e-mail n'est pas fourni
                    // Ce compte ne pourra pas être vérifié par e-mail mais reste utilisable via Discord
                    $user = (new User())->setEmail($email ?? $discordUser->getUsername().'@discord.invalid');
                }

                // La connexion OAuth prouve l'identité Discord → compte considéré vérifié
                $user->setIsVerified(true);

                // Construction de l'URL d'avatar Discord à partir du hash CDN
                // getAvatarHash() retourne null si l'utilisateur utilise l'avatar par défaut Discord
                $avatarHash = $discordUser->getAvatarHash();
                $avatarUrl = $avatarHash
                    ? \sprintf(
                        'https://cdn.discordapp.com/avatars/%s/%s.png',
                        $discordUser->getId(),
                        $avatarHash
                    )
                    : null;

                $user->setDiscordId((string) $discordUser->getId())
                    ->setName($discordUser->getUsername())
                    ->setAvatarUrl($avatarUrl);

                $this->em->persist($user);
                $this->em->flush();

                return $user;
            })
        );
    }

    /**
     * Redirige vers l'accueil après une authentification Discord réussie.
     * SecurityAuditSubscriber loggue l'événement login.success automatiquement.
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return new RedirectResponse($this->router->generate('app_home'));
    }

    /**
     * Stocke l'exception en session et redirige vers le formulaire de connexion.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse($this->router->generate('app_login'));
    }
}
