<?php

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

class DiscordAuthenticator extends OAuth2Authenticator
{
    public function __construct(
        private ClientRegistry $clientRegistry,
        private EntityManagerInterface $em,
        private RouterInterface $router,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return 'connect_discord_check' === $request->attributes->get('_route');
    }

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

                $user = $repo->findOneBy(['discordId' => (string) $discordUser->getId()])
                    ?? ($email ? $repo->findOneBy(['email' => $email]) : null);

                if (!$user) {
                    $user = (new User())
                        ->setEmail($email ?? $discordUser->getUsername().'@discord.invalid')
                        ->setIsVerified((bool) $discordUser->getVerified());
                }

                $avatarHash = $discordUser->getAvatarHash();
                $avatarUrl = $avatarHash
                    ? \sprintf('https://cdn.discordapp.com/avatars/%s/%s.png', $discordUser->getId(), $avatarHash)
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

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return new RedirectResponse($this->router->generate('app_home'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse($this->router->generate('app_login'));
    }
}
