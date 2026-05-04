<?php

/**
 * Authenticator OAuth2 pour la connexion via Google.
 *
 * Implémente le flux Authorization Code OAuth2 grâce au bundle KnpU OAuth2.
 * La route /connect/google/check est configurée dans security.yaml comme
 * custom_authenticator ; Symfony redirige automatiquement le callback Google
 * vers cet authenticator via supports().
 *
 * Stratégie de lookup utilisateur (par ordre de priorité) :
 *   1. Recherche par googleId → compte déjà lié à Google
 *   2. Recherche par email → compte local existant à lier automatiquement
 *   3. Création d'un nouveau compte si aucun résultat
 *
 * Sécurité e-mail : si un utilisateur existant (trouvé par googleId) a
 * un e-mail différent de celui retourné par Google, un warning est loggué
 * mais l'e-mail N'EST PAS mis à jour automatiquement (risque de hijacking).
 */

declare(strict_types=1);

namespace App\Security;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use League\OAuth2\Client\Provider\GoogleUser;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
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

/**
 * Gère l'authentification OAuth2 via Google.
 *
 * Le Passport retourné est un SelfValidatingPassport : il n'y a pas de
 * mot de passe à valider (la preuve d'identité est le token Google).
 * La callback du UserBadge est appelée par Symfony pour charger/créer l'entité User.
 */
class GoogleAuthenticator extends OAuth2Authenticator
{
    /**
     * @param ClientRegistry  $clientRegistry Registre des clients OAuth2 (KnpU)
     * @param EntityManagerInterface $em      Entity Manager Doctrine pour la persistance
     * @param RouterInterface $router         Routeur Symfony pour les redirections
     * @param LoggerInterface $logger         Logger du canal "security" (via Autowire)
     */
    public function __construct(
        private ClientRegistry $clientRegistry,
        private EntityManagerInterface $em,
        private RouterInterface $router,
        #[Autowire(service: 'monolog.logger.security')]
        private LoggerInterface $logger,
    ) {
    }

    /**
     * Détermine si cet authenticator gère la requête courante.
     *
     * Retourne true uniquement sur la route de callback Google,
     * évitant toute interférence avec les autres routes.
     */
    public function supports(Request $request): ?bool
    {
        return 'connect_google_check' === $request->attributes->get('_route');
    }

    /**
     * Récupère le token d'accès Google et construit le Passport d'authentification.
     *
     * La closure du UserBadge est exécutée de manière différée par Symfony :
     *   1. fetchAccessToken() échange le code d'autorisation contre un access token
     *   2. fetchUserFromToken() appelle l'API Google Userinfo pour récupérer les données
     *   3. L'utilisateur est cherché ou créé, et ses infos sont mises à jour
     *
     * @param Request $request Requête callback de Google avec le paramètre `code`
     */
    public function authenticate(Request $request): Passport
    {
        $client = $this->clientRegistry->getClient('google');
        $accessToken = $this->fetchAccessToken($client);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function () use ($accessToken, $client) {
                /** @var GoogleUser $googleUser */
                $googleUser = $client->fetchUserFromToken($accessToken);
                $email = $googleUser->getEmail();
                $repo = $this->em->getRepository(User::class);

                // Lookup par Google ID en priorité (plus stable que l'e-mail qui peut changer)
                // Fallback sur l'e-mail pour lier un compte local existant
                $user = $repo->findOneBy(['googleId' => $googleUser->getId()])
                    ?? $repo->findOneBy(['email' => $email]);

                // Détection d'un changement d'e-mail côté Google
                // On ne met pas à jour automatiquement pour éviter le hijacking :
                // un attaquant qui contrôlerait l'e-mail Google ne pourrait pas
                // prendre le contrôle d'un compte local différent
                if ($user && $user->getEmail() !== $email) {
                    $this->logger->warning('google_oauth.email_mismatch', [
                        'user_id'      => $user->getId(),
                        'stored_email' => $user->getEmail(),
                        'google_email' => $email,
                    ]);
                }

                // Création d'un nouveau compte si aucun utilisateur trouvé
                if (!$user) {
                    $user = (new User())->setEmail($email);
                }

                // Google garantit la propriété de l'e-mail → le compte est toujours vérifié
                // Met à jour le profil à chaque connexion (avatar, nom pouvant changer)
                $user->setIsVerified(true)
                    ->setGoogleId($googleUser->getId())
                    ->setName($googleUser->getName())
                    ->setAvatarUrl($googleUser->getAvatar());

                $this->em->persist($user);
                $this->em->flush();

                return $user;
            })
        );
    }

    /**
     * Redirige vers la page d'accueil après une authentification Google réussie.
     * SecurityAuditSubscriber loggue l'événement login.success automatiquement.
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return new RedirectResponse($this->router->generate('app_home'));
    }

    /**
     * Stocke l'exception en session et redirige vers le formulaire de connexion.
     *
     * L'exception est lue par AuthenticationUtils::getLastAuthenticationError()
     * dans SecurityController::login() et affichée dans le template.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse($this->router->generate('app_login'));
    }
}
