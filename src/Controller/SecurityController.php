<?php

/**
 * Contrôleur principal de la sécurité : connexion, inscription et vérification d'e-mail.
 *
 * Flux d'inscription (register) :
 *   1. Rate limiting par IP — 5 tentatives / heure (RateLimiterFactory 'registration')
 *   2. Validation du formulaire (contraintes Symfony : CNIL 12 chars, complexité, CSRF)
 *   3. Vérification HIBP k-anonymat — mot de passe compromis → erreur de formulaire
 *   4. Hashage argon2 + génération du token de vérification (64 hex chars = 256 bits)
 *   5. Persistance + audit + envoi d'e-mail de vérification
 *
 * Flux de vérification d'e-mail (verifyEmail) :
 *   - Token en URL → findOneBy(['verificationToken' => $token])
 *   - Si trouvé : setIsVerified(true) + audit + connexion automatique via Security::login()
 *   - Si non trouvé : flash error + redirection login (pas de révélation d'information)
 *
 * Renvoi de vérification (resendVerification) :
 *   - CSRF requis (formulaire caché dans check_email.html.twig)
 *   - Traitement silencieux : même comportement si l'e-mail existe ou non (anti-énumération)
 *   - Nouveau token généré à chaque renvoi (invalide l'ancien lien)
 *
 * Routes OAuth :
 *   - /connect/google et /connect/discord → démarrage du flux Authorization Code
 *   - /connect/google/check et /connect/discord/check → callback géré par les Authenticators
 *     (GoogleAuthenticator / DiscordAuthenticator via KnpU). La méthode PHP lance une
 *     LogicException car Symfony intercepte la requête avant qu'elle soit atteinte.
 *
 * Route /logout :
 *   - Gérée entièrement par le firewall Symfony (security.yaml > logout)
 *   - La méthode PHP ne sera jamais exécutée (LogicException de documentation)
 */

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Form\RegistrationFormType;
use App\Repository\UserRepository;
use App\Security\AppAuthenticator;
use App\Service\AuditLogger;
use App\Service\HibpService;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Form\FormError;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Gère le cycle de vie de l'authentification locale et OAuth.
 *
 * Délègue la connexion proprement dite à AppAuthenticator (formulaire),
 * GoogleAuthenticator et DiscordAuthenticator (OAuth2).
 * Ce contrôleur ne manipule jamais directement les tokens Symfony Security.
 */
class SecurityController extends AbstractController
{
    /**
     * @param MailerInterface $mailer Service d'envoi d'e-mails Symfony (SMTP ou DSN configuré)
     */
    public function __construct(private readonly MailerInterface $mailer)
    {
    }

    /**
     * Affiche le formulaire de connexion par e-mail/mot de passe.
     *
     * Si l'utilisateur est déjà connecté, redirige vers l'accueil (évite le double-login).
     * AuthenticationUtils lit les données de la dernière tentative depuis la session
     * pour repopuler le champ e-mail et afficher le message d'erreur traduit.
     *
     * @param AuthenticationUtils $authenticationUtils Utilitaire Symfony pour l'état du dernier login
     */
    #[Route('/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_home');
        }

        return $this->render('security/login.html.twig', [
            'last_username' => $authenticationUtils->getLastUsername(),
            'error' => $authenticationUtils->getLastAuthenticationError(),
        ]);
    }

    /**
     * Traite le formulaire d'inscription.
     *
     * Flux complet : rate limit → validation → HIBP → hashage → persistence → audit → e-mail.
     *
     * @param Request                     $request           Requête HTTP (GET affiche le formulaire, POST le traite)
     * @param UserPasswordHasherInterface $hasher            Service de hashage argon2 Symfony
     * @param EntityManagerInterface      $em                Entity Manager pour persister l'utilisateur
     * @param RateLimiterFactory          $registrationLimiter Limiteur injecté par convention de nommage
     * @param HibpService                 $hibp              Service de vérification HIBP
     * @param AuditLogger                 $auditLogger       Service d'audit des événements de sécurité
     * @param TranslatorInterface         $translator        Traducteur pour les messages d'erreur HIBP
     */
    #[Route('/register', name: 'app_register')]
    public function register(
        Request $request,
        UserPasswordHasherInterface $hasher,
        EntityManagerInterface $em,
        RateLimiterFactory $registrationLimiter,
        HibpService $hibp,
        AuditLogger $auditLogger,
        TranslatorInterface $translator,
    ): Response {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_home');
        }

        // Consomme 1 jeton du limiteur AVANT de traiter le formulaire
        // La vérification en amont de isSubmitted() protège aussi les requêtes GET répétées
        $limiter = $registrationLimiter->create($request->getClientIp());
        if (!$limiter->consume(1)->isAccepted()) {
            $this->addFlash('error', 'error.too_many_requests');

            return $this->render('security/register.html.twig', [
                'form' => $this->createForm(RegistrationFormType::class, new User()),
            ]);
        }

        $user = new User();
        $form = $this->createForm(RegistrationFormType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            /** @var string $plainPassword */
            $plainPassword = $form->get('plainPassword')->getData();

            // HIBP check après validation des contraintes (longueur, complexité)
            // L'erreur est ajoutée sur le champ 'plainPassword' et non via addFlash()
            // pour être affiché inline dans le formulaire
            if ($hibp->isPwned($plainPassword)) {
                $form->get('plainPassword')->addError(
                    new FormError($translator->trans('form.password_pwned'))
                );

                return $this->render('security/register.html.twig', ['form' => $form]);
            }

            $user->setPassword($hasher->hashPassword($user, $plainPassword));
            // Token de vérification : 32 octets = 256 bits d'entropie, stocké en hex (64 chars)
            $user->setVerificationToken(bin2hex(random_bytes(32)));
            $em->persist($user);
            $em->flush();

            $auditLogger->log('registration', $user, $request);

            $this->sendVerificationEmail($user);
            // Stocké en session pour afficher l'adresse sur la page check_email
            $request->getSession()->set('_verification_email', $user->getEmail());

            return $this->redirectToRoute('app_check_email');
        }

        return $this->render('security/register.html.twig', ['form' => $form]);
    }

    /**
     * Affiche la page de confirmation d'envoi d'e-mail de vérification.
     *
     * L'e-mail affiché vient de la session (évite de l'exposer dans l'URL).
     * Si la session ne contient pas cet e-mail (accès direct), redirige vers login.
     *
     * @param Request $request Requête courante pour lire la session
     */
    #[Route('/verify/email', name: 'app_check_email')]
    public function checkEmail(Request $request): Response
    {
        $email = $request->getSession()->get('_verification_email');
        if (!$email) {
            return $this->redirectToRoute('app_login');
        }

        return $this->render('security/check_email.html.twig', ['email' => $email]);
    }

    /**
     * Vérifie le token d'e-mail et connecte l'utilisateur automatiquement.
     *
     * La connexion après vérification (Security::login()) est UX — l'utilisateur
     * vient de prouver qu'il contrôle l'adresse e-mail, inutile de lui redemander son mot de passe.
     *
     * @param string                 $token       Token extrait de l'URL (64 hex chars)
     * @param UserRepository         $repo        Repository pour trouver l'utilisateur par token
     * @param EntityManagerInterface $em          Entity Manager pour flush après setIsVerified
     * @param Security               $security    Service Symfony pour déclencher la connexion programmatique
     * @param AuditLogger            $auditLogger Service d'audit
     * @param Request                $request     Requête courante (pour l'IP dans l'audit)
     */
    #[Route('/verify/email/{token}', name: 'app_verify_email')]
    public function verifyEmail(
        string $token,
        UserRepository $repo,
        EntityManagerInterface $em,
        Security $security,
        AuditLogger $auditLogger,
        Request $request,
    ): Response {
        $user = $repo->findOneBy(['verificationToken' => $token]);

        if (!$user) {
            $this->addFlash('error', 'auth.verify_invalid');

            return $this->redirectToRoute('app_login');
        }

        $user->setIsVerified(true)->setVerificationToken(null);
        $em->flush();

        $auditLogger->log('email.verified', $user, $request);

        return $security->login($user, AppAuthenticator::class, 'main');
    }

    /**
     * Renvoie l'e-mail de vérification à la demande de l'utilisateur.
     *
     * Traitement intentionnellement silencieux : qu'un compte existe ou non,
     * la redirection est la même (anti-énumération d'e-mails).
     * Un nouveau token est généré à chaque renvoi pour invalider les anciens liens.
     *
     * @param Request                $request Requête POST avec _csrf_token et email
     * @param UserRepository         $repo    Repository pour trouver l'utilisateur
     * @param EntityManagerInterface $em      Entity Manager pour flush le nouveau token
     */
    #[Route('/verify/resend', name: 'app_resend_verification', methods: ['POST'])]
    public function resendVerification(Request $request, UserRepository $repo, EntityManagerInterface $em): Response
    {
        if (!$this->isCsrfTokenValid('resend_verification', $request->request->getString('_csrf_token'))) {
            return $this->redirectToRoute('app_login');
        }

        $email = $request->request->getString('email');
        $user = $repo->findOneBy(['email' => $email]);

        if ($user && !$user->isVerified()) {
            $user->setVerificationToken(bin2hex(random_bytes(32)));
            $em->flush();
            $this->sendVerificationEmail($user);
        }

        $request->getSession()->set('_verification_email', $email);

        return $this->redirectToRoute('app_check_email');
    }

    /**
     * Route de déconnexion — interceptée par le firewall Symfony avant d'atteindre ce code.
     *
     * La configuration `logout.path: app_logout` dans security.yaml fait en sorte que
     * Symfony gère la déconnexion (invalidation session, suppression cookie remember-me)
     * avant d'appeler ce contrôleur. Cette méthode ne sera donc jamais exécutée.
     */
    #[Route('/logout', name: 'app_logout')]
    public function logout(): never
    {
        throw new \LogicException('This method should never be reached.');
    }

    /**
     * Démarre le flux OAuth2 Authorization Code vers Google.
     *
     * Les scopes 'openid', 'profile' et 'email' sont demandés.
     * Google garantit la fourniture de l'e-mail vérifié pour ces scopes.
     *
     * @param ClientRegistry $clientRegistry Registre KnpU des clients OAuth2
     */
    #[Route('/connect/google', name: 'connect_google')]
    public function connectGoogle(ClientRegistry $clientRegistry): RedirectResponse
    {
        return $clientRegistry->getClient('google')->redirect(['openid', 'profile', 'email'], []);
    }

    /**
     * Route de callback Google OAuth2 — interceptée par GoogleAuthenticator.
     *
     * KnpU/Symfony intercepte cette route via supports() avant que PHP l'atteigne.
     * Cette méthode ne sera jamais exécutée.
     */
    #[Route('/connect/google/check', name: 'connect_google_check')]
    public function connectGoogleCheck(): never
    {
        throw new \LogicException('This method should never be reached.');
    }

    /**
     * Démarre le flux OAuth2 Authorization Code vers Discord.
     *
     * Le scope 'identify' est obligatoire (username, avatar).
     * Le scope 'email' est demandé mais peut être refusé par l'utilisateur.
     *
     * @param ClientRegistry $clientRegistry Registre KnpU des clients OAuth2
     */
    #[Route('/connect/discord', name: 'connect_discord')]
    public function connectDiscord(ClientRegistry $clientRegistry): RedirectResponse
    {
        return $clientRegistry->getClient('discord')->redirect(['identify', 'email'], []);
    }

    /**
     * Route de callback Discord OAuth2 — interceptée par DiscordAuthenticator.
     *
     * KnpU/Symfony intercepte cette route via supports() avant que PHP l'atteigne.
     * Cette méthode ne sera jamais exécutée.
     */
    #[Route('/connect/discord/check', name: 'connect_discord_check')]
    public function connectDiscordCheck(): never
    {
        throw new \LogicException('This method should never be reached.');
    }

    /**
     * Construit et envoie l'e-mail de vérification d'adresse.
     *
     * L'URL de vérification est absolue (ABSOLUTE_URL) pour fonctionner dans les clients mail.
     * Le template emails/verify_email.html.twig gère la mise en forme HTML.
     *
     * @param User $user Utilisateur destinataire (doit avoir verificationToken non null)
     */
    private function sendVerificationEmail(User $user): void
    {
        $verifyUrl = $this->generateUrl(
            'app_verify_email',
            ['token' => $user->getVerificationToken()],
            UrlGeneratorInterface::ABSOLUTE_URL
        );

        $email = (new Email())
            ->from(new Address('noreply@baseapp.dev', 'BaseApp'))
            ->to((string) $user->getEmail())
            ->subject('Vérifiez votre adresse e-mail — BaseApp')
            ->html($this->renderView('emails/verify_email.html.twig', [
                'user' => $user,
                'verifyUrl' => $verifyUrl,
            ]));

        $this->mailer->send($email);
    }
}
