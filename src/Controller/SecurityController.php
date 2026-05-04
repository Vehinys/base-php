<?php

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

class SecurityController extends AbstractController
{
    public function __construct(private readonly MailerInterface $mailer)
    {
    }

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

            if ($hibp->isPwned($plainPassword)) {
                $form->get('plainPassword')->addError(
                    new FormError($translator->trans('form.password_pwned'))
                );

                return $this->render('security/register.html.twig', ['form' => $form]);
            }

            $user->setPassword($hasher->hashPassword($user, $plainPassword));
            $user->setVerificationToken(bin2hex(random_bytes(32)));
            $em->persist($user);
            $em->flush();

            $auditLogger->log('registration', $user, $request);

            $this->sendVerificationEmail($user);
            $request->getSession()->set('_verification_email', $user->getEmail());

            return $this->redirectToRoute('app_check_email');
        }

        return $this->render('security/register.html.twig', ['form' => $form]);
    }

    #[Route('/verify/email', name: 'app_check_email')]
    public function checkEmail(Request $request): Response
    {
        $email = $request->getSession()->get('_verification_email');
        if (!$email) {
            return $this->redirectToRoute('app_login');
        }

        return $this->render('security/check_email.html.twig', ['email' => $email]);
    }

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

    #[Route('/logout', name: 'app_logout')]
    public function logout(): never
    {
        throw new \LogicException('This method should never be reached.');
    }

    #[Route('/connect/google', name: 'connect_google')]
    public function connectGoogle(ClientRegistry $clientRegistry): RedirectResponse
    {
        return $clientRegistry->getClient('google')->redirect(['openid', 'profile', 'email'], []);
    }

    #[Route('/connect/google/check', name: 'connect_google_check')]
    public function connectGoogleCheck(): never
    {
        throw new \LogicException('This method should never be reached.');
    }

    #[Route('/connect/discord', name: 'connect_discord')]
    public function connectDiscord(ClientRegistry $clientRegistry): RedirectResponse
    {
        return $clientRegistry->getClient('discord')->redirect(['identify', 'email'], []);
    }

    #[Route('/connect/discord/check', name: 'connect_discord_check')]
    public function connectDiscordCheck(): never
    {
        throw new \LogicException('This method should never be reached.');
    }

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
