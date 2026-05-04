<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Form\ResetPasswordFormType;
use App\Form\ResetPasswordRequestFormType;
use App\Repository\UserRepository;
use App\Security\AppAuthenticator;
use App\Service\AuditLogger;
use App\Service\HibpService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Form\FormError;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

#[Route('/reset-password')]
class PasswordResetController extends AbstractController
{
    public function __construct(private readonly MailerInterface $mailer)
    {
    }

    #[Route('', name: 'app_reset_password_request', methods: ['GET', 'POST'])]
    public function request(
        Request $request,
        UserRepository $repo,
        EntityManagerInterface $em,
        RateLimiterFactory $passwordResetRequestLimiter,
        AuditLogger $auditLogger,
    ): Response {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_home');
        }

        $limiter = $passwordResetRequestLimiter->create($request->getClientIp());

        $form = $this->createForm(ResetPasswordRequestFormType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            if (!$limiter->consume(1)->isAccepted()) {
                $this->addFlash('error', 'error.too_many_requests');

                return $this->redirectToRoute('app_reset_password_request');
            }

            $emailAddress = $form->get('email')->getData();
            $user = $repo->findOneBy(['email' => $emailAddress]);

            if ($user) {
                $user->setResetToken(bin2hex(random_bytes(32)))
                     ->setResetTokenExpiresAt(new \DateTime('+1 hour'));
                $em->flush();
                $this->sendResetEmail($user);
                $auditLogger->log('password_reset.requested', $user, $request);
            }

            $this->addFlash('success', 'auth.reset_email_sent');

            return $this->redirectToRoute('app_reset_password_request');
        }

        return $this->render('password_reset/request.html.twig', ['form' => $form]);
    }

    #[Route('/{token}', name: 'app_reset_password', methods: ['GET', 'POST'])]
    public function reset(
        string $token,
        Request $request,
        UserRepository $repo,
        EntityManagerInterface $em,
        UserPasswordHasherInterface $hasher,
        Security $security,
        HibpService $hibp,
        AuditLogger $auditLogger,
        TranslatorInterface $translator,
    ): Response {
        $user = $repo->findOneBy(['resetToken' => $token]);

        if (!$user || !$user->getResetTokenExpiresAt() || $user->getResetTokenExpiresAt() < new \DateTime()) {
            $this->addFlash('error', 'auth.reset_invalid');

            return $this->redirectToRoute('app_reset_password_request');
        }

        $form = $this->createForm(ResetPasswordFormType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            /** @var string $plainPassword */
            $plainPassword = $form->get('plainPassword')->getData();

            if ($hibp->isPwned($plainPassword)) {
                $form->get('plainPassword')->addError(
                    new FormError($translator->trans('form.password_pwned'))
                );

                return $this->render('password_reset/reset.html.twig', ['form' => $form]);
            }

            $user->setPassword($hasher->hashPassword($user, $plainPassword))
                 ->setResetToken(null)
                 ->setResetTokenExpiresAt(null)
                 ->setIsVerified(true);
            $em->flush();

            $auditLogger->log('password_reset.completed', $user, $request);

            return $security->login($user, AppAuthenticator::class, 'main');
        }

        return $this->render('password_reset/reset.html.twig', ['form' => $form]);
    }

    private function sendResetEmail(User $user): void
    {
        $resetUrl = $this->generateUrl(
            'app_reset_password',
            ['token' => $user->getResetToken()],
            UrlGeneratorInterface::ABSOLUTE_URL
        );

        $email = (new Email())
            ->from(new Address('noreply@baseapp.dev', 'BaseApp'))
            ->to((string) $user->getEmail())
            ->subject('Réinitialisation de votre mot de passe — BaseApp')
            ->html($this->renderView('emails/reset_password.html.twig', [
                'user' => $user,
                'resetUrl' => $resetUrl,
            ]));

        $this->mailer->send($email);
    }
}
