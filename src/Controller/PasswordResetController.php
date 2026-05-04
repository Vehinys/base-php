<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Form\ResetPasswordFormType;
use App\Form\ResetPasswordRequestFormType;
use App\Repository\UserRepository;
use App\Security\AppAuthenticator;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

#[Route('/reset-password')]
class PasswordResetController extends AbstractController
{
    public function __construct(private readonly MailerInterface $mailer)
    {
    }

    // Formulaire de demande de réinitialisation (entrer l'e-mail)
    #[Route('', name: 'app_reset_password_request', methods: ['GET', 'POST'])]
    public function request(Request $request, UserRepository $repo, EntityManagerInterface $em): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_home');
        }

        $form = $this->createForm(ResetPasswordRequestFormType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $emailAddress = $form->get('email')->getData();
            $user = $repo->findOneBy(['email' => $emailAddress]);

            // Traitement silencieux — ne révèle pas si l'e-mail est enregistré (anti-énumération)
            if ($user) {
                $user->setResetToken(bin2hex(random_bytes(32)))
                     ->setResetTokenExpiresAt(new \DateTime('+1 hour'));
                $em->flush();
                $this->sendResetEmail($user);
            }

            $this->addFlash('success', 'auth.reset_email_sent');

            return $this->redirectToRoute('app_reset_password_request');
        }

        return $this->render('password_reset/request.html.twig', ['form' => $form]);
    }

    // Formulaire de saisie du nouveau mot de passe (cliqué depuis l'e-mail)
    #[Route('/{token}', name: 'app_reset_password', methods: ['GET', 'POST'])]
    public function reset(
        string $token,
        Request $request,
        UserRepository $repo,
        EntityManagerInterface $em,
        UserPasswordHasherInterface $hasher,
        Security $security,
    ): Response {
        $user = $repo->findOneBy(['resetToken' => $token]);

        // Invalide si le token est inconnu ou expiré
        if (!$user || !$user->getResetTokenExpiresAt() || $user->getResetTokenExpiresAt() < new \DateTime()) {
            $this->addFlash('error', 'auth.reset_invalid');

            return $this->redirectToRoute('app_reset_password_request');
        }

        $form = $this->createForm(ResetPasswordFormType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $user->setPassword($hasher->hashPassword($user, $form->get('plainPassword')->getData()))
                 ->setResetToken(null)
                 ->setResetTokenExpiresAt(null)
                 // Réinitialiser via e-mail prouve la propriété de l'adresse
                 ->setIsVerified(true);
            $em->flush();

            // Connexion automatique après réinitialisation
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
