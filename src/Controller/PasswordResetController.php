<?php

/**
 * Contrôleur de réinitialisation de mot de passe en deux étapes.
 *
 * Étape 1 — Demande (request) :
 *   1. Rate limiting par IP — 3 tentatives / heure (RateLimiterFactory 'password_reset_request')
 *      Le limiteur est consommé après soumission valide pour ne pas pénaliser les GET.
 *   2. Recherche de l'utilisateur par e-mail (silencieuse si non trouvé — anti-énumération)
 *   3. Génération d'un token reset (64 hex chars = 256 bits d'entropie) + expiration 1h
 *   4. Envoi d'e-mail + flash "e-mail envoyé" (même message si e-mail inconnu)
 *   5. Audit loggué uniquement si un utilisateur réel a été trouvé
 *
 * Étape 2 — Réinitialisation (reset) :
 *   1. Validation du token : existence + non-expiré (resetTokenExpiresAt > now)
 *   2. Validation du formulaire (contraintes CNIL : 12 chars, complexité, CSRF)
 *   3. Vérification HIBP (mot de passe compromis → erreur inline)
 *   4. Hashage argon2 + suppression du token + setIsVerified(true)
 *      (setIsVerified car un reset via e-mail prouve la propriété de l'adresse)
 *   5. Connexion automatique + audit
 *
 * Sécurité du token :
 *   - Token stocké en clair en base (acceptable car: entropie 256 bits, durée 1h, usage unique)
 *   - Supprimé immédiatement après utilisation (invalidation one-shot)
 *   - Expiration stricte : la comparaison < new \DateTime() couvre le fuseau horaire du serveur
 *
 * Préfixe de route : /reset-password (déclaré sur la classe via #[Route('/reset-password')])
 */

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

/**
 * Gère le flux de réinitialisation de mot de passe en deux étapes.
 *
 * Toutes les routes sont préfixées /reset-password.
 * L'utilisateur connecté est redirigé vers l'accueil sur la route de demande
 * (pas de reset pour un compte déjà authentifié).
 */
#[Route('/reset-password')]
class PasswordResetController extends AbstractController
{
    /**
     * @param MailerInterface $mailer Service d'envoi d'e-mails Symfony
     */
    public function __construct(private readonly MailerInterface $mailer)
    {
    }

    /**
     * Étape 1 — Affiche et traite le formulaire de demande de réinitialisation.
     *
     * Le traitement est silencieux côté utilisateur : la réponse est identique
     * qu'un compte existe ou non pour l'e-mail saisi (anti-énumération).
     *
     * @param Request              $request                  Requête HTTP courante
     * @param UserRepository       $repo                     Repository pour trouver l'utilisateur par e-mail
     * @param EntityManagerInterface $em                     Entity Manager pour persister le token reset
     * @param RateLimiterFactory   $passwordResetRequestLimiter Limiteur (3 requêtes / heure par IP)
     * @param AuditLogger          $auditLogger              Service d'audit de sécurité
     */
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
            // Rate limit vérifié après soumission valide seulement (GET non consommés)
            if (!$limiter->consume(1)->isAccepted()) {
                $this->addFlash('error', 'error.too_many_requests');

                return $this->redirectToRoute('app_reset_password_request');
            }

            $emailAddress = $form->get('email')->getData();
            $user = $repo->findOneBy(['email' => $emailAddress]);

            // Traitement conditionnel mais réponse identique : l'attaquant ne sait pas
            // si l'e-mail est enregistré (protection contre l'énumération de comptes)
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

    /**
     * Étape 2 — Affiche et traite le formulaire de saisie du nouveau mot de passe.
     *
     * Le token est valide uniquement s'il existe en base ET n'est pas expiré.
     * Un token invalide redirige vers la demande avec un message d'erreur générique.
     *
     * @param string                      $token       Token extrait de l'URL (64 hex chars)
     * @param Request                     $request     Requête HTTP courante
     * @param UserRepository              $repo        Repository pour valider le token
     * @param EntityManagerInterface      $em          Entity Manager pour persister le nouveau mot de passe
     * @param UserPasswordHasherInterface $hasher      Service de hashage argon2
     * @param Security                    $security    Service Symfony pour la connexion automatique post-reset
     * @param HibpService                 $hibp        Service de vérification HIBP
     * @param AuditLogger                 $auditLogger Service d'audit
     * @param TranslatorInterface         $translator  Traducteur pour le message d'erreur HIBP
     */
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

        // Validation stricte : token inexistant OU expiré → rejet immédiat
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
                 ->setResetToken(null)           // Invalidation one-shot du token
                 ->setResetTokenExpiresAt(null)
                 ->setIsVerified(true);           // Reset via e-mail prouve la propriété du compte
            $em->flush();

            $auditLogger->log('password_reset.completed', $user, $request);

            // Connexion automatique après reset — évite une seconde authentification redondante
            return $security->login($user, AppAuthenticator::class, 'main');
        }

        return $this->render('password_reset/reset.html.twig', ['form' => $form]);
    }

    /**
     * Construit et envoie l'e-mail contenant le lien de réinitialisation.
     *
     * L'URL est absolue (ABSOLUTE_URL) pour fonctionner dans les clients mail.
     * Elle contient le token en clair : sécurisé car HTTPS + entropie 256 bits + durée 1h.
     *
     * @param User $user Utilisateur destinataire (doit avoir resetToken non null)
     */
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
