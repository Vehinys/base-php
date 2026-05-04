<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Service\AuditLogger;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/account')]
#[IsGranted('IS_AUTHENTICATED_REMEMBERED')]
class AccountController extends AbstractController
{
    #[Route('/delete', name: 'app_account_delete', methods: ['GET', 'POST'])]
    #[IsGranted('IS_AUTHENTICATED_FULLY')]
    public function delete(
        Request $request,
        EntityManagerInterface $em,
        UserPasswordHasherInterface $hasher,
        Security $security,
        AuditLogger $auditLogger,
    ): Response {
        /** @var User $user */
        $user = $this->getUser();

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('account_delete', $request->request->getString('_csrf_token'))) {
                $this->addFlash('error', 'account.delete_csrf_invalid');

                return $this->redirectToRoute('app_account_delete');
            }

            // Vérification du mot de passe uniquement pour les comptes locaux
            $plainPassword = $request->request->getString('password');
            if (null !== $user->getPassword()) {
                if (!$hasher->isPasswordValid($user, $plainPassword)) {
                    $this->addFlash('error', 'account.delete_password_wrong');

                    return $this->redirectToRoute('app_account_delete');
                }
            }

            $auditLogger->log('account.delete', $user, $request);

            // Anonymisation RGPD — préserve l'intégrité référentielle
            $user->setEmail('deleted_'.$user->getId().'@deleted.invalid')
                ->setName(null)
                ->setPassword(null)
                ->setGoogleId(null)
                ->setDiscordId(null)
                ->setAvatarUrl(null)
                ->setVerificationToken(null)
                ->setResetToken(null)
                ->setResetTokenExpiresAt(null)
                ->setIsVerified(false)
                ->setRoles([]);

            $em->flush();

            $security->logout(false);

            $this->addFlash('success', 'account.delete_success');

            return $this->redirectToRoute('app_home');
        }

        return $this->render('account/delete.html.twig');
    }

    #[Route('/export', name: 'app_account_export', methods: ['GET'])]
    public function export(AuditLogger $auditLogger, Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();

        $auditLogger->log('account.data_export', $user, $request);

        $providers = [];
        if ($user->getGoogleId()) {
            $providers[] = 'google';
        }
        if ($user->getDiscordId()) {
            $providers[] = 'discord';
        }
        if ($user->getPassword()) {
            $providers[] = 'email_password';
        }

        $data = [
            'export_date' => (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM),
            'data' => [
                'id' => $user->getId(),
                'name' => $user->getName(),
                'email' => $user->getEmail(),
                'created_at' => $user->getCreatedAt()->format(\DateTimeInterface::ATOM),
                'roles' => $user->getRoles(),
                'linked_providers' => $providers,
                'email_verified' => $user->isVerified(),
            ],
        ];

        return new JsonResponse($data, headers: [
            'Content-Disposition' => 'attachment; filename="baseapp-data-export.json"',
        ]);
    }
}
