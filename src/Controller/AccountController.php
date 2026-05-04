<?php

/**
 * Contrôleur de gestion du compte utilisateur (RGPD).
 *
 * Expose deux actions conformes au Règlement Général sur la Protection des Données :
 *
 * 1. Suppression (art. 17 — droit à l'effacement) :
 *    - Authentification complète requise (IS_AUTHENTICATED_FULLY) — cookie remember-me insuffisant
 *    - Protection CSRF obligatoire (token 'account_delete')
 *    - Pour les comptes locaux : vérification du mot de passe actuel
 *    - Pour les comptes OAuth purs (sans mot de passe) : suppression sans vérification de MDP
 *    - Anonymisation plutôt que suppression physique : préserve l'intégrité référentielle
 *      de la table security_log (logs d'audit conservés par obligation légale)
 *    - Schéma d'anonymisation : email → deleted_{id}@deleted.invalid, tous les champs
 *      personnels à null, isVerified=false, roles=[]
 *
 * 2. Export (art. 20 — portabilité des données) :
 *    - Cookie remember-me suffisant (IS_AUTHENTICATED_REMEMBERED sur la classe)
 *    - Téléchargement JSON avec Content-Disposition: attachment
 *    - Contenu : id, nom, e-mail, date de création, rôles, providers OAuth liés, statut vérifié
 *    - Audit loggué avant l'envoi (traçabilité RGPD)
 *
 * Niveau d'authentification :
 *    - Classe : IS_AUTHENTICATED_REMEMBERED — valide pour l'export (faible risque)
 *    - delete() : IS_AUTHENTICATED_FULLY — surcharge nécessaire (action irréversible)
 *    - IS_AUTHENTICATED_FULLY rejette les sessions remember-me (cookie persistant non-interactif)
 *      → l'utilisateur doit avoir saisi son mot de passe dans la session courante
 */

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

/**
 * Gère la suppression (RGPD art. 17) et l'export (RGPD art. 20) des données personnelles.
 *
 * Toutes les routes sont préfixées /account.
 * IS_AUTHENTICATED_REMEMBERED est le niveau minimum pour l'accès au contrôleur ;
 * delete() surcharge avec IS_AUTHENTICATED_FULLY pour l'action destructive.
 */
#[Route('/account')]
#[IsGranted('IS_AUTHENTICATED_REMEMBERED')]
class AccountController extends AbstractController
{
    /**
     * Supprime (anonymise) le compte de l'utilisateur connecté.
     *
     * GET → affiche la page de confirmation avec formulaire CSRF + champ mot de passe
     * POST → valide CSRF, vérifie MDP (comptes locaux uniquement), anonymise, déconnecte
     *
     * La déconnexion programmatique (Security::logout(false)) invalide la session
     * sans déclencher le flux de déconnexion complet (pas de redirection configurée).
     * Le false indique de ne pas invalider la session Symfony (on redirige manuellement).
     *
     * @param Request                     $request     Requête HTTP courante
     * @param EntityManagerInterface      $em          Entity Manager pour flush l'anonymisation
     * @param UserPasswordHasherInterface $hasher      Service de vérification du mot de passe actuel
     * @param Security                    $security    Service Symfony pour la déconnexion programmatique
     * @param AuditLogger                 $auditLogger Service d'audit (loggué AVANT l'anonymisation)
     */
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
            // Les comptes OAuth purs (googleId/discordId sans password) ne peuvent pas fournir de MDP
            $plainPassword = $request->request->getString('password');
            if (null !== $user->getPassword()) {
                if (!$hasher->isPasswordValid($user, $plainPassword)) {
                    $this->addFlash('error', 'account.delete_password_wrong');

                    return $this->redirectToRoute('app_account_delete');
                }
            }

            // Audit AVANT l'anonymisation pour conserver l'identité réelle dans les logs
            $auditLogger->log('account.delete', $user, $request);

            // Anonymisation RGPD — les logs security_log référencent userId (INT) et non l'email,
            // l'intégrité référentielle est préservée même après suppression de l'identité
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

    /**
     * Génère un fichier JSON contenant toutes les données personnelles de l'utilisateur.
     *
     * L'export est conforme RGPD art. 20 (portabilité) : format structuré, lisible par machine.
     * Content-Disposition: attachment déclenche le téléchargement automatique dans le navigateur.
     *
     * Données incluses : minimales et suffisantes pour la portabilité. Les logs de sécurité
     * (SecurityLog) ne sont pas inclus — ils font partie des obligations légales du responsable
     * de traitement et ne sont pas "fournis par l'utilisateur" au sens RGPD.
     *
     * @param AuditLogger $auditLogger Service d'audit (export tracé pour conformité)
     * @param Request     $request     Requête courante (pour l'IP dans l'audit)
     */
    #[Route('/export', name: 'app_account_export', methods: ['GET'])]
    public function export(AuditLogger $auditLogger, Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();

        $auditLogger->log('account.data_export', $user, $request);

        // Reconstruit la liste des providers OAuth liés à ce compte
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
            // ISO 8601 (ATOM) pour l'interopérabilité des outils de traitement de données
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
