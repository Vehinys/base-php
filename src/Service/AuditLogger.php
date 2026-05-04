<?php

/**
 * Service centralisé de journalisation des événements de sécurité.
 *
 * Chaque événement est enregistré sur deux canaux simultanément :
 *   1. Base de données (entité SecurityLog) — pour consultation et alertes internes
 *   2. Canal Monolog "security" — pour agrégation dans des outils externes (ELK, Loki, etc.)
 *
 * Design fail-safe :
 *   Si la persistance Doctrine échoue (ex. DB indisponible), l'exception est capturée
 *   et une erreur est loggée sur le canal Monolog, mais le flux applicatif principal
 *   n'est pas interrompu. L'événement reste traçable dans les logs même sans DB.
 *
 * Injection du logger "security" :
 *   #[Autowire(service: 'monolog.logger.security')] est nécessaire car Symfony injecte
 *   le logger du canal par défaut ("app") sans cet attribut. Le canal "security" est
 *   déclaré dans config/packages/monolog.yaml et redirige vers security.log (dev)
 *   ou php://stderr en JSON (prod).
 */

declare(strict_types=1);

namespace App\Service;

use App\Entity\SecurityLog;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Request;

/**
 * Persiste et loggue les événements de sécurité (connexions, échecs, suppressions, exports).
 *
 * Utilisé par SecurityAuditSubscriber (automatique sur les événements Symfony Security)
 * et directement dans les contrôleurs pour les événements métier (inscription, reset).
 */
class AuditLogger
{
    /**
     * @param EntityManagerInterface $em     Entity Manager Doctrine pour persister SecurityLog
     * @param LoggerInterface        $logger Logger du canal "security" (Monolog), injecté par nom de service
     */
    public function __construct(
        private readonly EntityManagerInterface $em,
        #[Autowire(service: 'monolog.logger.security')]
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * Enregistre un événement de sécurité en base et dans les logs Monolog.
     *
     * Ordre des opérations :
     *   1. Construction de l'entité SecurityLog avec toutes les métadonnées
     *   2. Tentative de persistance Doctrine (wrappée dans try/catch fail-safe)
     *   3. Écriture dans le canal Monolog "security" quel que soit le résultat de l'étape 2
     *
     * @param string               $event   Identifiant de l'événement (ex. 'login.success', 'account.delete')
     * @param User|null            $user    Utilisateur concerné (null pour les échecs anonymes)
     * @param Request              $request Requête courante (pour l'IP client)
     * @param array<string, mixed> $extra   Métadonnées supplémentaires (provider, raison, etc.)
     */
    public function log(string $event, ?User $user, Request $request, array $extra = []): void
    {
        $log = (new SecurityLog())
            ->setEvent($event)
            ->setUserId($user?->getId())
            ->setUserEmail($user?->getEmail())
            ->setIp($request->getClientIp())
            ->setExtra($extra ?: null);

        try {
            $this->em->persist($log);
            $this->em->flush();
        } catch (\Throwable $e) {
            // La DB est indisponible — on log l'erreur mais on ne propage pas l'exception
            // pour ne pas casser le flux applicatif principal (ex. connexion OAuth en cours)
            $this->logger->error('audit_log.db_failure', ['exception' => $e->getMessage(), 'event' => $event]);
        }

        // Écriture Monolog : toujours exécutée, même si la DB a échoué
        $this->logger->info($event, array_filter([
            'user_id' => $user?->getId(),
            'email' => $user?->getEmail(),
            'ip' => $request->getClientIp(),
            ...$extra,
        ]));
    }
}
