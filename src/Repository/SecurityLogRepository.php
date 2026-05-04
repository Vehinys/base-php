<?php

/**
 * Repository Doctrine pour l'entité SecurityLog.
 *
 * Fournit les méthodes de base pour requêter la table security_log.
 * Pour des requêtes d'audit avancées (ex. statistiques de connexions par IP,
 * détection d'anomalies), ajouter des méthodes personnalisées ici.
 *
 * Exemples de méthodes utiles à implémenter pour un admin dashboard :
 *
 *   - findRecentByUser(int $userId, int $limit): array
 *   - countFailedLoginsLastHour(string $ip): int
 *   - findByEvent(string $event, \DateTimeInterface $since): array
 */

declare(strict_types=1);

namespace App\Repository;

use App\Entity\SecurityLog;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * Repository de l'entité SecurityLog.
 *
 * @extends ServiceEntityRepository<SecurityLog>
 */
class SecurityLogRepository extends ServiceEntityRepository
{
    /**
     * @param ManagerRegistry $registry Registre Doctrine — injecté automatiquement par le DI
     */
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, SecurityLog::class);
    }
}
