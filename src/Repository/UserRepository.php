<?php

/**
 * Repository Doctrine pour l'entité User.
 *
 * Étend ServiceEntityRepository (Doctrine Bundle) qui fournit les méthodes
 * de base : find(), findAll(), findBy(), findOneBy(), count().
 *
 * Implémente PasswordUpgraderInterface pour permettre à Symfony de migrer
 * automatiquement les hashs vers un algorithme plus récent quand l'utilisateur
 * se connecte (si le coût argon2 a été augmenté par exemple).
 */

declare(strict_types=1);

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;

/**
 * Repository de l'entité User.
 *
 * Pour ajouter des requêtes métier personnalisées, déclarez des méthodes
 * supplémentaires ici. Exemple :
 *
 *     public function findActiveAdmins(): array
 *     {
 *         return $this->createQueryBuilder('u')
 *             ->where('u.roles LIKE :role')
 *             ->andWhere('u.isVerified = true')
 *             ->setParameter('role', '%ROLE_ADMIN%')
 *             ->getQuery()
 *             ->getResult();
 *     }
 *
 * @extends ServiceEntityRepository<User>
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    /**
     * @param ManagerRegistry $registry Registre Doctrine — injecté automatiquement par le DI
     */
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    /**
     * Met à niveau le hash du mot de passe après une connexion réussie.
     *
     * Appelé automatiquement par Symfony Security si le hash existant
     * est considéré "outdated" (ex. coût argon2 insuffisant).
     * Permet de migrer progressivement les hashs sans forcer les utilisateurs
     * à changer leur mot de passe.
     *
     * @param PasswordAuthenticatedUserInterface $user            L'utilisateur dont le hash doit être mis à jour
     * @param string                             $newHashedPassword Le nouveau hash généré par Symfony
     *
     * @throws UnsupportedUserException Si l'entité n'est pas une instance de User
     */
    public function upgradePassword(PasswordAuthenticatedUserInterface $user, string $newHashedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(\sprintf('Instances of "%s" are not supported.', $user::class));
        }

        $user->setPassword($newHashedPassword);
        $this->getEntityManager()->persist($user);
        $this->getEntityManager()->flush();
    }
}
