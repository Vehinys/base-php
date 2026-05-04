<?php

/**
 * Entité de journalisation des événements de sécurité.
 *
 * Chaque entrée représente une action sensible tracée par AuditLogger :
 * connexion réussie/échouée, déconnexion, inscription, vérification e-mail,
 * demande/completion de reset, suppression de compte, export de données.
 *
 * Conception intentionnelle :
 *   - userId et userEmail sont stockés directement (pas de FK vers User)
 *     pour conserver l'historique même après anonymisation/suppression du compte.
 *   - extra (JSON) permet d'ajouter des métadonnées spécifiques à chaque événement
 *     sans avoir à modifier le schéma (ex. provider OAuth, email tenté).
 *   - Les index sur event, user_id et created_at permettent des requêtes
 *     efficaces pour l'audit et les dashboards de sécurité.
 */

declare(strict_types=1);

namespace App\Entity;

use App\Repository\SecurityLogRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

/**
 * Enregistre un événement de sécurité dans la table security_log.
 *
 * Immutable par convention une fois persisté — ne pas modifier une entrée existante,
 * créer une nouvelle entrée si une correction est nécessaire.
 */
#[ORM\Entity(repositoryClass: SecurityLogRepository::class)]
#[ORM\Index(columns: ['event'], name: 'idx_security_log_event')]
#[ORM\Index(columns: ['user_id'], name: 'idx_security_log_user')]
#[ORM\Index(columns: ['created_at'], name: 'idx_security_log_date')]
class SecurityLog
{
    /** Identifiant auto-incrémenté de l'entrée de log. */
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    /**
     * Identifiant de l'événement — convention snake_case.
     *
     * Exemples : login.success, login.failure, logout, registration,
     * email.verified, password_reset.requested, password_reset.completed,
     * account.delete, account.data_export.
     */
    #[ORM\Column(length: 64)]
    private string $event = '';

    /**
     * ID de l'utilisateur concerné au moment de l'événement.
     *
     * Nullable car certains événements (login.failure sur compte inexistant)
     * n'ont pas d'utilisateur associé. Intentionnellement pas une FK
     * pour survivre à la suppression/anonymisation du compte.
     */
    #[ORM\Column(nullable: true)]
    private ?int $userId = null;

    /**
     * E-mail de l'utilisateur au moment de l'événement.
     *
     * Copié directement (dénormalisé) pour rester lisible dans les logs
     * même après anonymisation du compte (userId resterait mais email
     * deviendrait deleted_N@deleted.invalid).
     */
    #[ORM\Column(length: 180, nullable: true)]
    private ?string $userEmail = null;

    /**
     * Adresse IP du client au moment de l'événement.
     *
     * Stockée pour la détection d'anomalies (ex. connexions depuis plusieurs
     * pays simultanément). VARCHAR(45) supporte IPv6 (max 39 chars).
     */
    #[ORM\Column(length: 45, nullable: true)]
    private ?string $ip = null;

    /**
     * Données contextuelles spécifiques à l'événement.
     *
     * Structure libre en JSON — exemples :
     *   - login.success : {"provider": "google"}
     *   - login.failure : {"attempted_email": "foo@bar.com", "reason": "Bad credentials."}
     *   - password_reset.requested : {}
     *
     * @var array<string, mixed>|null
     */
    #[ORM\Column(type: Types::JSON, nullable: true)]
    private ?array $extra = null;

    /**
     * Horodatage de création — immutable, défini dans le constructeur.
     *
     * Utilise DateTimeImmutable pour empêcher toute modification accidentelle.
     */
    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private \DateTimeImmutable $createdAt;

    /**
     * Définit la date de création à l'instant de l'instanciation.
     */
    public function __construct()
    {
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEvent(): string
    {
        return $this->event;
    }

    public function setEvent(string $event): static
    {
        $this->event = $event;

        return $this;
    }

    public function getUserId(): ?int
    {
        return $this->userId;
    }

    public function setUserId(?int $userId): static
    {
        $this->userId = $userId;

        return $this;
    }

    public function getUserEmail(): ?string
    {
        return $this->userEmail;
    }

    public function setUserEmail(?string $userEmail): static
    {
        $this->userEmail = $userEmail;

        return $this;
    }

    public function getIp(): ?string
    {
        return $this->ip;
    }

    public function setIp(?string $ip): static
    {
        $this->ip = $ip;

        return $this;
    }

    /** @return array<string, mixed>|null */
    public function getExtra(): ?array
    {
        return $this->extra;
    }

    /** @param array<string, mixed>|null $extra */
    public function setExtra(?array $extra): static
    {
        $this->extra = $extra;

        return $this;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }
}
