<?php

/**
 * Entité principale représentant un utilisateur de l'application.
 *
 * Un utilisateur peut s'authentifier par trois moyens distincts :
 *   1. Email/mot de passe local (argon2 via Symfony PasswordHasher)
 *   2. OAuth Google (googleId + isVerified automatique)
 *   3. OAuth Discord (discordId + isVerified automatique)
 *
 * Les comptes locaux nécessitent une vérification de l'adresse e-mail
 * avant de pouvoir se connecter (champ isVerified + verificationToken).
 * Les comptes OAuth sont considérés vérifiés dès la première connexion,
 * car le fournisseur OAuth a déjà validé l'e-mail de l'utilisateur.
 */

declare(strict_types=1);

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Entité User — table `user` en base de données.
 *
 * Implémente UserInterface pour l'intégration avec le composant Security
 * de Symfony, et PasswordAuthenticatedUserInterface pour le hashage argon2.
 *
 * Contrainte d'unicité sur l'email : une seule entrée par adresse,
 * qu'il s'agisse d'un compte local ou OAuth.
 */
#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: '`user`')]
#[ORM\UniqueConstraint(name: 'UNIQ_IDENTIFIER_EMAIL', fields: ['email'])]
#[UniqueEntity(fields: ['email'], message: 'auth.email_already_used')]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    /** Identifiant auto-incrémenté — clé primaire. */
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    /** Adresse e-mail — sert aussi d'identifiant de connexion (getUserIdentifier). */
    #[ORM\Column(length: 180)]
    private string $email = '';

    /**
     * Rôles de l'utilisateur stockés en JSON.
     *
     * ROLE_USER est toujours ajouté dynamiquement par getRoles()
     * même s'il n'est pas explicitement présent dans le tableau persisté,
     * ce qui garantit qu'aucun utilisateur ne peut exister sans rôle de base.
     *
     * @var array<string>
     */
    #[ORM\Column]
    private array $roles = [];

    /**
     * Hash argon2 du mot de passe.
     *
     * Nullable car les comptes créés exclusivement via OAuth (Google ou Discord)
     * n'ont pas de mot de passe local — ils ne peuvent pas se connecter par e-mail.
     */
    #[ORM\Column(nullable: true)]
    private ?string $password = null;

    /** Nom d'affichage de l'utilisateur (prénom + nom ou pseudo). */
    #[ORM\Column(length: 100, nullable: true)]
    private ?string $name = null;

    /**
     * Identifiant unique fourni par Google lors de la connexion OAuth.
     * Utilisé comme clé de lookup prioritaire dans GoogleAuthenticator.
     */
    #[ORM\Column(length: 255, nullable: true)]
    private ?string $googleId = null;

    /**
     * Identifiant unique fourni par Discord lors de la connexion OAuth.
     * Utilisé comme clé de lookup prioritaire dans DiscordAuthenticator.
     */
    #[ORM\Column(length: 255, nullable: true)]
    private ?string $discordId = null;

    /** URL de l'avatar — fourni par Google/Discord, null si aucun avatar configuré. */
    #[ORM\Column(length: 255, nullable: true)]
    private ?string $avatarUrl = null;

    /**
     * Indique si l'adresse e-mail a été vérifiée.
     *
     * - false par défaut à l'inscription locale → UserChecker bloque la connexion
     * - passé à true lors du clic sur le lien de vérification e-mail
     * - forcé à true dès la première connexion OAuth (le fournisseur garantit l'e-mail)
     */
    #[ORM\Column]
    private bool $isVerified = false;

    /**
     * Token de vérification de l'adresse e-mail.
     *
     * Généré lors de l'inscription (bin2hex(random_bytes(32)) → 64 hex chars).
     * Envoyé par e-mail sous forme de lien. Effacé (null) dès la vérification
     * pour rendre le lien inutilisable une seconde fois (usage unique).
     */
    #[ORM\Column(length: 64, nullable: true)]
    private ?string $verificationToken = null;

    /**
     * Token de réinitialisation du mot de passe.
     *
     * Généré lors d'une demande de reset (bin2hex(random_bytes(32))).
     * Associé à resetTokenExpiresAt pour une expiration à 1 heure.
     * Effacé après utilisation ou à l'expiration.
     */
    #[ORM\Column(length: 64, nullable: true)]
    private ?string $resetToken = null;

    /**
     * Date d'expiration du token de réinitialisation.
     *
     * Fixée à +1 heure lors de la génération du token.
     * Vérifiée par PasswordResetController avant d'accepter un nouveau mot de passe.
     */
    #[ORM\Column(type: Types::DATETIME_MUTABLE, nullable: true)]
    private ?\DateTimeInterface $resetTokenExpiresAt = null;

    /** Date de création du compte — définie automatiquement dans le constructeur. */
    #[ORM\Column(type: Types::DATETIME_MUTABLE)]
    private \DateTimeInterface $createdAt;

    /**
     * Initialise la date de création au moment de l'instanciation.
     *
     * Doctrine n'appelle pas le constructeur lors d'une hydratation depuis la BDD,
     * donc createdAt sera null pour les entités chargées — ce qui est attendu
     * car la valeur persistée sera utilisée directement.
     */
    public function __construct()
    {
        $this->createdAt = new \DateTime();
    }

    /** Retourne l'identifiant technique auto-incrémenté, null avant la persistance. */
    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;

        return $this;
    }

    /**
     * Identifiant utilisé par Symfony Security pour identifier l'utilisateur.
     *
     * L'e-mail est choisi comme identifiant car il est unique et lisible.
     * Il est stocké dans le token de session et utilisé pour le "remember me".
     */
    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    /**
     * Retourne les rôles de l'utilisateur.
     *
     * ROLE_USER est toujours ajouté même s'il n'est pas stocké en base,
     * garantissant qu'un utilisateur valide a toujours au minimum ce rôle.
     * array_unique évite les doublons si ROLE_USER était aussi explicitement persisté.
     *
     * @return array<string>
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        $roles[] = 'ROLE_USER';

        return array_unique($roles);
    }

    /** @param array<string> $roles */
    public function setRoles(array $roles): static
    {
        $this->roles = $roles;

        return $this;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function setPassword(?string $password): static
    {
        $this->password = $password;

        return $this;
    }

    /**
     * Efface les données sensibles temporaires de l'entité.
     *
     * Appelé automatiquement par Symfony après l'authentification.
     * Le plainPassword n'étant pas stocké dans l'entité (mapped: false dans le form),
     * cette méthode n'a rien à effacer — elle est présente pour respecter l'interface.
     */
    public function eraseCredentials(): void
    {
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(?string $name): static
    {
        $this->name = $name;

        return $this;
    }

    public function getGoogleId(): ?string
    {
        return $this->googleId;
    }

    public function setGoogleId(?string $googleId): static
    {
        $this->googleId = $googleId;

        return $this;
    }

    public function getDiscordId(): ?string
    {
        return $this->discordId;
    }

    public function setDiscordId(?string $discordId): static
    {
        $this->discordId = $discordId;

        return $this;
    }

    public function getAvatarUrl(): ?string
    {
        return $this->avatarUrl;
    }

    public function setAvatarUrl(?string $avatarUrl): static
    {
        $this->avatarUrl = $avatarUrl;

        return $this;
    }

    public function isVerified(): bool
    {
        return $this->isVerified;
    }

    public function setIsVerified(bool $isVerified): static
    {
        $this->isVerified = $isVerified;

        return $this;
    }

    public function getVerificationToken(): ?string
    {
        return $this->verificationToken;
    }

    public function setVerificationToken(?string $verificationToken): static
    {
        $this->verificationToken = $verificationToken;

        return $this;
    }

    public function getResetToken(): ?string
    {
        return $this->resetToken;
    }

    public function setResetToken(?string $resetToken): static
    {
        $this->resetToken = $resetToken;

        return $this;
    }

    public function getResetTokenExpiresAt(): ?\DateTimeInterface
    {
        return $this->resetTokenExpiresAt;
    }

    public function setResetTokenExpiresAt(?\DateTimeInterface $resetTokenExpiresAt): static
    {
        $this->resetTokenExpiresAt = $resetTokenExpiresAt;

        return $this;
    }

    public function getCreatedAt(): \DateTimeInterface
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeInterface $createdAt): static
    {
        $this->createdAt = $createdAt;

        return $this;
    }
}
