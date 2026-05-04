<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20260504221825 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE security_log (id INT AUTO_INCREMENT NOT NULL, event VARCHAR(64) NOT NULL, user_id INT DEFAULT NULL, user_email VARCHAR(180) DEFAULT NULL, ip VARCHAR(45) DEFAULT NULL, extra JSON DEFAULT NULL, created_at DATETIME NOT NULL, INDEX idx_security_log_event (event), INDEX idx_security_log_user (user_id), INDEX idx_security_log_date (created_at), PRIMARY KEY (id)) DEFAULT CHARACTER SET utf8mb4');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('DROP TABLE security_log');
    }
}
