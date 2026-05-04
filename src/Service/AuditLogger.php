<?php

declare(strict_types=1);

namespace App\Service;

use App\Entity\SecurityLog;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Request;

class AuditLogger
{
    public function __construct(
        private readonly EntityManagerInterface $em,
        #[Autowire(service: 'monolog.logger.security')]
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @param array<string, mixed> $extra
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
            $this->logger->error('audit_log.db_failure', ['exception' => $e->getMessage(), 'event' => $event]);
        }

        $this->logger->info($event, array_filter([
            'user_id' => $user?->getId(),
            'email' => $user?->getEmail(),
            'ip' => $request->getClientIp(),
            ...$extra,
        ]));
    }
}
