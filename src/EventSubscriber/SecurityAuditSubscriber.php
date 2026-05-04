<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use App\Entity\User;
use App\Service\AuditLogger;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class SecurityAuditSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly AuditLogger $auditLogger)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
            LoginFailureEvent::class => 'onLoginFailure',
            LogoutEvent::class => 'onLogout',
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getAuthenticatedToken()->getUser();
        $authenticatorClass = \get_class($event->getAuthenticator());
        $provider = $this->resolveProvider($authenticatorClass);

        $this->auditLogger->log(
            'login.success',
            $user instanceof User ? $user : null,
            $event->getRequest(),
            ['provider' => $provider]
        );
    }

    public function onLoginFailure(LoginFailureEvent $event): void
    {
        $email = $event->getRequest()->getPayload()->getString('email', '');

        $this->auditLogger->log(
            'login.failure',
            null,
            $event->getRequest(),
            array_filter([
                'attempted_email' => $email ?: null,
                'reason' => $event->getException()->getMessageKey(),
            ])
        );
    }

    public function onLogout(LogoutEvent $event): void
    {
        $token = $event->getToken();
        $user = $token?->getUser();

        $this->auditLogger->log(
            'logout',
            $user instanceof User ? $user : null,
            $event->getRequest()
        );
    }

    private function resolveProvider(string $class): string
    {
        return match (true) {
            str_contains($class, 'Google') => 'google',
            str_contains($class, 'Discord') => 'discord',
            default => 'email',
        };
    }
}
