<?php

declare(strict_types=1);

namespace App\Service;

use Symfony\Contracts\HttpClient\HttpClientInterface;

class HibpService
{
    public function __construct(private readonly HttpClientInterface $httpClient)
    {
    }

    /**
     * Vérifie si le mot de passe apparaît dans une base de données de fuites connues.
     * Utilise l'API HIBP k-anonymat : seuls les 5 premiers caractères du hash SHA-1 sont envoyés.
     * Fail-open : retourne false en cas d'erreur réseau pour ne pas bloquer l'inscription.
     */
    public function isPwned(string $password): bool
    {
        $hash = strtoupper(sha1($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        try {
            $response = $this->httpClient->request(
                'GET',
                'https://api.pwnedpasswords.com/range/'.$prefix,
                [
                    'headers' => ['Add-Padding' => 'true'],
                    'timeout' => 3.0,
                ]
            );

            foreach (explode("\n", $response->getContent()) as $line) {
                $parts = explode(':', trim($line), 2);
                if (2 === \count($parts) && strtoupper($parts[0]) === $suffix) {
                    return (int) $parts[1] > 0;
                }
            }
        } catch (\Throwable) {
            // Fail open — HIBP inaccessible ne bloque pas l'inscription
        }

        return false;
    }
}
