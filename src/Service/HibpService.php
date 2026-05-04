<?php

/**
 * Service de vérification des mots de passe contre la base HaveIBeenPwned (HIBP).
 *
 * L'API HIBP Pwned Passwords utilise le modèle k-anonymat :
 *   1. Le mot de passe est haché en SHA-1 côté client
 *   2. Seuls les 5 premiers caractères hexadécimaux (prefix) sont envoyés à l'API
 *   3. L'API retourne toutes les entrées dont le hash commence par ce préfixe (~500 lignes)
 *   4. Le client compare le reste du hash (suffix, 35 chars) localement
 *
 * Ce protocole garantit que le mot de passe en clair ET son hash complet ne quittent
 * jamais le serveur. HIBP ne peut pas déduire quel mot de passe a été vérifié.
 *
 * En-tête Add-Padding: true :
 *   Demande à l'API de compléter la réponse à une taille fixe, masquant ainsi la
 *   taille réelle du résultat (qui pourrait révéler si le préfixe est très courant).
 *
 * Politique fail-open :
 *   Si HIBP est inaccessible (timeout, erreur réseau), isPwned() retourne false.
 *   Bloquer les inscriptions sur indisponibilité HIBP serait une erreur de conception :
 *   l'application dégagerait une dépendance dure sur un service tiers non critique.
 *
 * Timeout : 3 secondes — délai raisonnable pour une API publique externe.
 */

declare(strict_types=1);

namespace App\Service;

use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Vérifie si un mot de passe figure dans les bases de données de fuites connues (HIBP).
 *
 * Utilisé dans SecurityController::register() et PasswordResetController::reset()
 * après validation des contraintes de formulaire, avant le hashage argon2.
 */
class HibpService
{
    /**
     * @param HttpClientInterface $httpClient Client HTTP Symfony (injecté automatiquement)
     */
    public function __construct(private readonly HttpClientInterface $httpClient)
    {
    }

    /**
     * Vérifie si le mot de passe apparaît dans une base de données de fuites connues.
     *
     * Protocole k-anonymat HIBP :
     *   - Seuls les 5 premiers caractères du hash SHA-1 en majuscules sont transmis
     *   - La comparaison du suffix se fait localement, jamais côté serveur HIBP
     *
     * @param string $password Mot de passe en clair à vérifier (jamais loggué)
     *
     * @return bool true si le mot de passe est compromis, false sinon (ou si HIBP inaccessible)
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
                    // Add-Padding masque la taille de réponse pour renforcer k-anonymat
                    'headers' => ['Add-Padding' => 'true'],
                    'timeout' => 3.0,
                ]
            );

            // Chaque ligne de la réponse : "SUFFIX:COUNT\r\n"
            foreach (explode("\n", $response->getContent()) as $line) {
                $parts = explode(':', trim($line), 2);
                if (2 === \count($parts) && strtoupper($parts[0]) === $suffix) {
                    return (int) $parts[1] > 0;
                }
            }
        } catch (\Throwable) {
            // Fail-open — HIBP inaccessible ne bloque pas l'inscription
        }

        return false;
    }
}
