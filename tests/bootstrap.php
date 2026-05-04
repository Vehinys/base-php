<?php

/**
 * Point d'entrée PHPUnit — chargement de l'environnement avant les tests.
 *
 * bootEnv() vs loadEnv() :
 *   bootEnv() charge .env, puis .env.local, .env.test, .env.test.local dans l'ordre.
 *   Il définit aussi APP_ENV=test automatiquement si le paramètre n'est pas déjà défini.
 *   method_exists() garde une compatibilité avec les versions antérieures du composant Dotenv
 *   qui n'implémentaient pas bootEnv.
 *
 * umask(0000) :
 *   En mode debug (APP_DEBUG=true), les fichiers de cache créés par le kernel de test
 *   doivent être lisibles et éditables sans restriction de permissions.
 *   umask(0000) garantit que les fichiers créés pendant les tests ont les permissions 0777
 *   (avant que les permissions du répertoire parent s'appliquent).
 *   Cette ligne n'a d'effet qu'en mode debug — inoffensive en prod.
 */

declare(strict_types=1);

use Symfony\Component\Dotenv\Dotenv;

require dirname(__DIR__).'/vendor/autoload.php';

if (method_exists(Dotenv::class, 'bootEnv')) {
    (new Dotenv())->bootEnv(dirname(__DIR__).'/.env');
}

if ($_SERVER['APP_DEBUG']) {
    umask(0000);
}
