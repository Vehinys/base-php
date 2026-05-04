<?php

/**
 * Point d'entrée du noyau Symfony.
 *
 * MicroKernelTrait fournit la logique de boot minimale :
 *   - chargement automatique des bundles depuis config/bundles.php
 *   - import des fichiers de configuration depuis config/packages/
 *   - découverte des routes depuis config/routes/ et les attributs PHP
 *
 * Ce fichier ne doit pas être modifié sauf pour ajouter un bundle non
 * auto-détectable ou une configuration de boot très spécifique.
 */

declare(strict_types=1);

namespace App;

use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\HttpKernel\Kernel as BaseKernel;

/**
 * Noyau principal de l'application BaseApp.
 *
 * Hérite de BaseKernel (Symfony) et utilise MicroKernelTrait pour
 * limiter le boilerplate tout en conservant toutes les fonctionnalités
 * du framework (DI, routing, events, cache, etc.).
 */
class Kernel extends BaseKernel
{
    use MicroKernelTrait;
}
