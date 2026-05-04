<?php

/**
 * Formulaire de saisie du nouveau mot de passe lors d'un reset.
 *
 * Affiché après le clic sur le lien de réinitialisation envoyé par e-mail.
 * Le token est validé en amont par PasswordResetController ; ce formulaire
 * ne collecte que le nouveau mot de passe (saisi deux fois pour confirmation).
 *
 * Les contraintes de complexité sont identiques à celles de l'inscription
 * (recommandations CNIL 2022) pour garantir une politique cohérente.
 */

declare(strict_types=1);

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Regex;

/**
 * Formulaire de réinitialisation du mot de passe (étape 2/2).
 *
 * Non lié à une entité (pas de data_class) — le contrôleur récupère
 * le plainPassword via $form->get('plainPassword')->getData() et le
 * hache avant de le persister.
 *
 * @extends AbstractType<array<string, mixed>>
 */
class ResetPasswordFormType extends AbstractType
{
    /**
     * Construit le formulaire avec les deux champs mot de passe.
     *
     * @param FormBuilderInterface $builder Constructeur de formulaire Symfony
     * @param array<string, mixed> $options Options du formulaire
     */
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        // RepeatedType valide que les deux champs sont identiques avant soumission
        // Symfony génère automatiquement plainPassword[first] et plainPassword[second]
        $builder->add('plainPassword', RepeatedType::class, [
            'type'            => PasswordType::class,
            'mapped'          => false,
            'first_options'   => [
                'label' => 'auth.new_password',
                // data-strength-input active l'indicateur de force JS (app.js)
                'attr'  => ['autocomplete' => 'new-password', 'data-strength-input' => ''],
            ],
            'second_options'  => [
                'label' => 'form.password_confirm',
                'attr'  => ['autocomplete' => 'new-password'],
            ],
            // Message si les deux saisies ne correspondent pas
            'invalid_message' => 'form.password_mismatch',
            'constraints'     => [
                new NotBlank(message: 'form.password_required'),
                // Minimum CNIL 2022 : 12 caractères / max 4096 = protection DoS argon2
                new Length(min: 12, max: 4096, minMessage: 'form.password_min'),
                // Exige au moins 1 minuscule, 1 majuscule, 1 chiffre (lookahead regex)
                new Regex(
                    pattern: '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/',
                    message: 'form.password_complexity'
                ),
            ],
        ]);
    }
}
