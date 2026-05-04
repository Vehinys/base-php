<?php

/**
 * Formulaire d'inscription d'un nouvel utilisateur.
 *
 * Collecte les informations nécessaires à la création d'un compte local :
 * nom complet, adresse e-mail, mot de passe (saisi deux fois) et
 * acceptation des conditions générales d'utilisation.
 *
 * Politique de mot de passe conforme aux recommandations CNIL 2022 :
 *   - 12 caractères minimum
 *   - Au moins une majuscule, une minuscule ET un chiffre (3 types sur 4)
 *   - Max 4096 chars pour prévenir les attaques par mots de passe très longs
 *   - Vérifié contre la base HIBP (Have I Been Pwned) dans SecurityController
 */

declare(strict_types=1);

namespace App\Form;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\IsTrue;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Regex;

/**
 * Formulaire Symfony pour la création d'un compte utilisateur.
 *
 * Lié à l'entité User via data_class — les champs name et email sont
 * mappés directement sur l'entité. Le mot de passe (plainPassword) est
 * `mapped: false` car il ne doit jamais être stocké en clair ; c'est
 * SecurityController qui le hache et l'assigne à user.password.
 *
 * @extends AbstractType<User>
 */
class RegistrationFormType extends AbstractType
{
    /**
     * Construit la structure du formulaire d'inscription.
     *
     * @param FormBuilderInterface $builder Constructeur de formulaire Symfony
     * @param array<string, mixed> $options Options du formulaire (data_class, etc.)
     */
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            // Nom complet — mappé sur User::name
            ->add('name', TextType::class, [
                'label' => 'form.name',
            ])

            // E-mail — mappé sur User::email, validé aussi par UniqueEntity sur l'entité
            ->add('email', EmailType::class, [
                'label' => 'form.email',
            ])

            // Mot de passe — RepeatedType génère deux champs identiques validés par Symfony
            // mapped: false → le hash argon2 est assigné manuellement dans SecurityController
            ->add('plainPassword', RepeatedType::class, [
                'type'            => PasswordType::class,
                'mapped'          => false,
                'first_options'   => [
                    'label' => 'form.password',
                    // data-strength-input déclenche l'indicateur de force JS (app.js)
                    'attr'  => ['autocomplete' => 'new-password', 'data-strength-input' => ''],
                ],
                'second_options'  => [
                    'label' => 'form.password_confirm',
                    'attr'  => ['autocomplete' => 'new-password'],
                ],
                // Message affiché si les deux champs ne correspondent pas
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
            ])

            // Case CGU — mapped: false, validation IsTrue = obligatoire à cocher
            ->add('agreeTerms', CheckboxType::class, [
                'label'       => 'form.agree_terms',
                'mapped'      => false,
                'constraints' => [new IsTrue(message: 'form.agree_terms_required')],
            ]);
    }

    /**
     * Configure les options par défaut du formulaire.
     *
     * data_class lie le formulaire à l'entité User :
     * à la soumission valide, Symfony hydrate automatiquement l'entité
     * avec les valeurs des champs mappés (name, email).
     *
     * @param OptionsResolver $resolver Résolveur d'options Symfony
     */
    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults(['data_class' => User::class]);
    }
}
