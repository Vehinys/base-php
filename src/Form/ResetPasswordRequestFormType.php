<?php

/**
 * Formulaire de demande de réinitialisation de mot de passe (étape 1/2).
 *
 * L'utilisateur saisit uniquement son adresse e-mail. Le contrôleur vérifie
 * si cette adresse est enregistrée et envoie un lien de reset par e-mail.
 *
 * Traitement intentionnellement silencieux : qu'un compte existe ou non,
 * le même message de confirmation est affiché (anti-énumération d'e-mails).
 */

declare(strict_types=1);

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\FormBuilderInterface;

/**
 * Formulaire de saisie de l'e-mail pour recevoir un lien de réinitialisation.
 *
 * Non lié à une entité — le contrôleur récupère l'e-mail via
 * $form->get('email')->getData() et interroge UserRepository.
 *
 * @extends AbstractType<array<string, mixed>>
 */
class ResetPasswordRequestFormType extends AbstractType
{
    /**
     * Construit le formulaire avec le champ e-mail.
     *
     * @param FormBuilderInterface $builder Constructeur de formulaire Symfony
     * @param array<string, mixed> $options Options du formulaire
     */
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder->add('email', EmailType::class, [
            'label' => 'form.email',
            // autocomplete: email aide les gestionnaires de mots de passe et les navigateurs
            'attr'  => ['autocomplete' => 'email'],
        ]);
    }
}
