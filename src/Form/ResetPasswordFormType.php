<?php

declare(strict_types=1);

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

/**
 * @extends AbstractType<array<string, mixed>>
 */
class ResetPasswordFormType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        // RepeatedType valide que les deux champs sont identiques avant de soumettre
        $builder->add('plainPassword', RepeatedType::class, [
            'type' => PasswordType::class,
            'mapped' => false,
            'first_options' => [
                'label' => 'auth.new_password',
                'attr' => ['autocomplete' => 'new-password'],
            ],
            'second_options' => [
                'label' => 'form.password_confirm',
                'attr' => ['autocomplete' => 'new-password'],
            ],
            'invalid_message' => 'form.password_mismatch',
            'constraints' => [
                new NotBlank(message: 'form.password_required'),
                new Length(min: 8, max: 4096, minMessage: 'form.password_min'),
            ],
        ]);
    }
}
