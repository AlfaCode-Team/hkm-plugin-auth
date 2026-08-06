<?php

declare(strict_types=1);

/**
 * French copy for the Auth plugin's transactional emails.
 *
 * Security wording is translated for meaning, not word-for-word: this mail is
 * the only signal an account owner gets if someone else reset their password,
 * so the French must be as direct and unambiguous as the English. Softening it
 * into more idiomatic-but-vaguer phrasing would cost the reader the urgency.
 */
return [
    // --- Code de réinitialisation -------------------------------------------
    'otp' => [
        'title'  => 'Code de réinitialisation du mot de passe',
        // French pluralises like English here: 1 → singular, everything else
        // plural. (French also treats 0 as singular, but an expiry of 0 minutes
        // is not a state this mail is ever sent in.)
        'intro'  => 'Utilisez le code ci-dessous pour réinitialiser votre mot de passe. '
            . 'Il expire dans :count minute.'
            . '|Utilisez le code ci-dessous pour réinitialiser votre mot de passe. '
            . 'Il expire dans :count minutes.',
        'ignore' => 'Si vous n\'avez pas demandé de réinitialisation, vous pouvez ignorer cet '
            . 'e-mail sans risque. Votre mot de passe ne sera pas modifié.',
    ],

    // --- Notification de changement -----------------------------------------
    'changed' => [
        'title'    => 'Votre mot de passe a été modifié',
        'intro'    => 'Le mot de passe de :email vient d\'être réinitialisé. Vous avez été '
            . 'déconnecté de tous les autres appareils par précaution.',
        'when'     => 'Date',
        'from_ip'  => 'Adresse IP',
        'not_you'  => 'Vous n\'êtes pas à l\'origine de cette action ?',
        'recovery' => 'Quelqu\'un a peut-être accès à votre boîte e-mail. Réinitialisez '
            . 'immédiatement votre mot de passe, puis sécurisez le compte e-mail '
            . 'lui-même. Si vous ne parvenez pas à vous connecter, contactez le '
            . 'support sans attendre.',
    ],
];
