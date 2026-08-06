<?php

declare(strict_types=1);

/**
 * English copy for the Auth plugin's transactional emails.
 *
 * Reached as 'auth::mail.*'. The namespace matters: "mail" is a name several
 * plugins would plausibly use, and a plain 'mail.otp_title' would collide the
 * moment another plugin ships one.
 *
 * A project can reword any of these without forking the plugin by placing its
 * own file at {project-lang}/auth/{locale}/mail.php — only the keys it defines
 * are overridden, the rest still come from here.
 */
return [
    // --- Password reset code -------------------------------------------------
    'otp' => [
        'title'  => 'Password Reset Code',
        // trans_choice() supplies :count automatically and uses it to pick the
        // form. A different placeholder name would render literally.
        'intro'  => 'Use the code below to reset your password. It expires in :count minute.'
            . '|Use the code below to reset your password. It expires in :count minutes.',
        'ignore' => 'If you didn\'t request a password reset, you can safely ignore this email. '
            . 'Your password will not be changed.',
    ],

    // --- Password changed notification --------------------------------------
    // This mail is the account-takeover tripwire: if the reset was not the
    // account owner, it is the only signal they get. The wording states plainly
    // what happened, when, and what to do.
    'changed' => [
        'title'    => 'Your password was changed',
        'intro'    => 'The password for :email was just reset. You were signed out on every '
            . 'other device as a precaution.',
        'when'     => 'When',
        'from_ip'  => 'From IP',
        'not_you'  => 'Didn\'t do this?',
        'recovery' => 'Someone else may have access to your email inbox. Reset your password '
            . 'again immediately, then secure the email account itself. If you cannot '
            . 'sign in, contact support straight away.',
    ],
];
