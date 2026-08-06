<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Plugins\I18n\Support\Lang;
use Plugins\I18n\Translator;

/**
 * The mail templates must actually render translated copy — the catalogue
 * existing is not the same as the view using it.
 *
 * These render the real template files against a real Translator rather than
 * asserting on the catalogue arrays. A view that still holds a hard-coded
 * English sentence, or that calls a key nobody defined, passes every catalogue
 * test and still ships English to a French recipient.
 */
#[CoversNothing]
final class MailViewLocalizationTest extends TestCase
{
    protected function tearDown(): void
    {
        Lang::clear();
    }

    /**
     * Bind a Translator wired the way the boot manifest wires this plugin.
     *
     * module.json declares the catalogue with "global": false, so the `auth`
     * NAMESPACE is the only route to these messages — registering the directory
     * as a global path instead would resolve nothing and every key would render
     * as itself.
     */
    private function bindLocale(string $locale): void
    {
        Lang::bind(new Translator(
            directory:  [],
            locale:     $locale,
            fallback:   'en',
            namespaces: ['auth' => [dirname(__DIR__) . '/resources/lang']],
        ));
    }

    /**
     * Render a template the way the view renderer does: extracted variables,
     * output buffered.
     *
     * @param array<string,mixed> $data
     */
    private function render(string $view, array $data): string
    {
        $file = dirname(__DIR__) . '/resources/views/' . $view . '.php';
        self::assertFileExists($file);

        extract($data, EXTR_SKIP);
        ob_start();
        include $file;

        return (string) ob_get_clean();
    }

    // --- OTP mail -------------------------------------------------------------

    public function test_otp_mail_renders_english(): void
    {
        $this->bindLocale('en');
        $html = $this->render('password-otp', ['otp' => '123456', 'expiresMinutes' => 10]);

        $this->assertStringContainsString('Password Reset Code', $html);
        $this->assertStringContainsString('123456', $html, 'the code itself must still render');
        $this->assertStringContainsString('lang="en"', $html);
    }

    public function test_otp_mail_renders_french(): void
    {
        $this->bindLocale('fr');
        $html = $this->render('password-otp', ['otp' => '123456', 'expiresMinutes' => 10]);

        $this->assertStringContainsString('Code de réinitialisation', $html);
        $this->assertStringNotContainsString('Password Reset Code', $html);
        $this->assertStringContainsString('123456', $html);
    }

    /** The document language has to follow the copy, not the template's original. */
    public function test_otp_mail_declares_the_active_language(): void
    {
        $this->bindLocale('fr');

        $this->assertStringContainsString('lang="fr"', $this->render(
            'password-otp',
            ['otp' => '1', 'expiresMinutes' => 5],
        ));
    }

    public function test_otp_expiry_pluralises_in_both_locales(): void
    {
        foreach (['en' => ['1 minute', '10 minutes'], 'fr' => ['1 minute', '10 minutes']] as $locale => $forms) {
            $this->bindLocale($locale);

            $singular = $this->render('password-otp', ['otp' => '1', 'expiresMinutes' => 1]);
            $plural   = $this->render('password-otp', ['otp' => '1', 'expiresMinutes' => 10]);

            $this->assertStringContainsString($forms[0], $singular, "[{$locale}] singular form");
            $this->assertStringContainsString($forms[1], $plural, "[{$locale}] plural form");
        }
    }

    // --- Password-changed mail ------------------------------------------------

    public function test_password_changed_mail_renders_french(): void
    {
        $this->bindLocale('fr');
        $html = $this->render('password-changed', [
            'email'     => 'user@example.com',
            'changedAt' => '2026-08-06 10:00',
            'ip'        => '203.0.113.7',
        ]);

        $this->assertStringContainsString('Votre mot de passe a été modifié', $html);
        $this->assertStringNotContainsString('Your password was changed', $html);
        $this->assertStringContainsString('Adresse IP', $html);
    }

    public function test_password_changed_mail_still_shows_the_incident_details(): void
    {
        // This mail is the account-takeover tripwire. Localising it must not
        // drop the facts the recipient needs to act on.
        $this->bindLocale('fr');
        $html = $this->render('password-changed', [
            'email'     => 'user@example.com',
            'changedAt' => '2026-08-06 10:00',
            'ip'        => '203.0.113.7',
        ]);

        $this->assertStringContainsString('user@example.com', $html);
        $this->assertStringContainsString('2026-08-06 10:00', $html);
        $this->assertStringContainsString('203.0.113.7', $html);
    }

    public function test_the_ip_row_is_omitted_when_unknown(): void
    {
        $this->bindLocale('fr');
        $html = $this->render('password-changed', [
            'email'     => 'user@example.com',
            'changedAt' => '2026-08-06 10:00',
            'ip'        => '',
        ]);

        $this->assertStringNotContainsString('Adresse IP', $html);
    }

    // --- No untranslated copy left --------------------------------------------

    /**
     * Catches the failure this whole exercise is about: a sentence left in
     * English inside a template that is otherwise translated.
     */
    public function test_no_english_copy_survives_in_the_french_render(): void
    {
        $this->bindLocale('fr');

        $otp = $this->render('password-otp', ['otp' => '1', 'expiresMinutes' => 5]);
        $chg = $this->render('password-changed', [
            'email' => 'a@b.c', 'changedAt' => 'now', 'ip' => '',
        ]);

        foreach ([
            'Use the code below',
            'you can safely ignore this email',
            'was just reset',
            'Someone else may have access',
            'contact support straight away',
        ] as $english) {
            $this->assertStringNotContainsString($english, $otp . $chg, "untranslated: {$english}");
        }
    }

    /**
     * A key with no catalogue entry renders as the key itself, which would ship
     * "auth::mail.otp.title" to a user. Assert no key-shaped text escapes.
     */
    public function test_no_raw_translation_keys_leak_into_the_output(): void
    {
        foreach (['en', 'fr'] as $locale) {
            $this->bindLocale($locale);

            $html = $this->render('password-otp', ['otp' => '1', 'expiresMinutes' => 5])
                . $this->render('password-changed', ['email' => 'a@b.c', 'changedAt' => 'now', 'ip' => '1.1.1.1']);

            $this->assertStringNotContainsString('auth::', $html, "[{$locale}] an unresolved key reached the output");
        }
    }
}
