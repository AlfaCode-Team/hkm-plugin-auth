<?php
/**
 * OTP password-reset email (ported from the old __DEV__ flow, brand-neutral).
 * Data: string $otp, int $expiresMinutes
 *
 * Copy lives in resources/lang/{locale}/mail.php and is reached as
 * 'auth::mail.otp.*'. The namespace keeps it from colliding with any other
 * plugin's "mail" group, and lets a project reword it without forking.
 */
$otp = htmlspecialchars((string) ($otp ?? ''), ENT_QUOTES, 'UTF-8');
$expiresMinutes = (int) ($expiresMinutes ?? 10);

// The document language must follow the copy. A French email declaring
// lang="en" makes screen readers pronounce it with English phonetics.
$lang = htmlspecialchars(lang_locale(), ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:20px;background:#f6f7f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(17,24,39,.08);">
    <div style="padding:32px 28px;">
      <h2 style="margin:0 0 8px;font-size:20px;color:#111827;font-weight:700;"><?= esc(trans('auth::mail.otp.title')) ?></h2>
      <p style="color:#6B7280;margin:0 0 28px;font-size:15px;line-height:1.5;">
        <?= esc(trans_choice('auth::mail.otp.intro', $expiresMinutes)) ?>
      </p>
      <div style="background:#f3f4f6;border-radius:12px;padding:24px;text-align:center;margin-bottom:28px;">
        <span style="font-size:40px;font-weight:800;letter-spacing:12px;color:#111827;font-variant-numeric:tabular-nums;"><?= $otp ?></span>
      </div>
      <p style="color:#9CA3AF;font-size:13px;margin:0;line-height:1.6;">
        <?= esc(trans('auth::mail.otp.ignore')) ?>
      </p>
    </div>
  </div>
</body>
</html>
