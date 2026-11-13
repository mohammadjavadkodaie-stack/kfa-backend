import type { EmailCodePurpose, EmailNoticeKind } from './email.provider';

export type EmailLocale = 'en' | 'fa' | 'tr' | 'ar';

export interface EmailContent {
  readonly subject: string;
  readonly text: string;
}

const PERSIAN_DIGITS = '۰۱۲۳۴۵۶۷۸۹';

/** Renders a latin number with Persian digits, matching the rest of the `fa` copy. */
function toPersianDigits(value: number): string {
  return String(value).replace(/[0-9]/gu, (digit) => PERSIAN_DIGITS[Number(digit)] ?? digit);
}

const labels: Record<
  EmailLocale,
  { code: string; validity: (minutes: number) => string; ignore: string }
> = {
  en: {
    code: 'Your verification code',
    validity: (minutes) => `This code is valid for ${minutes} minutes.`,
    ignore: "If you didn't request this, please ignore this message.",
  },
  fa: {
    code: 'کد تأیید شما',
    validity: (minutes) => `این کد به مدت ${toPersianDigits(minutes)} دقیقه معتبر است.`,
    ignore: 'اگر شما این درخواست را نداده‌اید، این پیام را نادیده بگیرید.',
  },
  tr: {
    code: 'Doğrulama kodunuz',
    validity: (minutes) => `Bu kod ${minutes} dakika geçerlidir.`,
    ignore: 'Bu isteği siz yapmadıysanız bu mesajı yok sayın.',
  },
  ar: {
    code: 'رمز التحقق الخاص بك',
    validity: (minutes) => `هذا الرمز صالح لمدة ${minutes} دقائق.`,
    ignore: 'إذا لم تطلب ذلك، فتجاهل هذه الرسالة.',
  },
};

const codeNames: Record<EmailLocale, Record<EmailCodePurpose, string>> = {
  en: {
    register: 'Create your KFA account',
    login_device: 'Confirm this new device',
    password_reset: 'Reset your KFA password',
    email_change_new: 'Confirm your new email',
    email_change_old: 'Confirm your email change',
  },
  fa: {
    register: 'ساخت حساب KFA',
    login_device: 'تأیید دستگاه جدید',
    password_reset: 'بازنشانی رمز عبور KFA',
    email_change_new: 'تأیید ایمیل جدید',
    email_change_old: 'تأیید تغییر ایمیل',
  },
  tr: {
    register: 'Hesabınızı oluşturun',
    login_device: 'Yeni cihazı doğrulayın',
    password_reset: 'KFA şifrenizi sıfırlayın',
    email_change_new: 'Yeni e-postanızı doğrulayın',
    email_change_old: 'E-posta değişikliğini doğrulayın',
  },
  ar: {
    register: 'أنشئ حساب KFA',
    login_device: 'تحقق من الجهاز الجديد',
    password_reset: 'إعادة تعيين كلمة مرور KFA',
    email_change_new: 'تأكيد بريدك الإلكتروني الجديد',
    email_change_old: 'تأكيد تغيير البريد الإلكتروني',
  },
};

const noticeNames: Record<EmailLocale, Record<EmailNoticeKind, string>> = {
  en: {
    password_changed: 'Your password was changed',
    email_changed: 'Your email was changed',
    new_device_login: 'A new device signed in',
    admin_granted: 'Administrator access was granted',
  },
  fa: {
    password_changed: 'رمز عبور شما تغییر کرد',
    email_changed: 'ایمیل شما تغییر کرد',
    new_device_login: 'ورود از دستگاه جدید',
    admin_granted: 'دسترسی مدیر اعطا شد',
  },
  tr: {
    password_changed: 'Şifreniz değiştirildi',
    email_changed: 'E-postanız değiştirildi',
    new_device_login: 'Yeni bir cihaz giriş yaptı',
    admin_granted: 'Yönetici erişimi verildi',
  },
  ar: {
    password_changed: 'تم تغيير كلمة المرور',
    email_changed: 'تم تغيير البريد الإلكتروني',
    new_device_login: 'تم تسجيل الدخول من جهاز جديد',
    admin_granted: 'تم منح صلاحية المدير',
  },
};

export function buildCodeEmail(
  purpose: EmailCodePurpose,
  code: string,
  locale: EmailLocale = 'en',
  ttlSeconds = 600,
): EmailContent {
  const language = labels[locale];
  const minutes = Math.max(1, Math.round(ttlSeconds / 60));
  const validity = language.validity(minutes);
  const title = codeNames[locale][purpose];
  return {
    subject: title,
    text: `${title}\n\n${language.code}: ${code}\n\n${validity}\n${language.ignore}`,
  };
}

export function buildNoticeEmail(kind: EmailNoticeKind, locale: EmailLocale = 'en'): EmailContent {
  const title = noticeNames[locale][kind];
  const action = {
    en: 'If this was not you, secure your account and contact support.',
    fa: 'اگر این کار توسط شما انجام نشده است، حساب خود را ایمن کرده و با پشتیبانی تماس بگیرید.',
    tr: 'Bu işlemi siz yapmadıysanız hesabınızı güvene alın ve destek ekibiyle iletişime geçin.',
    ar: 'إذا لم تكن أنت، أمّن حسابك وتواصل مع الدعم.',
  }[locale];
  return { subject: title, text: `${title}\n\n${action}` };
}

export function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/gu,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character] ??
      character,
  );
}
