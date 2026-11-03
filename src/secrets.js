// SPDX-License-Identifier: AGPL-3.0-only
// Шифрование секрета TOTP в базе (AES-256-GCM) и запасные коды.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

const keyFrom = (secret) => createHash('sha256').update('dvauth-totp-v1\0' + secret).digest();

// Формат: v1.<iv>.<тег>.<шифртекст>, всё в base64url.
export function encryptSecret(plain, secret) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', keyFrom(secret), iv);
  const enc = Buffer.concat([c.update(plain), c.final()]);
  return ['v1', iv.toString('base64url'), c.getAuthTag().toString('base64url'), enc.toString('base64url')].join('.');
}

export function decryptSecret(stored, secret) {
  const [v, iv, tag, enc] = stored.split('.');
  if (v !== 'v1' || !iv || !tag || !enc) throw new Error('Неизвестный формат секрета');
  const d = createDecipheriv('aes-256-gcm', keyFrom(secret), Buffer.from(iv, 'base64url'));
  d.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(enc, 'base64url')), d.final()]);
}

// Запасной код: 12 символов из алфавита без похожих (0/O, 1/I), показывается как XXXX-XXXX-XXXX. Около 60 бит.
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function newRecoveryCode() {
  const b = randomBytes(12);
  let s = '';
  for (let i = 0; i < 12; i++) s += ALPHA[b[i] & 31];
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8)}`;
}

export function normalizeRecovery(s) {
  const t = s.replace(/[\s-]/g, '').toUpperCase();
  return /^[A-HJ-NP-Z2-9]{12}$/.test(t) ? t : null;
}

export const hashRecovery = (normalized) => createHash('sha256').update('dvauth-recovery\0' + normalized).digest();
