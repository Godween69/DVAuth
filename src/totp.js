// SPDX-License-Identifier: AGPL-3.0-only
// TOTP по RFC 6238 (HMAC-SHA1, 6 цифр, шаг 30 секунд): совместим с Google Authenticator, Aegis, 2FAS и т.п.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const STEP_SEC = 30;

export function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s) {
  const clean = s.replace(/[\s=-]/g, '').toUpperCase();
  const bytes = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const i = B32.indexOf(ch);
    if (i < 0) throw new Error('Недопустимый символ base32');
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function newSecret() {
  return randomBytes(20); // 160 бит, как рекомендует RFC 4226
}

export function hotp(secret, counter) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', secret).update(msg).digest();
  const off = h[h.length - 1] & 15;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 1_000_000).padStart(6, '0');
}

// Проверяет код с допуском ±1 шаг (уход часов). Возвращает номер принятого шага или null.
// lastStep: шаги не больше него уже использованы, повтор отвергается.
export function verifyTotp(secret, code, nowMs, lastStep) {
  if (!/^\d{6}$/.test(code)) return null;
  const now = Math.floor(nowMs / 1000 / STEP_SEC);
  let found = null;
  for (const step of [now - 1, now, now + 1]) {
    const a = Buffer.from(hotp(secret, step));
    const b = Buffer.from(code);
    if (timingSafeEqual(a, b) && step > lastStep) found = step; // перебираем все три, чтобы время не зависело от места совпадения
  }
  return found;
}

// Ссылка для QR-кода приложения-аутентификатора.
export function otpauthUri(issuer, account, secret) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  return `otpauth://totp/${label}?secret=${base32Encode(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${STEP_SEC}`;
}
