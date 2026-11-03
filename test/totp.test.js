// SPDX-License-Identifier: AGPL-3.0-only
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32Decode, base32Encode, hotp, otpauthUri, verifyTotp } from '../src/totp.js';
import { decryptSecret, encryptSecret, hashRecovery, newRecoveryCode, normalizeRecovery } from '../src/secrets.js';

const RFC = Buffer.from('12345678901234567890'); // ключ из приложения B к RFC 6238

test('TOTP: эталонные значения RFC 6238 (шесть последних цифр)', () => {
  for (const [t, code] of [
    [59, '287082'],
    [1111111109, '081804'],
    [1234567890, '005924'],
    [2000000000, '279037'],
  ]) {
    assert.equal(hotp(RFC, Math.floor(t / 30)), code);
  }
});

test('TOTP: допуск плюс-минус шаг, повтор и чужой код отвергаются', () => {
  const now = 1234567890 * 1000;
  const step = Math.floor(now / 30000);
  assert.equal(verifyTotp(RFC, '005924', now, 0), step);
  assert.equal(verifyTotp(RFC, '005924', now + 30000, 0), step); // соседний шаг ещё принимается
  assert.equal(verifyTotp(RFC, '005924', now + 90000, 0), null); // а через три шага уже нет
  assert.equal(verifyTotp(RFC, '005924', now, step), null); // уже использованный шаг
  assert.equal(verifyTotp(RFC, '000000', now, 0), null);
  assert.equal(verifyTotp(RFC, '12345', now, 0), null);
  assert.equal(verifyTotp(RFC, 'abcdef', now, 0), null);
});

test('base32 туда и обратно, пробелы и регистр не мешают', () => {
  assert.equal(base32Encode(RFC), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.deepEqual(base32Decode('gezd gnbv-GY3TQOJQGEZDGNBVGY3TQOJQ'), RFC);
  assert.throws(() => base32Decode('1'));
});

test('ссылка для QR: издатель, аккаунт и параметры', () => {
  const u = otpauthUri('DV Cloud', 'anna', RFC);
  assert.match(u, /^otpauth:\/\/totp\/DV%20Cloud:anna\?secret=GEZDGNBV/);
  assert.match(u, /issuer=DV%20Cloud&algorithm=SHA1&digits=6&period=30$/);
});

test('секрет шифруется и расшифровывается, с чужим ключом или после порчи не открывается', () => {
  const key = 'k'.repeat(40);
  const enc = encryptSecret(RFC, key);
  assert.ok(!enc.includes(RFC.toString('base64url')));
  assert.deepEqual(decryptSecret(enc, key), RFC);
  assert.throws(() => decryptSecret(enc, 'z'.repeat(40)));
  assert.throws(() => decryptSecret(enc.slice(0, -2) + 'AA', key));
  assert.notEqual(encryptSecret(RFC, key), enc); // у каждого шифрования своя соль
});

test('запасные коды: формат, нормализация, хеш не зависит от записи', () => {
  const c = newRecoveryCode();
  assert.match(c, /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
  const n = normalizeRecovery(c);
  assert.equal(n.length, 12);
  assert.deepEqual(hashRecovery(n), hashRecovery(normalizeRecovery(' ' + c.toLowerCase() + ' ')));
  assert.equal(normalizeRecovery('0OIL-1111-0000'), null);
  assert.equal(normalizeRecovery('123456'), null);
  assert.notEqual(newRecoveryCode(), newRecoveryCode());
});
