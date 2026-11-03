// SPDX-License-Identifier: AGPL-3.0-only
// Конфигурация из переменных окружения. Секреты нигде не печатаются.
import { createHash } from 'node:crypto';

function intVar(env, name, def, min, max) {
  const raw = env[name];
  const v = raw === undefined || raw === '' ? def : Number(raw);
  if (!Number.isInteger(v) || v < min || v > max) throw new Error(`${name} должен быть целым числом от ${min} до ${max}`);
  return v;
}

// DVAUTH_CLIENTS: JSON-массив приложений, которым разрешено пользоваться сервисом:
//   [{"id":"cloud","title":"DV Cloud","secret":"<не короче 32 символов>"}]
export function parseClients(raw) {
  let list;
  try {
    list = JSON.parse(raw || '[]');
  } catch {
    throw new Error('DVAUTH_CLIENTS: неверный JSON');
  }
  if (!Array.isArray(list) || list.length === 0) throw new Error('DVAUTH_CLIENTS: нужен непустой список приложений');
  const seen = new Set();
  return list.map((c) => {
    if (!c || typeof c.id !== 'string' || !/^[a-z0-9_-]{1,32}$/.test(c.id)) throw new Error('DVAUTH_CLIENTS: id приложения: a-z, 0-9, _ и -, до 32 символов');
    if (seen.has(c.id)) throw new Error(`DVAUTH_CLIENTS: id ${c.id} повторяется`);
    seen.add(c.id);
    if (typeof c.title !== 'string' || c.title.length < 1 || c.title.length > 40) throw new Error(`DVAUTH_CLIENTS: название приложения ${c.id}: от 1 до 40 символов`);
    if (typeof c.secret !== 'string' || c.secret.length < 32) throw new Error(`DVAUTH_CLIENTS: секрет приложения ${c.id} не короче 32 символов`);
    return { id: c.id, title: c.title, secretHash: createHash('sha256').update(c.secret).digest() };
  });
}

export function loadConfig(env = process.env) {
  const port = intVar(env, 'DVAUTH_PORT', 3010, 1, 65535);
  const internalPort = intVar(env, 'DVAUTH_INTERNAL_PORT', 3011, 1, 65535);
  if (port === internalPort) throw new Error('DVAUTH_PORT и DVAUTH_INTERNAL_PORT должны различаться');
  const databaseUrl = env.DVAUTH_DATABASE_URL ?? '';
  if (!databaseUrl) throw new Error('Не задан DVAUTH_DATABASE_URL');
  const totpKey = env.DVAUTH_TOTP_KEY ?? '';
  if (totpKey !== '' && totpKey.length < 32) throw new Error('DVAUTH_TOTP_KEY должен быть не короче 32 символов');
  const matrixServer = (env.DVAUTH_MATRIX_SERVER_NAME ?? '').trim();
  const matrixUrl = (env.DVAUTH_MATRIX_URL ?? '').trim().replace(/\/+$/, '');
  if ((matrixServer === '') !== (matrixUrl === '')) throw new Error('DVAUTH_MATRIX_SERVER_NAME и DVAUTH_MATRIX_URL задаются вместе');
  if (matrixUrl !== '' && !/^https?:\/\//.test(matrixUrl)) throw new Error('DVAUTH_MATRIX_URL должен начинаться с http:// или https://');
  if (totpKey === '' && matrixUrl === '') throw new Error('Нужен хотя бы один способ: задайте DVAUTH_TOTP_KEY и/или DVAUTH_MATRIX_*');
  return {
    host: env.DVAUTH_HOST ?? '127.0.0.1',
    port,
    internalHost: env.DVAUTH_INTERNAL_HOST ?? '127.0.0.1',
    internalPort,
    trustProxy: intVar(env, 'DVAUTH_TRUST_PROXY', 0, 0, 10),
    databaseUrl,
    clients: parseClients(env.DVAUTH_CLIENTS),
    totpKey,
    matrixServer,
    matrixUrl,
  };
}
