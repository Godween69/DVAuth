// SPDX-License-Identifier: AGPL-3.0-only
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig, parseClients } from '../src/config.js';

const SECRET = 's'.repeat(32);
const base = {
  DVAUTH_DATABASE_URL: 'postgres://x',
  DVAUTH_CLIENTS: JSON.stringify([{ id: 'cloud', title: 'DV Cloud', secret: SECRET }]),
  DVAUTH_TOTP_KEY: 'k'.repeat(32),
};

test('значения по умолчанию: только localhost, порты 3010 и 3011', () => {
  const c = loadConfig(base);
  assert.equal(c.host, '127.0.0.1');
  assert.equal(c.internalHost, '127.0.0.1');
  assert.equal(c.port, 3010);
  assert.equal(c.internalPort, 3011);
  assert.equal(c.clients[0].id, 'cloud');
  assert.ok(!JSON.stringify(c).includes(SECRET)); // секрет приложения в конфигурации хранится только хешем
});

test('без базы, без приложений или без единого способа сервис не стартует', () => {
  assert.throws(() => loadConfig({ ...base, DVAUTH_DATABASE_URL: '' }), /DVAUTH_DATABASE_URL/);
  assert.throws(() => loadConfig({ ...base, DVAUTH_CLIENTS: '' }), /DVAUTH_CLIENTS/);
  assert.throws(() => loadConfig({ ...base, DVAUTH_TOTP_KEY: '' }), /хотя бы один способ/);
});

test('приложения: id, название, длина секрета, повторы', () => {
  assert.throws(() => parseClients('не json'), /JSON/);
  assert.throws(() => parseClients('[{"id":"Cloud","title":"x","secret":"' + SECRET + '"}]'), /id приложения/);
  assert.throws(() => parseClients('[{"id":"a","title":"x","secret":"short"}]'), /32/);
  assert.throws(() => parseClients(JSON.stringify([{ id: 'a', title: 'x', secret: SECRET }, { id: 'a', title: 'y', secret: SECRET }])), /повторяется/);
});

test('чат: имя сервера и адрес задаются вместе, адрес с http или https', () => {
  assert.throws(() => loadConfig({ ...base, DVAUTH_MATRIX_URL: 'http://127.0.0.1:8008' }), /вместе/);
  assert.throws(() => loadConfig({ ...base, DVAUTH_MATRIX_SERVER_NAME: 'a.b', DVAUTH_MATRIX_URL: 'ftp://x' }), /http/);
  const c = loadConfig({ ...base, DVAUTH_TOTP_KEY: '', DVAUTH_MATRIX_SERVER_NAME: 'a.b', DVAUTH_MATRIX_URL: 'http://127.0.0.1:8008/' });
  assert.equal(c.matrixUrl, 'http://127.0.0.1:8008');
});
