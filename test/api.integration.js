// SPDX-License-Identifier: AGPL-3.0-only
// Интеграционные тесты на настоящем Postgres и поддельном Synapse. Запуск: npm run test:db (нужен DVAUTH_TEST_DATABASE_URL).
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { createInternalApp, createPublicApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createMatrix } from '../src/matrix.js';
import { migrate } from '../src/migrate.js';
import { createService } from '../src/service.js';
import { base32Decode, hotp } from '../src/totp.js';

const ADMIN_URL = process.env.DVAUTH_TEST_DATABASE_URL;
if (!ADMIN_URL) throw new Error('Не задан DVAUTH_TEST_DATABASE_URL: интеграционные тесты без базы не запускаются');
const SERVER = 'chat.example.org';
const SECRET_A = 'a'.repeat(40);
const SECRET_B = 'b'.repeat(40);

const listen = (srv) => new Promise((ok) => srv.listen(0, '127.0.0.1', () => ok(srv.address().port)));

describe('DV Auth (настоящий Postgres, поддельный Synapse)', () => {
  let dbName, pool, fake, pub, internal, synapseDown = false;
  let intBase, pubBase;
  const openid = new Map(); // токен OpenID -> Matrix ID

  async function call(base, method, path, { body, secret = SECRET_A } = {}) {
    const headers = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (secret && base === intBase) headers.authorization = `Bearer ${secret}`;
    const r = await fetch(base + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    return { status: r.status, json: await r.json().catch(() => null) };
  }
  const i = (m, p, o) => call(intBase, m, p, o);
  const pb = (m, p, o) => call(pubBase, m, p, o);
  const code = (secretB32, shift = 0) => hotp(base32Decode(secretB32), Math.floor(Date.now() / 30000) + shift);
  const clear = () => pool.query('DELETE FROM attempts');

  // Включает TOTP человеку, возвращает секрет и запасные коды.
  async function enrollTotp(subject, client = SECRET_A) {
    const b = await i('POST', '/v1/totp/begin', { body: { subject }, secret: client });
    const e = await i('POST', '/v1/totp/enable', { body: { subject, code: code(b.json.secret) }, secret: client });
    return { secret: b.json.secret, recovery: e.json.recoveryCodes };
  }
  async function linkChat(subject, matrixId, secretKey = SECRET_A) {
    const tok = `tok-${randomBytes(6).toString('hex')}`;
    openid.set(tok, matrixId);
    const s = await i('POST', '/v1/chat/link/start', { body: { subject, ip: '10.0.0.1' }, secret: secretKey });
    await pb('POST', '/v1/chat/confirm', { body: { challenge: s.json.challenge, number: s.json.number, openid: tok } });
    return i('POST', '/v1/chat/link/status', { body: { subject }, secret: secretKey });
  }

  before(async () => {
    fake = createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      const sub = openid.get(u.searchParams.get('access_token') ?? '');
      if (synapseDown) { res.statusCode = 502; res.end('{}'); }
      else if (u.pathname === '/_matrix/federation/v1/openid/userinfo' && sub) res.end(JSON.stringify({ sub }));
      else { res.statusCode = 401; res.end('{"errcode":"M_UNKNOWN_TOKEN"}'); }
    });
    const fakePort = await listen(fake);
    dbName = `dvauth_test_${randomBytes(4).toString('hex')}`;
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    await admin.end();
    const u = new URL(ADMIN_URL);
    u.pathname = `/${dbName}`;
    pool = new pg.Pool({ connectionString: u.toString(), max: 5 });
    const c = new pg.Client({ connectionString: u.toString() });
    await c.connect();
    await migrate(c, fileURLToPath(new URL('../migrations', import.meta.url)));
    await c.end();
    const cfg = loadConfig({
      DVAUTH_DATABASE_URL: u.toString(),
      DVAUTH_CLIENTS: JSON.stringify([{ id: 'cloud', title: 'DV Cloud', secret: SECRET_A }, { id: 'mail', title: 'DV Mail', secret: SECRET_B }]),
      DVAUTH_TOTP_KEY: 'integration-totp-key-'.padEnd(40, 'k'),
      DVAUTH_MATRIX_SERVER_NAME: SERVER,
      DVAUTH_MATRIX_URL: `http://127.0.0.1:${fakePort}`,
    });
    const svc = createService({ db: pool, cfg, matrix: createMatrix(cfg) });
    pub = createPublicApp(cfg, svc);
    internal = createInternalApp(cfg, svc);
    pubBase = `http://127.0.0.1:${await listen(pub)}`;
    intBase = `http://127.0.0.1:${await listen(internal)}`;
  });

  after(async () => {
    for (const s of [pub, internal, fake]) await new Promise((ok) => s?.close(ok));
    await pool?.end();
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin.end();
  });

  it('внутренний порт требует секрет приложения; публичный не отдаёт внутренние адреса', async () => {
    assert.equal((await i('GET', '/health', { secret: null })).status, 200);
    assert.equal((await i('GET', '/v1/status?subject=1', { secret: null })).status, 401);
    assert.equal((await i('GET', '/v1/status?subject=1', { secret: 'x'.repeat(40) })).status, 401);
    assert.equal((await pb('GET', '/v1/status?subject=1')).status, 404);
    assert.equal((await pb('POST', '/v1/reset', { body: { subject: '1' } })).status, 404);
    assert.equal((await pb('GET', '/health')).status, 200);
  });

  it('без второго фактора вход идёт сразу', async () => {
    const r = await i('POST', '/v1/login/begin', { body: { subject: '100', ip: '1.1.1.1' } });
    assert.deepEqual(r.json, { required: false });
    const s = await i('GET', '/v1/status?subject=100');
    assert.equal(s.json.enabled, false);
    assert.equal(s.json.totpAvailable, true);
    assert.equal(s.json.chatAvailable, true);
  });

  it('запросы без JSON и с лишним весом отвергаются', async () => {
    const r = await fetch(intBase + '/v1/login/begin', { method: 'POST', headers: { authorization: `Bearer ${SECRET_A}`, 'content-type': 'text/plain' }, body: 'x' });
    assert.equal(r.status, 415);
    const big = await fetch(intBase + '/v1/login/begin', { method: 'POST', headers: { authorization: `Bearer ${SECRET_A}`, 'content-type': 'application/json' }, body: JSON.stringify({ subject: 'x'.repeat(40000) }) });
    assert.equal(big.status, 413);
    assert.equal((await i('POST', '/v1/login/begin', { body: { subject: '' } })).status, 400);
  });

  describe('TOTP и запасные коды', () => {
    let secret, recovery;
    const S = '200';
    it('настройка: неверный первый код не включает, верный выдаёт 10 запасных кодов', async () => {
      const b = await i('POST', '/v1/totp/begin', { body: { subject: S, label: 'tina' } });
      assert.match(b.json.uri, /^otpauth:\/\/totp\/DV%20Cloud:tina\?secret=/);
      secret = b.json.secret;
      assert.equal((await i('POST', '/v1/totp/enable', { body: { subject: S, code: '000000' } })).status, 400);
      const e = await i('POST', '/v1/totp/enable', { body: { subject: S, code: code(secret) } });
      recovery = e.json.recoveryCodes;
      assert.equal(recovery.length, 10);
      const st = (await i('GET', `/v1/status?subject=${S}`)).json;
      assert.deepEqual([st.enabled, st.totpEnabled, st.recoveryLeft, st.methods], [true, true, 10, ['totp', 'recovery']]);
      assert.equal((await i('POST', '/v1/totp/begin', { body: { subject: S } })).status, 409);
    });

    it('вход: выдаётся талон; неверный код отвергается; пять ошибок сжигают талон', async () => {
      const t = (await i('POST', '/v1/login/begin', { body: { subject: S, ip: '2.2.2.2' } })).json;
      assert.equal(t.required, true);
      assert.deepEqual(t.methods, ['totp', 'recovery']);
      for (let n = 0; n < 5; n++) assert.equal((await i('POST', '/v1/login/code', { body: { ticket: t.ticket, code: '111111', ip: '2.2.2.2' } })).status, 401);
      assert.equal((await i('POST', '/v1/login/code', { body: { ticket: t.ticket, code: code(secret), ip: '2.2.2.2' } })).json.error, 'ticket_expired');
      await clear();
    });

    it('верный код принимается один раз; повтор того же кода отвергается', async () => {
      const c = code(secret, 1); // текущий шаг уже занят кодом из настройки, берём следующий (он тоже в допуске)
      const t1 = (await i('POST', '/v1/login/begin', { body: { subject: S, ip: '2.2.2.2' } })).json.ticket;
      const ok = await i('POST', '/v1/login/code', { body: { ticket: t1, code: c, ip: '2.2.2.2' } });
      assert.equal(ok.status, 200);
      assert.equal(ok.json.subject, S);
      assert.equal((await i('POST', '/v1/login/code', { body: { ticket: t1, code: code(secret, -1), ip: '2.2.2.2' } })).status, 401); // талон одноразовый
      const t2 = (await i('POST', '/v1/login/begin', { body: { subject: S, ip: '2.2.2.2' } })).json.ticket;
      assert.equal((await i('POST', '/v1/login/code', { body: { ticket: t2, code: c, ip: '2.2.2.2' } })).status, 401); // тот же шаг
      await clear();
    });

    it('запасной код работает один раз в любой записи', async () => {
      const t1 = (await i('POST', '/v1/login/begin', { body: { subject: S, ip: '2.2.2.2' } })).json.ticket;
      const written = recovery[0].toLowerCase().replace(/-/g, ' ');
      assert.equal((await i('POST', '/v1/login/code', { body: { ticket: t1, code: written, ip: '2.2.2.2' } })).status, 200);
      const t2 = (await i('POST', '/v1/login/begin', { body: { subject: S, ip: '2.2.2.2' } })).json.ticket;
      assert.equal((await i('POST', '/v1/login/code', { body: { ticket: t2, code: recovery[0], ip: '2.2.2.2' } })).status, 401);
      assert.equal((await i('GET', `/v1/status?subject=${S}`)).json.recoveryLeft, 9);
      await clear();
    });

    it('проверка для чувствительных действий: /check принимает код, неверный считает как ошибку', async () => {
      assert.equal((await i('POST', '/v1/check', { body: { subject: S, code: '123456', ip: '3.3.3.3' } })).status, 401);
      assert.equal((await i('POST', '/v1/check', { body: { subject: S, code: recovery[1], ip: '3.3.3.3' } })).status, 200);
      await clear();
    });

    it('перебор: после пяти ошибок по человеку ответ 429 даже на верный код', async () => {
      for (let n = 0; n < 5; n++) await i('POST', '/v1/check', { body: { subject: S, code: '654321', ip: `9.9.9.${n}` } });
      const r = await i('POST', '/v1/check', { body: { subject: S, code: recovery[2], ip: '9.9.9.9' } });
      assert.equal(r.status, 429);
      assert.equal((await i('POST', '/v1/login/begin', { body: { subject: S, ip: '9.9.9.9' } })).status, 429);
      await clear();
    });

    it('новые запасные коды отменяют старые; отключение TOTP убирает и запасные коды', async () => {
      const n = await i('POST', '/v1/recovery/new', { body: { subject: S } });
      assert.equal(n.json.recoveryCodes.length, 10);
      assert.equal((await i('POST', '/v1/check', { body: { subject: S, code: recovery[3], ip: '4.4.4.4' } })).status, 401);
      assert.equal((await i('POST', '/v1/totp/disable', { body: { subject: S } })).status, 200);
      const st = (await i('GET', `/v1/status?subject=${S}`)).json;
      assert.deepEqual([st.enabled, st.recoveryLeft], [false, 0]);
      assert.equal((await i('POST', '/v1/recovery/new', { body: { subject: S } })).status, 409);
      await clear();
    });
  });

  describe('подтверждение в чате', () => {
    const confirm = (challenge, number, token) => pb('POST', '/v1/chat/confirm', { body: { challenge, number, openid: token } });
    const wrongNumber = (n) => String((Number(n) % 800) + 101);
    openid.set('tok-lena-aaaaaaaa', `@lena:${SERVER}`);
    openid.set('tok-oleg-aaaaaaaa', `@oleg:${SERVER}`);
    openid.set('tok-alien-aaaaaaa', '@lena:evil.example.net');
    const L = '300';

    it('привязка: чужой сервер, неверное число и неизвестный токен не проходят; верное число привязывает', async () => {
      const s = await i('POST', '/v1/chat/link/start', { body: { subject: L, ip: '5.5.5.5', agent: 'Firefox' } });
      assert.match(s.json.number, /^[1-9]\d\d$/);
      assert.ok(s.json.qr.startsWith('dvchat://auth#'));
      assert.equal(JSON.parse(Buffer.from(s.json.qr.slice(14), 'base64url')).c, s.json.challenge);
      const info = await pb('GET', `/v1/chat/info?challenge=${s.json.challenge}`);
      assert.deepEqual(info.json, { title: 'DV Cloud', purpose: 'link', ip: '5.5.5.5', agent: 'Firefox' });
      assert.equal((await confirm(s.json.challenge, s.json.number, 'tok-alien-aaaaaaa')).status, 401);
      assert.equal((await confirm(s.json.challenge, s.json.number, 'tok-неизвестный-xx')).status, 401);
      assert.equal((await confirm(s.json.challenge, wrongNumber(s.json.number), 'tok-lena-aaaaaaaa')).status, 401);
      assert.equal((await i('POST', '/v1/chat/link/status', { body: { subject: L } })).json.state, 'pending');
      assert.equal((await confirm(s.json.challenge, s.json.number, 'tok-lena-aaaaaaaa')).status, 200);
      const done = await i('POST', '/v1/chat/link/status', { body: { subject: L } });
      assert.equal(done.json.state, 'approved');
      assert.equal(done.json.matrixId, `@lena:${SERVER}`);
      assert.equal(done.json.recoveryCodes.length, 10);
      assert.equal((await confirm(s.json.challenge, s.json.number, 'tok-lena-aaaaaaaa')).status, 404); // запрос одноразовый
      await clear();
    });

    it('один аккаунт чата нельзя привязать к двум людям одного приложения, но можно в разных приложениях', async () => {
      const r = await linkChat('301', `@lena:${SERVER}`);
      assert.equal(r.status, 409);
      assert.equal((await i('GET', '/v1/status?subject=301')).json.chatLinked, false);
      const other = await linkChat('301', `@lena:${SERVER}`, SECRET_B);
      assert.equal(other.json.state, 'approved');
      assert.equal((await i('GET', '/v1/status?subject=300', { secret: SECRET_B })).json.chatLinked, false); // приложения изолированы
      await clear();
    });

    it('вход: подтверждение чужим аккаунтом сжигает запрос', async () => {
      const t = (await i('POST', '/v1/login/begin', { body: { subject: L, ip: '6.6.6.6' } })).json;
      assert.deepEqual(t.methods, ['chat', 'recovery']);
      const s = await i('POST', '/v1/login/chat/start', { body: { ticket: t.ticket, ip: '6.6.6.6', agent: 'Chrome' } });
      assert.equal((await i('POST', '/v1/login/chat/status', { body: { ticket: t.ticket } })).json.state, 'pending');
      assert.equal((await confirm(s.json.challenge, s.json.number, 'tok-oleg-aaaaaaaa')).status, 403);
      assert.equal((await i('POST', '/v1/login/chat/status', { body: { ticket: t.ticket } })).json.state, 'failed');
      assert.equal((await confirm(s.json.challenge, s.json.number, 'tok-lena-aaaaaaaa')).status, 404);
      await clear();
    });

    it('вход: верное число и свой аккаунт, результат выдаётся один раз', async () => {
      const t = (await i('POST', '/v1/login/begin', { body: { subject: L, ip: '6.6.6.6' } })).json.ticket;
      const s = await i('POST', '/v1/login/chat/start', { body: { ticket: t, ip: '6.6.6.6' } });
      assert.equal((await confirm(s.json.challenge, s.json.number, 'tok-lena-aaaaaaaa')).status, 200);
      const ok = await i('POST', '/v1/login/chat/status', { body: { ticket: t } });
      assert.deepEqual([ok.json.state, ok.json.subject], ['approved', L]);
      assert.equal((await i('POST', '/v1/login/chat/status', { body: { ticket: t } })).status, 401); // талон сгорел
      await clear();
    });

    it('три неверных числа отменяют запрос; новый запрос гасит прежний', async () => {
      const t = (await i('POST', '/v1/login/begin', { body: { subject: L, ip: '6.6.6.6' } })).json.ticket;
      const a = await i('POST', '/v1/login/chat/start', { body: { ticket: t, ip: '6.6.6.6' } });
      for (let n = 0; n < 3; n++) assert.equal((await confirm(a.json.challenge, wrongNumber(a.json.number), 'tok-lena-aaaaaaaa')).status, 401);
      assert.equal((await confirm(a.json.challenge, a.json.number, 'tok-lena-aaaaaaaa')).status, 404);
      await clear();
      const b = await i('POST', '/v1/login/chat/start', { body: { ticket: t, ip: '6.6.6.6' } });
      const c = await i('POST', '/v1/login/chat/start', { body: { ticket: t, ip: '6.6.6.6' } });
      assert.equal((await confirm(b.json.challenge, b.json.number, 'tok-lena-aaaaaaaa')).status, 404);
      await clear();
      synapseDown = true;
      assert.equal((await confirm(c.json.challenge, c.json.number, 'tok-lena-aaaaaaaa')).status, 503);
      synapseDown = false;
      assert.ok((await i('POST', '/v1/login/begin', { body: { subject: L, ip: '6.6.6.6' } })).json.methods.includes('recovery'));
      await clear();
    });

    it('перебор с одного адреса через публичный порт: после 30 ошибок 429', async () => {
      const s = await i('POST', '/v1/chat/link/start', { body: { subject: '399', ip: '7.7.7.7' } });
      let last = 0;
      for (let n = 0; n < 40; n++) last = (await confirm(s.json.challenge === 'x' ? 'nope' : `nope-${n}-xxxxxxxx`, '123', 'tok-lena-aaaaaaaa')).status;
      assert.equal(last, 429);
      await clear();
    });

    it('отвязка: после неё запасные коды больше не нужны', async () => {
      assert.equal((await i('POST', '/v1/chat/unlink', { body: { subject: L } })).status, 200);
      const st = (await i('GET', `/v1/status?subject=${L}`)).json;
      assert.deepEqual([st.enabled, st.recoveryLeft], [false, 0]);
    });
  });

  it('сброс снимает всё у человека, соседние приложения не затрагиваются; список включённых', async () => {
    await enrollTotp('400');
    await enrollTotp('400', SECRET_B);
    assert.deepEqual((await i('GET', '/v1/subjects')).json.subjects.includes('400'), true);
    assert.equal((await i('POST', '/v1/reset', { body: { subject: '400' } })).status, 200);
    assert.equal((await i('GET', '/v1/status?subject=400')).json.enabled, false);
    assert.equal((await i('GET', '/v1/status?subject=400', { secret: SECRET_B })).json.enabled, true);
    assert.equal((await i('GET', '/v1/subjects')).json.subjects.includes('400'), false);
  });

  it('в базе нет секретов и кодов открытым текстом', async () => {
    const { secret, recovery } = await enrollTotp('500');
    const dump = JSON.stringify((await pool.query('SELECT * FROM totp')).rows) + JSON.stringify((await pool.query('SELECT * FROM recovery_codes')).rows) + JSON.stringify((await pool.query('SELECT * FROM events')).rows);
    assert.ok(!dump.includes(secret));
    for (const c of recovery) assert.ok(!dump.includes(c.replace(/-/g, '')));
  });
});
