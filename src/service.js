// SPDX-License-Identifier: AGPL-3.0-only
// Вся логика второго фактора. Человек это пара (client, subject); все запросы к базе ограничены клиентом,
// поэтому одно приложение не видит и не меняет людей другого.
import { createHash, randomBytes, randomInt } from 'node:crypto';
import { ApiError } from './http.js';
import { decryptSecret, encryptSecret, hashRecovery, newRecoveryCode, normalizeRecovery } from './secrets.js';
import { base32Encode, newSecret, otpauthUri, verifyTotp } from './totp.js';

const TICKET_MINUTES = 5;
const MAX_TICKET_FAILS = 5;
const CHALLENGE_SECONDS = 180;
const MAX_NUMBER_FAILS = 3;
const MAX_FAILS_PER_SUBJECT = 5; // за 15 минут
const MAX_FAILS_PER_IP = 30; // за 15 минут
const RECOVERY_COUNT = 10;
const sha256 = (s) => createHash('sha256').update(s).digest();

export function createService({ db, cfg, matrix }) {
  const q = (text, params) => db.query(text, params);
  const totpOn = cfg.totpKey !== '';

  // ---------- ограничение перебора ----------
  async function assertNotLocked(key, ip) {
    await q("DELETE FROM attempts WHERE at < now() - interval '1 day'");
    const c = (
      await q(
        `SELECT (SELECT count(*) FROM attempts WHERE key = $1 AND at > now() - interval '15 minutes') AS by_key,
                (SELECT count(*) FROM attempts WHERE ip = $2 AND at > now() - interval '15 minutes') AS by_ip`,
        [key, ip],
      )
    ).rows[0];
    if (Number(c.by_key) >= MAX_FAILS_PER_SUBJECT || Number(c.by_ip) >= MAX_FAILS_PER_IP) {
      throw new ApiError(429, 'locked', 'Слишком много попыток. Подождите 15 минут.');
    }
  }
  const recordFail = (key, ip) => q('INSERT INTO attempts (key, ip) VALUES ($1, $2)', [key, ip]);
  const clearFails = (key) => q('DELETE FROM attempts WHERE key = $1', [key]);
  const subjKey = (client, subject) => `s:${client}:${subject}`.slice(0, 200);
  const event = (client, subject, kind, ip = '') => q('INSERT INTO events (client, subject, kind, ip) VALUES ($1, $2, $3, $4)', [client, subject, kind, ip]);

  // ---------- состояние ----------
  async function status(client, subject) {
    const r = (
      await q(
        `SELECT (SELECT matrix_id FROM chat_links WHERE client = $1 AND subject = $2) AS matrix_id,
                EXISTS (SELECT 1 FROM totp WHERE client = $1 AND subject = $2 AND confirmed_at IS NOT NULL) AS totp,
                (SELECT count(*) FROM recovery_codes WHERE client = $1 AND subject = $2 AND used_at IS NULL) AS left`,
        [client, subject],
      )
    ).rows[0];
    const s = {
      enabled: r.matrix_id !== null || r.totp,
      chatAvailable: matrix.enabled,
      chatLinked: r.matrix_id !== null,
      matrixId: r.matrix_id,
      totpAvailable: totpOn,
      totpEnabled: r.totp,
      recoveryLeft: Number(r.left),
    };
    s.methods = [];
    if (s.chatLinked && s.chatAvailable) s.methods.push('chat');
    if (s.totpEnabled) s.methods.push('totp');
    if (s.recoveryLeft > 0) s.methods.push('recovery');
    return s;
  }

  // ---------- проверка кода (TOTP или запасной) ----------
  async function checkFactor(client, subject, code) {
    const t = String(code).trim();
    if (/^\d{6}$/.test(t)) {
      if (!totpOn) return false;
      const r = (await q('SELECT secret_enc, last_step FROM totp WHERE client = $1 AND subject = $2 AND confirmed_at IS NOT NULL', [client, subject])).rows[0];
      if (!r) return false;
      const step = verifyTotp(decryptSecret(r.secret_enc, cfg.totpKey), t, Date.now(), Number(r.last_step));
      if (step === null) return false;
      // last_step < $3 делает «один код один раз» верным и при двух одновременных запросах.
      return (await q('UPDATE totp SET last_step = $3 WHERE client = $1 AND subject = $2 AND last_step < $3', [client, subject, step])).rowCount === 1;
    }
    const norm = normalizeRecovery(t);
    if (!norm) return false;
    return (await q('UPDATE recovery_codes SET used_at = now() WHERE client = $1 AND subject = $2 AND code_hash = $3 AND used_at IS NULL', [client, subject, hashRecovery(norm)])).rowCount === 1;
  }

  // Проверка кода для чувствительных действий в приложении (смена настроек и т.п.), с ограничением перебора.
  async function check(client, subject, code, ip) {
    await assertNotLocked(subjKey(client, subject), ip);
    if (!(await checkFactor(client, subject, code))) {
      await recordFail(subjKey(client, subject), ip);
      throw new ApiError(401, 'invalid_code', 'Неверный код');
    }
    return { ok: true };
  }

  // ---------- вход: талон и второй шаг ----------
  async function loginBegin(client, subject, ip) {
    await assertNotLocked(subjKey(client, subject), ip);
    const st = await status(client, subject);
    if (!st.enabled) return { required: false };
    await q('DELETE FROM tickets WHERE expires_at < now()');
    const token = randomBytes(32).toString('base64url');
    await q('INSERT INTO tickets (token_hash, client, subject, expires_at) VALUES ($1, $2, $3, now() + make_interval(mins => $4))', [sha256(token), client, subject, TICKET_MINUTES]);
    await event(client, subject, 'login.begin', ip);
    return { required: true, ticket: token, methods: st.methods };
  }

  async function ticket(client, token) {
    const r = (await q('SELECT id, subject FROM tickets WHERE token_hash = $1 AND client = $2 AND expires_at > now() AND fails < $3', [sha256(token), client, MAX_TICKET_FAILS])).rows[0];
    if (!r) throw new ApiError(401, 'ticket_expired', 'Время входа истекло. Войдите заново.');
    return r;
  }

  async function loginCode(client, token, code, ip) {
    const t = await ticket(client, token);
    await assertNotLocked(subjKey(client, t.subject), ip);
    if (!(await checkFactor(client, t.subject, code))) {
      await q('UPDATE tickets SET fails = fails + 1 WHERE id = $1', [t.id]);
      await recordFail(subjKey(client, t.subject), ip);
      await event(client, t.subject, 'login.code.fail', ip);
      throw new ApiError(401, 'invalid_code', 'Неверный код');
    }
    await q('DELETE FROM tickets WHERE id = $1', [t.id]);
    await clearFails(subjKey(client, t.subject));
    await event(client, t.subject, 'login.code.ok', ip);
    return { ok: true, subject: t.subject };
  }

  // ---------- подтверждение в чате ----------
  async function newChallenge(client, subject, purpose, ticketId, ip, agent) {
    if (!matrix.enabled) throw new ApiError(503, 'unavailable', 'Подтверждение через чат не настроено');
    await q("DELETE FROM challenges WHERE expires_at < now() - interval '1 hour'");
    // Прежние незавершённые запросы этого человека и назначения гасим: действует только последний.
    await q("UPDATE challenges SET state = 'dead' WHERE client = $1 AND subject = $2 AND purpose = $3 AND state = 'pending'", [client, subject, purpose]);
    const id = randomBytes(18).toString('base64url');
    const number = String(randomInt(100, 1000));
    await q(
      `INSERT INTO challenges (id, client, subject, purpose, ticket_id, number, ip, agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))`,
      [id, client, subject, purpose, ticketId, number, ip, String(agent).slice(0, 200), CHALLENGE_SECONDS],
    );
    return { challenge: id, number, qr: 'dvchat://auth#' + Buffer.from(JSON.stringify({ c: id }), 'utf8').toString('base64url'), expiresIn: CHALLENGE_SECONDS };
  }

  async function chatStartLogin(client, token, ip, agent) {
    const t = await ticket(client, token);
    if (!(await status(client, t.subject)).chatLinked) throw new ApiError(400, 'bad_request', 'Чат не привязан');
    return newChallenge(client, t.subject, 'login', t.id, ip, agent);
  }

  async function chatPollLogin(client, token) {
    const t = await ticket(client, token);
    const ch = (await q('SELECT id, state, expires_at < now() AS expired FROM challenges WHERE ticket_id = $1 ORDER BY expires_at DESC LIMIT 1', [t.id])).rows[0];
    if (!ch) return { state: 'none' };
    if (ch.state === 'approved') {
      if ((await q("UPDATE challenges SET state = 'dead' WHERE id = $1 AND state = 'approved'", [ch.id])).rowCount !== 1) return { state: 'failed' };
      await q('DELETE FROM tickets WHERE id = $1', [t.id]);
      await clearFails(subjKey(client, t.subject));
      await event(client, t.subject, 'login.chat.ok');
      return { state: 'approved', subject: t.subject };
    }
    if (ch.state === 'dead' || ch.expired) return { state: 'failed' };
    return { state: 'pending' };
  }

  async function chatStartLink(client, subject, ip, agent) {
    return newChallenge(client, subject, 'link', null, ip, agent);
  }

  // Привязка записывается здесь, по запросу приложения, которое начало привязку и опрашивает её.
  async function chatPollLink(client, subject) {
    const ch = (await q("SELECT id, state, matrix_id, expires_at < now() AS expired FROM challenges WHERE client = $1 AND subject = $2 AND purpose = 'link' ORDER BY expires_at DESC LIMIT 1", [client, subject])).rows[0];
    if (!ch) return { state: 'none' };
    if (ch.state === 'approved' && ch.matrix_id) {
      if ((await q("UPDATE challenges SET state = 'dead' WHERE id = $1 AND state = 'approved'", [ch.id])).rowCount !== 1) return { state: 'failed' };
      try {
        await q('INSERT INTO chat_links (client, subject, matrix_id) VALUES ($1, $2, $3) ON CONFLICT (client, subject) DO UPDATE SET matrix_id = EXCLUDED.matrix_id, linked_at = now()', [client, subject, ch.matrix_id]);
      } catch (e) {
        if (e.code === '23505') throw new ApiError(409, 'conflict', 'Этот аккаунт чата уже привязан к другому человеку');
        throw e;
      }
      await event(client, subject, 'chat.link');
      return { state: 'approved', matrixId: ch.matrix_id, recoveryCodes: await ensureRecovery(client, subject) };
    }
    if (ch.state === 'dead' || ch.expired) return { state: 'failed' };
    return { state: 'pending' };
  }

  async function chatUnlink(client, subject) {
    await q('DELETE FROM chat_links WHERE client = $1 AND subject = $2', [client, subject]);
    await dropRecoveryIfNoFactor(client, subject);
    await event(client, subject, 'chat.unlink');
    return { ok: true };
  }

  // Что показать человеку в приложении чата перед подтверждением. Публично, но без секретов.
  async function chatInfo(challengeId) {
    const r = (await q("SELECT client, purpose, ip, agent, expires_at - now() AS left FROM challenges WHERE id = $1 AND state = 'pending' AND expires_at > now()", [String(challengeId).slice(0, 64)])).rows[0];
    if (!r) throw new ApiError(404, 'not_found', 'Запрос не найден или устарел');
    const c = cfg.clients.find((x) => x.id === r.client);
    return { title: c ? c.title : r.client, purpose: r.purpose, ip: r.ip, agent: r.agent };
  }

  // Вызывается приложением чата (из интернета, без доверия). Что угодно неверное засчитывается как попытка.
  async function chatConfirm(challengeId, number, openidToken, ip) {
    const lockKey = `c:${ip}`.slice(0, 200);
    await assertNotLocked(lockKey, ip);
    const bad = async (status, code, msg) => {
      await recordFail(lockKey, ip);
      throw new ApiError(status, code, msg);
    };
    const ch = (await q("SELECT id, client, subject, purpose, number FROM challenges WHERE id = $1 AND state = 'pending' AND expires_at > now()", [String(challengeId).slice(0, 64)])).rows[0];
    if (!ch) return bad(404, 'not_found', 'Запрос входа не найден или устарел');
    if (number !== ch.number) {
      const f = (await q("UPDATE challenges SET fails = fails + 1, state = CASE WHEN fails + 1 >= $2 THEN 'dead' ELSE state END WHERE id = $1 RETURNING fails", [ch.id, MAX_NUMBER_FAILS])).rows[0].fails;
      await recordFail(lockKey, ip);
      throw new ApiError(401, 'invalid_number', f >= MAX_NUMBER_FAILS ? 'Неверное число. Запрос отменён, начните вход заново.' : 'Неверное число');
    }
    const matrixId = await matrix.whoIs(openidToken);
    if (!matrixId) return bad(401, 'not_verified', 'Чат не подтвердил, кто вы');
    if (ch.purpose === 'login') {
      const link = (await q('SELECT matrix_id FROM chat_links WHERE client = $1 AND subject = $2', [ch.client, ch.subject])).rows[0];
      if (link?.matrix_id !== matrixId) {
        // Подтверждает чужой аккаунт: запрос сгорает, чтобы его нельзя было перебирать.
        await q("UPDATE challenges SET state = 'dead' WHERE id = $1", [ch.id]);
        await event(ch.client, ch.subject, 'login.chat.wrong-account', ip);
        return bad(403, 'wrong_account', 'Этот аккаунт чата не привязан к этому входу');
      }
    }
    await q("UPDATE challenges SET state = 'approved', matrix_id = $2 WHERE id = $1", [ch.id, matrixId]);
    return { ok: true, purpose: ch.purpose };
  }

  // ---------- TOTP и запасные коды ----------
  async function totpBegin(client, subject, label) {
    if (!totpOn) throw new ApiError(503, 'unavailable', 'Коды из приложения не настроены (нет DVAUTH_TOTP_KEY)');
    if ((await status(client, subject)).totpEnabled) throw new ApiError(409, 'conflict', 'Коды из приложения уже включены');
    const secret = newSecret();
    await q(
      `INSERT INTO totp (client, subject, secret_enc) VALUES ($1, $2, $3)
       ON CONFLICT (client, subject) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, confirmed_at = NULL, last_step = 0`,
      [client, subject, encryptSecret(secret, cfg.totpKey)],
    );
    const title = cfg.clients.find((c) => c.id === client)?.title ?? client;
    return { secret: base32Encode(secret), uri: otpauthUri(title, label || subject, secret) };
  }

  async function totpEnable(client, subject, code) {
    const r = (await q('SELECT secret_enc FROM totp WHERE client = $1 AND subject = $2 AND confirmed_at IS NULL', [client, subject])).rows[0];
    if (!r) throw new ApiError(400, 'bad_request', 'Сначала начните настройку');
    const step = verifyTotp(decryptSecret(r.secret_enc, cfg.totpKey), String(code).trim(), Date.now(), 0);
    if (step === null) throw new ApiError(400, 'invalid_code', 'Код не подошёл. Проверьте время на телефоне и попробуйте новый код.');
    await q('UPDATE totp SET confirmed_at = now(), last_step = $3 WHERE client = $1 AND subject = $2', [client, subject, step]);
    await event(client, subject, 'totp.enable');
    return { recoveryCodes: await ensureRecovery(client, subject) };
  }

  async function totpDisable(client, subject) {
    await q('DELETE FROM totp WHERE client = $1 AND subject = $2', [client, subject]);
    await dropRecoveryIfNoFactor(client, subject);
    await event(client, subject, 'totp.disable');
    return { ok: true };
  }

  async function ensureRecovery(client, subject) {
    const n = Number((await q('SELECT count(*) AS n FROM recovery_codes WHERE client = $1 AND subject = $2', [client, subject])).rows[0].n);
    return n > 0 ? null : makeRecovery(client, subject);
  }

  async function makeRecovery(client, subject) {
    if (!(await status(client, subject)).enabled) throw new ApiError(409, 'conflict', 'Сначала включите второй фактор');
    const codes = Array.from({ length: RECOVERY_COUNT }, () => newRecoveryCode());
    await q('DELETE FROM recovery_codes WHERE client = $1 AND subject = $2', [client, subject]);
    for (const c of codes) await q('INSERT INTO recovery_codes (client, subject, code_hash) VALUES ($1, $2, $3)', [client, subject, hashRecovery(normalizeRecovery(c))]);
    await event(client, subject, 'recovery.new');
    return codes;
  }

  async function dropRecoveryIfNoFactor(client, subject) {
    if (!(await status(client, subject)).enabled) await q('DELETE FROM recovery_codes WHERE client = $1 AND subject = $2', [client, subject]);
  }

  // Полный сброс человека (потерял телефон и запасные коды): вызывает приложение по решению администратора.
  async function reset(client, subject) {
    for (const t of ['totp', 'recovery_codes', 'chat_links', 'tickets', 'challenges']) await q(`DELETE FROM ${t} WHERE client = $1 AND subject = $2`, [client, subject]);
    await event(client, subject, 'reset');
    return { ok: true };
  }

  async function enabledSubjects(client) {
    const r = await q('SELECT subject FROM chat_links WHERE client = $1 UNION SELECT subject FROM totp WHERE client = $1 AND confirmed_at IS NOT NULL', [client]);
    return { subjects: r.rows.map((x) => x.subject) };
  }

  return { status, check, loginBegin, loginCode, chatStartLogin, chatPollLogin, chatStartLink, chatPollLink, chatUnlink, chatInfo, chatConfirm, totpBegin, totpEnable, totpDisable, makeRecovery, reset, enabledSubjects };
}
