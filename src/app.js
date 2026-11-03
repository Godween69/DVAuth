// SPDX-License-Identifier: AGPL-3.0-only
// Два слушателя: внутренний (API для приложений, по секрету приложения) и публичный (только приложение чата).
import { timingSafeEqual, createHash } from 'node:crypto';
import { ApiError, createApp, open, optStr, str } from './http.js';

function clientIp(req, trust) {
  if (trust > 0) {
    const parts = String(req.headers['x-forwarded-for'] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    const ip = parts[parts.length - trust];
    if (ip) return ip.slice(0, 64);
  }
  return String(req.socket.remoteAddress ?? 'unknown').slice(0, 64);
}

export function createInternalApp(cfg, svc) {
  // Приложение узнаётся по секрету; дальше все запросы ограничены его client.
  const auth = (req) => {
    const m = /^Bearer (.{32,200})$/.exec(String(req.headers.authorization ?? ''));
    const h = createHash('sha256').update(m ? m[1] : '').digest();
    let found = null;
    for (const c of cfg.clients) if (timingSafeEqual(h, c.secretHash) && m) found = c;
    if (!found) throw new ApiError(401, 'unauthorized', 'Неверный секрет приложения');
    return found.id;
  };
  const sub = (b) => str(b, 'subject', 1, 128);
  const ip = (b) => optStr(b, 'ip', 0, 64) || 'unknown';
  const routes = {
    'GET /health': open(() => ({ status: 'ok', service: 'dvauth-internal' })),
    'GET /v1/status': ({ query, ctx }) => svc.status(ctx, str(Object.fromEntries(query), 'subject', 1, 128)),
    'GET /v1/subjects': ({ ctx }) => svc.enabledSubjects(ctx),
    'POST /v1/login/begin': ({ body, ctx }) => svc.loginBegin(ctx, sub(body), ip(body)),
    'POST /v1/login/code': ({ body, ctx }) => svc.loginCode(ctx, str(body, 'ticket', 20, 64), str(body, 'code', 1, 40), ip(body)),
    'POST /v1/login/chat/start': ({ body, ctx }) => svc.chatStartLogin(ctx, str(body, 'ticket', 20, 64), ip(body), optStr(body, 'agent', 0, 500)),
    'POST /v1/login/chat/status': ({ body, ctx }) => svc.chatPollLogin(ctx, str(body, 'ticket', 20, 64)),
    'POST /v1/check': ({ body, ctx }) => svc.check(ctx, sub(body), str(body, 'code', 1, 40), ip(body)),
    'POST /v1/totp/begin': ({ body, ctx }) => svc.totpBegin(ctx, sub(body), optStr(body, 'label', 0, 64)),
    'POST /v1/totp/enable': ({ body, ctx }) => svc.totpEnable(ctx, sub(body), str(body, 'code', 6, 6)),
    'POST /v1/totp/disable': ({ body, ctx }) => svc.totpDisable(ctx, sub(body)),
    'POST /v1/recovery/new': async ({ body, ctx }) => ({ recoveryCodes: await svc.makeRecovery(ctx, sub(body)) }),
    'POST /v1/chat/link/start': ({ body, ctx }) => svc.chatStartLink(ctx, sub(body), ip(body), optStr(body, 'agent', 0, 500)),
    'POST /v1/chat/link/status': ({ body, ctx }) => svc.chatPollLink(ctx, sub(body)),
    'POST /v1/chat/unlink': ({ body, ctx }) => svc.chatUnlink(ctx, sub(body)),
    'POST /v1/reset': ({ body, ctx }) => svc.reset(ctx, sub(body)),
  };
  return createApp({ routes, auth });
}

export function createPublicApp(cfg, svc) {
  const routes = {
    'GET /health': open(() => ({ status: 'ok', service: 'dvauth' })),
    // Экран подтверждения в приложении чата: кто и откуда просит вход.
    'GET /v1/chat/info': open(({ query }) => svc.chatInfo(str(Object.fromEntries(query), 'challenge', 8, 64))),
    'POST /v1/chat/confirm': open(({ body, req }) =>
      svc.chatConfirm(str(body, 'challenge', 8, 64), str(body, 'number', 1, 8), str(body, 'openid', 8, 512), clientIp(req, cfg.trustProxy)),
    ),
  };
  return createApp({ routes, auth: () => null });
}
