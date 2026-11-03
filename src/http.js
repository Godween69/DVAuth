// SPDX-License-Identifier: AGPL-3.0-only
// Крошечный HTTP-каркас без зависимостей: маршруты, JSON, ошибки, заголовки безопасности.
import { createServer } from 'node:http';

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  'referrer-policy': 'no-referrer',
};
const MAX_BODY = 16 * 1024;

async function readJson(req) {
  if (!String(req.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
    throw new ApiError(415, 'bad_request', 'Нужен Content-Type: application/json');
  }
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY) throw new ApiError(413, 'bad_request', 'Тело запроса слишком большое');
    chunks.push(c);
  }
  let v;
  try {
    v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  } catch {
    throw new ApiError(400, 'bad_request', 'Неверный JSON');
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new ApiError(400, 'bad_request', 'Ожидается JSON-объект');
  return v;
}

// Проверки полей: строка нужной длины.
export function str(o, name, min, max) {
  const v = o[name];
  if (typeof v !== 'string' || v.length < min || v.length > max) throw new ApiError(400, 'bad_request', `Поле ${name}: строка длиной от ${min} до ${max}`);
  return v;
}
export const optStr = (o, name, min, max) => (o[name] === undefined ? '' : str(o, name, min, max));

// routes: { 'GET /path': async ({ body, query, req, ctx }) => объект }. auth(req) вернёт контекст или бросит ApiError.
export function createApp({ routes, auth }) {
  return createServer(async (req, res) => {
    const send = (status, obj) => {
      res.writeHead(status, HEADERS);
      res.end(JSON.stringify(obj));
    };
    try {
      const url = new URL(req.url ?? '/', 'http://x');
      const handler = routes[`${req.method} ${url.pathname}`];
      if (!handler) throw new ApiError(404, 'not_found', 'Нет такого адреса');
      const ctx = handler.open ? null : await auth(req);
      const body = req.method === 'POST' ? await readJson(req) : {};
      const out = await (handler.fn ?? handler)({ body, query: url.searchParams, req, ctx });
      send(200, out ?? { ok: true });
    } catch (e) {
      if (e instanceof ApiError) return send(e.status, { error: e.code, message: e.message });
      console.error('Внутренняя ошибка:', e?.message ?? e);
      send(500, { error: 'internal', message: 'Внутренняя ошибка' });
    }
  });
}

export const open = (fn) => Object.assign(fn, { open: true, fn });
