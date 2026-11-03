// SPDX-License-Identifier: AGPL-3.0-only
// Проверка личности через Matrix OpenID: приложение чата получает у своего сервера одноразовый токен
// и отдаёт его сюда; мы спрашиваем у Synapse, чей это токен. Токен доступа и пароль чата сервису не передаются.
// Адрес Synapse берётся только из настроек, никогда из запроса.
import { ApiError } from './http.js';

export function createMatrix(cfg, fetchFn = fetch) {
  const enabled = cfg.matrixUrl !== '' && cfg.matrixServer !== '';
  async function whoIs(token) {
    if (!enabled) return null;
    if (typeof token !== 'string' || token.length < 8 || token.length > 512 || /[^\x21-\x7e]/.test(token)) return null;
    let res;
    try {
      res = await fetchFn(`${cfg.matrixUrl}/_matrix/federation/v1/openid/userinfo?access_token=${encodeURIComponent(token)}`, { signal: AbortSignal.timeout(5000) });
    } catch {
      throw new ApiError(503, 'unavailable', 'Чат сейчас недоступен. Используйте код из приложения или запасной код.');
    }
    if (res.status >= 500) throw new ApiError(503, 'unavailable', 'Чат сейчас недоступен. Используйте код из приложения или запасной код.');
    if (!res.ok) return null;
    let sub;
    try {
      sub = (await res.json()).sub;
    } catch {
      return null;
    }
    if (typeof sub !== 'string') return null;
    const m = /^@([^:\s]{1,255}):([^\s]{1,255})$/.exec(sub);
    if (!m || m[2].toLowerCase() !== cfg.matrixServer.toLowerCase()) return null;
    return sub;
  }
  return { enabled, whoIs };
}
