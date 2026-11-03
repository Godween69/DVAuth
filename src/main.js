// SPDX-License-Identifier: AGPL-3.0-only
import pg from 'pg';
import { createInternalApp, createPublicApp } from './app.js';
import { loadConfig } from './config.js';
import { createMatrix } from './matrix.js';
import { createService } from './service.js';

try {
  const cfg = loadConfig();
  const db = new pg.Pool({ connectionString: cfg.databaseUrl, max: 5 });
  const svc = createService({ db, cfg, matrix: createMatrix(cfg) });
  const pub = createPublicApp(cfg, svc);
  const internal = createInternalApp(cfg, svc);
  await new Promise((ok) => pub.listen(cfg.port, cfg.host, ok));
  await new Promise((ok) => internal.listen(cfg.internalPort, cfg.internalHost, ok));
  console.log(`DV Auth: публичный ${cfg.host}:${cfg.port}, внутренний ${cfg.internalHost}:${cfg.internalPort}, приложений: ${cfg.clients.length}`);
  for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { pub.close(); internal.close(); db.end().finally(() => process.exit(0)); });
} catch (e) {
  console.error(e.message);
  process.exit(1);
}
