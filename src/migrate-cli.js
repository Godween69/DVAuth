// SPDX-License-Identifier: AGPL-3.0-only
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { migrate } from './migrate.js';

const url = process.env.DVAUTH_DATABASE_URL;
if (!url) {
  console.error('Не задан DVAUTH_DATABASE_URL');
  process.exit(1);
}
const client = new pg.Client({ connectionString: url });
try {
  await client.connect();
  const applied = await migrate(client, fileURLToPath(new URL('../migrations', import.meta.url)));
  console.log(applied.length ? `Применено: ${applied.join(', ')}` : 'Новых миграций нет');
} catch (e) {
  console.error(e.message);
  process.exitCode = 1;
} finally {
  await client.end();
}
