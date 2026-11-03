// SPDX-License-Identifier: AGPL-3.0-only
// Простые SQL-миграции без ORM: файлы NNNN_имя.sql по порядку, каждая в транзакции.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const NAME_RE = /^\d{4}_[a-z0-9_]+\.sql$/;

export async function migrate(client, dir) {
  await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
  const done = new Set((await client.query('SELECT name FROM schema_migrations')).rows.map((r) => r.name));
  const applied = [];
  for (const name of readdirSync(dir).filter((f) => NAME_RE.test(f)).sort()) {
    if (done.has(name)) continue;
    await client.query('BEGIN');
    try {
      await client.query(readFileSync(join(dir, name), 'utf8'));
      await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [name]);
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw new Error(`Миграция ${name} не применилась: ${e.message}`);
    }
    applied.push(name);
  }
  return applied;
}
