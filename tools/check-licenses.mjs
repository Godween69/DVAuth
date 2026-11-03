// Проверка лицензий зависимостей. Проект распространяется под AGPL-3.0, поэтому в нём допустимо всё, что с ним совместимо.
// Политика:
//   разрешены без оговорок: MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, MPL-2.0;
//   разрешены, но видны в отчёте: ISC, 0BSD и подобные свободные лицензии;
//   копилефт, совместимый с AGPL-3.0, виден отдельным списком: LGPL-3.0, GPL-3.0, AGPL-3.0, LGPL-2.1-or-later, GPL-2.0-or-later;
//   ошибка: GPL-2.0-only, LGPL-2.1-only (несовместимы с AGPL-3.0), несвободные и неизвестные лицензии, пакет без лицензии.
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ALLOWED = new Set(['MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', 'MPL-2.0']);
const VISIBLE = new Set(['ISC', '0BSD', 'BlueOak-1.0.0', 'Unlicense', 'CC0-1.0', 'Python-2.0', 'CC-BY-4.0']);
const COPYLEFT_OK = new Set([
  'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'LGPL-2.1-or-later', 'GPL-2.0-or-later',
]);

// Правило для одного SPDX-идентификатора: 'ok' | 'visible' | 'copyleft' | 'bad'
function rate(id) {
  const x = id.replace(/\+$/, '');
  if (ALLOWED.has(x)) return 'ok';
  if (VISIBLE.has(x)) return 'visible';
  if (COPYLEFT_OK.has(x)) return 'copyleft';
  return 'bad';
}

// Выражение вида "(MIT OR Apache-2.0)" или "MIT AND ISC": OR — лучшее из вариантов, AND — худшее.
export function rateExpression(expr) {
  const order = { ok: 0, visible: 1, copyleft: 2, bad: 3 };
  const s = String(expr || '').trim().replace(/^\(|\)$/g, '');
  if (!s) return 'bad';
  const ors = s.split(/\s+OR\s+/i).map((part) => {
    const ands = part.replace(/[()]/g, '').split(/\s+AND\s+/i).map((i) => rate(i.trim()));
    return ands.sort((a, b) => order[b] - order[a])[0];
  });
  return ors.sort((a, b) => order[a] - order[b])[0];
}

function* walk(dir) {
  if (!existsSync(dir)) return;
  for (const name of readdirSync(dir)) {
    if (name.startsWith('.')) continue;
    const p = join(dir, name);
    if (name.startsWith('@')) {
      yield* walk(p);
      continue;
    }
    const pj = join(p, 'package.json');
    if (existsSync(pj)) {
      yield JSON.parse(readFileSync(pj, 'utf8'));
      yield* walk(join(p, 'node_modules'));
    }
  }
}

function licenseOf(pkg) {
  if (typeof pkg.license === 'string') return pkg.license;
  if (pkg.license && typeof pkg.license.type === 'string') return pkg.license.type;
  if (Array.isArray(pkg.licenses)) return pkg.licenses.map((l) => l.type).join(' OR ');
  return '';
}

export function check(root) {
  const seen = new Map();
  for (const pkg of walk(join(root, 'node_modules'))) {
    if (!pkg.name || !pkg.version || pkg.name.startsWith('@dvcloud/')) continue;
    seen.set(`${pkg.name}@${pkg.version}`, licenseOf(pkg));
  }
  const visible = [];
  const copyleft = [];
  const bad = [];
  const counts = {};
  for (const [id, lic] of [...seen].sort()) {
    const r = rateExpression(lic);
    counts[lic || '(нет)'] = (counts[lic || '(нет)'] ?? 0) + 1;
    if (r === 'visible') visible.push(`${id}  ${lic}`);
    if (r === 'copyleft') copyleft.push(`${id}  ${lic}`);
    if (r === 'bad') bad.push(`${id}  ${lic || '(лицензия не указана)'}`);
  }
  return { total: seen.size, counts, visible, copyleft, bad };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const root = process.argv[2] ?? process.cwd();
  const { total, counts, visible, copyleft, bad } = check(root);
  console.log(`Пакетов проверено: ${total}`);
  for (const [k, v] of Object.entries(counts).sort((a, b) => b[1] - a[1])) console.log(`  ${k}: ${v}`);
  if (visible.length) console.log(`\nТребуют внимания (разрешены, но видны в отчёте): ${visible.length}\n  ${visible.join('\n  ')}`);
  if (copyleft.length) console.log(`\nКопилефт, совместимый с AGPL-3.0: ${copyleft.length}\n  ${copyleft.join('\n  ')}`);
  if (bad.length) {
    console.error(`\nЗАПРЕЩЕНО или неизвестно: ${bad.length}\n  ${bad.join('\n  ')}`);
    process.exit(1);
  }
  console.log('\nЛицензии в порядке.');
}
