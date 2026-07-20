// Служебный скрипт (v2): расшифровывает data/employees.json.enc в stdout.
// Запуск:  SIG_EMAIL='email' SIG_PASSWORD='код доступа' node tools/decrypt-data.mjs
import { deriveKeys, decryptString, importEncKey } from '../js/crypto.js';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const password = process.env.SIG_PASSWORD;
const email = (process.env.SIG_EMAIL || '').toLowerCase();
if (!password || !email) {
  console.error("Запуск: SIG_EMAIL='email' SIG_PASSWORD='код' node tools/decrypt-data.mjs");
  process.exit(1);
}

const doc = JSON.parse(readFileSync(join(root, 'data/users.json'), 'utf8'));
const user = doc.users.find((u) => (u.email || '').toLowerCase() === email);
if (!user) { console.error('Пользователь не найден.'); process.exit(2); }

const derived = await deriveKeys(password, user.salt, doc.kdf.iterations);
if (derived.verifier !== user.verifier) { console.error('Неверный код доступа.'); process.exit(2); }

const dataKeyRaw = await decryptString(derived.encKey, JSON.stringify(user.encDataKey));
const dataKey = await importEncKey(dataKeyRaw);
console.log(await decryptString(dataKey, readFileSync(join(root, 'data/employees.json.enc'), 'utf8')));
