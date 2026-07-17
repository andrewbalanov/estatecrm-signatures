// Служебный скрипт: расшифровывает data/employees.json.enc в stdout.
// Запуск:  SIG_PASSWORD='пароль' node tools/decrypt-data.mjs
import { deriveKeys, decryptString } from '../js/crypto.js';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const password = process.env.SIG_PASSWORD;
if (!password) {
  console.error('Задайте пароль: SIG_PASSWORD=... node tools/decrypt-data.mjs');
  process.exit(1);
}

const auth = JSON.parse(readFileSync(join(root, 'data/auth.json'), 'utf8'));
const { encKey, verifier } = await deriveKeys(password, auth.salt, auth.iterations);
if (verifier !== auth.verifier) {
  console.error('Неверный пароль.');
  process.exit(2);
}
const payload = readFileSync(join(root, 'data/employees.json.enc'), 'utf8');
console.log(await decryptString(encKey, payload));
