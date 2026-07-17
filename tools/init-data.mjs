// Служебный скрипт: генерирует data/auth.json и шифрует data/employees.json.enc.
// Запуск:  SIG_PASSWORD='пароль' node tools/init-data.mjs [seed.json]
// seed.json — файл вида {"employees":[...]}; без него берётся пустой список.
// Пароль передаётся только через переменную окружения и нигде не сохраняется.
import { deriveKeys, encryptJson, b64encode, randomBytes } from '../js/crypto.js';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const password = process.env.SIG_PASSWORD;
if (!password) {
  console.error('Задайте пароль: SIG_PASSWORD=... node tools/init-data.mjs');
  process.exit(1);
}

const ITERATIONS = 600000;
const authPath = join(root, 'data/auth.json');

// Если auth.json уже существует — используем его соль (смена данных без смены пароля).
let salt, iterations = ITERATIONS;
if (existsSync(authPath) && !process.env.SIG_RESET) {
  const existing = JSON.parse(readFileSync(authPath, 'utf8'));
  salt = existing.salt;
  iterations = existing.iterations;
} else {
  salt = b64encode(randomBytes(16));
}

const { encKey, verifier } = await deriveKeys(password, salt, iterations);

writeFileSync(authPath, JSON.stringify({ v: 1, salt, iterations, verifier }, null, 2) + '\n');
console.log('data/auth.json записан.');

const seedFile = process.argv[2];
const seed = seedFile
  ? JSON.parse(readFileSync(seedFile, 'utf8'))
  : { employees: [] };
writeFileSync(join(root, 'data/employees.json.enc'), await encryptJson(encKey, seed) + '\n');
console.log(`data/employees.json.enc записан (${seed.employees.length} сотр.).`);
