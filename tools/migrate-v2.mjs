// Миграция v1 → v2 (многопользовательский режим).
// Запуск:  SIG_PASSWORD='пароль администратора' node tools/migrate-v2.mjs
//
// Что делает:
// - расшифровывает employees.json.enc старым ключом (из пароля администратора);
// - генерирует общий dataKey (AES-256) и перешифровывает employees им;
// - создаёт data/users.json с администратором (email a.balanov@estatecrm.io,
//   пароль ПРЕЖНИЙ — соль и верификатор переносятся из auth.json);
// - удаляет устаревший data/auth.json.
import {
  deriveKeys, decryptJson, encryptJson, encryptString, b64encode, randomBytes, importEncKey,
} from '../js/crypto.js';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const password = process.env.SIG_PASSWORD;
if (!password) {
  console.error('Задайте пароль администратора: SIG_PASSWORD=... node tools/migrate-v2.mjs');
  process.exit(1);
}

const authPath = join(root, 'data/auth.json');
const usersPath = join(root, 'data/users.json');
if (!existsSync(authPath)) {
  console.error('data/auth.json не найден — миграция уже выполнена?');
  process.exit(1);
}

const auth = JSON.parse(readFileSync(authPath, 'utf8'));
const derived = await deriveKeys(password, auth.salt, auth.iterations);
if (derived.verifier !== auth.verifier) {
  console.error('Неверный пароль администратора.');
  process.exit(2);
}

const employees = await decryptJson(derived.encKey, readFileSync(join(root, 'data/employees.json.enc'), 'utf8'));
console.log(`Расшифровано сотрудников: ${employees.employees.length}`);

const dataKeyRaw = b64encode(randomBytes(32));
const dataKey = await importEncKey(dataKeyRaw);

writeFileSync(join(root, 'data/employees.json.enc'), await encryptJson(dataKey, employees) + '\n');
console.log('employees.json.enc перешифрован новым dataKey.');

const ADMIN_EMAIL = process.env.SIG_ADMIN_EMAIL || 'a.balanov@estatecrm.io';
const admin = employees.employees.find(
  (e) => (e.email || '').toLowerCase() === ADMIN_EMAIL.toLowerCase()
);
if (!admin) {
  console.error(`Сотрудник-администратор ${ADMIN_EMAIL} не найден в базе.`);
  process.exit(1);
}
const usersDoc = {
  v: 2,
  kdf: { iterations: auth.iterations },
  users: [
    {
      id: 'u-' + [...randomBytes(4)].map((b) => b.toString(16).padStart(2, '0')).join(''),
      employeeId: admin.id,
      email: admin.email,
      displayName: `${admin.firstName} ${admin.lastName}`,
      role: 'admin',
      salt: auth.salt,           // прежняя соль — пароль администратора не меняется
      verifier: auth.verifier,
      encDataKey: JSON.parse(await encryptString(derived.encKey, dataKeyRaw)),
      invitedAt: new Date().toISOString().slice(0, 10),
    },
  ],
  encToken: null, // GitHub-токен добавит администратор через интерфейс
};
writeFileSync(usersPath, JSON.stringify(usersDoc, null, 2) + '\n');
console.log(`data/users.json создан (администратор: ${admin.email}).`);

unlinkSync(authPath);
console.log('data/auth.json удалён. Миграция завершена.');
