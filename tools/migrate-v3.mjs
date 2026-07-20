// Миграция v2 → v3: у сотрудника появляются loginEmail (для входа)
// и массив подписей signatures: [{templateId, email}] вместо email+templateId.
// Запуск:  SIG_EMAIL='email админа' SIG_PASSWORD='пароль' node tools/migrate-v3.mjs
import { deriveKeys, decryptString, encryptString, importEncKey } from '../js/crypto.js';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const password = process.env.SIG_PASSWORD;
const email = (process.env.SIG_EMAIL || '').toLowerCase();
if (!password || !email) {
  console.error("Запуск: SIG_EMAIL='email' SIG_PASSWORD='пароль' node tools/migrate-v3.mjs");
  process.exit(1);
}

const doc = JSON.parse(readFileSync(join(root, 'data/users.json'), 'utf8'));
const user = doc.users.find((u) => (u.email || '').toLowerCase() === email);
const derived = await deriveKeys(password, user.salt, doc.kdf.iterations);
if (derived.verifier !== user.verifier) { console.error('Неверный пароль.'); process.exit(2); }
const dataKeyRaw = await decryptString(derived.encKey, JSON.stringify(user.encDataKey));
const dataKey = await importEncKey(dataKeyRaw);

const empPath = join(root, 'data/employees.json.enc');
const data = JSON.parse(await decryptString(dataKey, readFileSync(empPath, 'utf8')));

for (const e of data.employees) {
  if (!e.loginEmail) e.loginEmail = e.email || '';
  if (!Array.isArray(e.signatures) || !e.signatures.length) {
    e.signatures = [{ templateId: e.templateId || 'estatecrm-main', email: e.email || e.loginEmail }];
  }
  delete e.email;
  delete e.templateId;
}
data.v = 3;

writeFileSync(empPath, await encryptString(dataKey, JSON.stringify(data, null, 2)) + '\n');
console.log(`Мигрировано сотрудников: ${data.employees.length}`);
for (const e of data.employees) {
  console.log(`- ${e.firstName} ${e.lastName}: вход ${e.loginEmail}, подписи: ${e.signatures.map((s) => s.templateId + ' <' + s.email + '>').join(', ')}`);
}
