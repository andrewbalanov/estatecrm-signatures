// Служебный скрипт (v2): создаёт data/users.json и data/employees.json.enc с нуля.
// Использовать только для полной переинициализации (все коды доступа сбрасываются!).
// Запуск:  SIG_EMAIL='email админа' SIG_PASSWORD='код' node tools/init-data.mjs [seed.json]
import {
  deriveKeys, encryptJson, encryptString, b64encode, randomBytes, importEncKey,
} from '../js/crypto.js';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const password = process.env.SIG_PASSWORD;
const email = process.env.SIG_EMAIL;
if (!password || !email) {
  console.error("Запуск: SIG_EMAIL='email' SIG_PASSWORD='код' node tools/init-data.mjs [seed.json]");
  process.exit(1);
}

const ITERATIONS = 600000;
const seed = process.argv[2]
  ? JSON.parse(readFileSync(process.argv[2], 'utf8'))
  : { employees: [] };

const dataKeyRaw = b64encode(randomBytes(32));
const dataKey = await importEncKey(dataKeyRaw);
writeFileSync(join(root, 'data/employees.json.enc'), await encryptJson(dataKey, seed) + '\n');

const salt = b64encode(randomBytes(16));
const derived = await deriveKeys(password, salt, ITERATIONS);
const adminEmp = seed.employees[0];
const usersDoc = {
  v: 2,
  kdf: { iterations: ITERATIONS },
  users: [
    {
      id: 'u-' + [...randomBytes(4)].map((b) => b.toString(16).padStart(2, '0')).join(''),
      employeeId: adminEmp ? adminEmp.id : null,
      email,
      displayName: adminEmp ? `${adminEmp.firstName} ${adminEmp.lastName}` : email,
      role: 'admin',
      salt,
      verifier: derived.verifier,
      encDataKey: JSON.parse(await encryptString(derived.encKey, dataKeyRaw)),
      invitedAt: new Date().toISOString().slice(0, 10),
    },
  ],
  encToken: null,
};
writeFileSync(join(root, 'data/users.json'), JSON.stringify(usersDoc, null, 2) + '\n');
console.log(`Инициализировано: ${seed.employees.length} сотр., администратор ${email}.`);
