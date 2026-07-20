// Основная логика интерфейса (v3 — приглашения по ссылке, несколько подписей).
//
// Криптосхема («конверт»):
//   dataKey (случайный AES-256) шифрует employees.json.enc и GitHub-токен (encToken).
//   Для каждого пользователя dataKey зашифрован его личным ключом, выведенным
//   из пароля (PBKDF2). У приглашённого до установки пароля роль конверта играет
//   invite-токен из персональной ссылки: открыв её, сотрудник сам ставит пароль,
//   и одноразовый invite-конверт удаляется.
import { BASE_URL } from './config.js?v=15';
import * as cr from './crypto.js?v=15';
import { GitHubStore, DevStore, ReadOnlyStore } from './github.js?v=15';
import {
  NETWORKS, EMPLOYEE_FIELDS, renderSignature, renderPlainText, fullHtmlDocument,
  missingRequired, defaultTemplateConfig, escapeHtml,
} from './templates.js?v=15';
import { MAIL_CLIENTS, copyRichHtml, copyPlainText, downloadFile } from './clients.js?v=15';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const DEV = location.hash === '#dev';
const SESSION_KEY = 'ecsig.session2';
const LEGACY_TOKEN_KEY = 'ecsig.token';

const state = {
  session: null,      // { userId, dataKeyRaw }
  me: null,           // запись пользователя из users.json
  userKeyRaw: null,   // только в памяти сразу после входа (для миграции токена)
  dataKey: null,      // CryptoKey
  store: null,
  usersDoc: null,     // содержимое data/users.json
  employees: [],
  templates: [],
  inviteCtx: null,    // контекст принятия приглашения { me, doc, dataKeyRaw }
  editingId: null,
  editingTplId: null,
  pendingPhoto: null, // { blob, dataUrl } — обрезанное фото до сохранения
  pendingLogo: null,  // { blob, dataUrl, ratio } — логотип шаблона до сохранения
  cropper: null,
  cropBaseZoom: null,
  cropSourceUrl: null,
  cropTarget: 'emp',  // 'emp' (модал администратора) | 'my' (личный кабинет)
  sigEmployeeId: null,
  mySigs: [],         // рабочая копия подписей в личном кабинете
  mySigIndex: 0,
};

// ---------- Служебное ----------
let toastTimer = null;
function toast(msg, isErr = false, ms = 3500) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.toggle('err', isErr);
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), ms);
}

function hex8() {
  return [...cr.randomBytes(4)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Токен/код: 16 символов base58 (без похожих букв), ~93 бита энтропии.
function genCode() {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let s = '';
  while (s.length < 16) {
    for (const b of cr.randomBytes(24)) {
      if (b < 232 && s.length < 16) s += alphabet[b % 58]; // 232 = 4*58, без смещения
    }
  }
  return s.match(/.{4}/g).join('-');
}

function showScreen(name) {
  for (const id of ['login', 'setpass', 'token', 'main', 'my']) {
    $(`#screen-${id}`).classList.toggle('hidden', id !== name);
  }
}

function isAdmin() { return state.me && state.me.role === 'admin'; }

function setModeBadge() {
  const text = state.store && state.store.isDev
    ? 'ДЕМО-РЕЖИМ: изменения не сохраняются'
    : (state.store && !state.store.canWrite ? 'Только просмотр' : null);
  for (const id of ['#mode-badge', '#my-mode-badge']) {
    const badge = $(id);
    badge.textContent = text || '';
    badge.classList.toggle('hidden', !text);
  }
}

function busy(btn, on, label) {
  if (on) { btn.dataset.label = btn.textContent; btn.textContent = label || 'Подождите…'; btn.disabled = true; }
  else { btn.textContent = btn.dataset.label || btn.textContent; btn.disabled = false; }
}

async function encryptObjForDoc(key, str) {
  return JSON.parse(await cr.encryptString(key, str));
}
async function decryptObjFromDoc(key, obj) {
  return cr.decryptString(key, JSON.stringify(obj));
}

// ---------- Вход и приглашения ----------
async function fetchUsersDocPublic() {
  const res = await fetch(`data/users.json?t=${Date.now()}`, { cache: 'no-store' });
  if (!res.ok) throw new Error('Не удалось загрузить список пользователей');
  return res.json();
}

function parseInviteHash() {
  const m = location.hash.match(/^#invite=([A-Za-z0-9-]+)\.([A-Za-z0-9-]+)$/);
  return m ? { userId: m[1], token: m[2] } : null;
}

async function init() {
  const inv = parseInviteHash();
  if (inv) {
    await startInviteAccept(inv);
    return;
  }
  const saved = sessionStorage.getItem(SESSION_KEY);
  if (saved) {
    try {
      const session = JSON.parse(saved);
      const doc = await fetchUsersDocPublic();
      const me = doc.users.find((u) => u.id === session.userId);
      if (!me) throw new Error('Доступ отозван');
      state.session = session;
      state.me = me;
      state.usersDoc = doc;
      state.dataKey = await cr.importEncKey(session.dataKeyRaw);
      await afterLogin();
      return;
    } catch (e) {
      console.warn('Сессия не восстановлена:', e);
      sessionStorage.removeItem(SESSION_KEY);
    }
  }
  showScreen('login');
}

// Открыта персональная ссылка-приглашение: проверяем токен и предлагаем задать пароль.
async function startInviteAccept({ userId, token }) {
  showScreen('login');
  const errEl = $('#login-error');
  try {
    const doc = await fetchUsersDocPublic();
    const me = doc.users.find((u) => u.id === userId);
    if (!me || !me.invite) {
      throw new Error('Ссылка-приглашение недействительна или уже использована. Запросите новую у администратора.');
    }
    const derived = await cr.deriveKeys(token, me.invite.salt, doc.kdf.iterations);
    if (derived.verifier !== me.invite.verifier) {
      throw new Error('Ссылка-приглашение повреждена. Запросите новую у администратора.');
    }
    const dataKeyRaw = await decryptObjFromDoc(derived.encKey, me.invite.encDataKey);
    state.inviteCtx = { me, doc, dataKeyRaw };
    $('#setpass-name').textContent = me.displayName;
    $('#setpass-email').textContent = me.email;
    showScreen('setpass');
  } catch (e) {
    console.error(e);
    errEl.textContent = e.message;
    errEl.classList.remove('hidden');
  }
}

$('#setpass-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#setpass-btn');
  const errEl = $('#setpass-error');
  errEl.classList.add('hidden');
  const p1 = $('#setpass-p1').value;
  const p2 = $('#setpass-p2').value;
  if (p1.length < 10) {
    errEl.textContent = 'Пароль слишком короткий — нужно не меньше 10 символов.';
    errEl.classList.remove('hidden');
    return;
  }
  if (p1 !== p2) {
    errEl.textContent = 'Пароли не совпадают.';
    errEl.classList.remove('hidden');
    return;
  }
  busy(btn, true, 'Сохраняю…');
  try {
    const { me, doc, dataKeyRaw } = state.inviteCtx;
    const salt = cr.b64encode(cr.randomBytes(16));
    const derived = await cr.deriveKeys(p1, salt, doc.kdf.iterations);
    me.salt = salt;
    me.verifier = derived.verifier;
    me.encDataKey = await encryptObjForDoc(derived.encKey, dataKeyRaw);
    delete me.invite;

    state.usersDoc = doc;
    state.me = me;
    state.session = { userId: me.id, dataKeyRaw };
    state.dataKey = await cr.importEncKey(dataKeyRaw);

    await connectStore();
    if (!state.store || !state.store.canWrite) {
      throw new Error('Сохранение пароля недоступно — обратитесь к администратору.');
    }
    await saveUsers(`Установлен пароль: ${me.displayName}`);
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(state.session));
    history.replaceState(null, '', location.pathname + location.search);
    $('#setpass-p1').value = '';
    $('#setpass-p2').value = '';
    toast('Пароль сохранён — добро пожаловать!');
    await enterApp();
  } catch (err) {
    console.error(err);
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
  } finally {
    busy(btn, false);
  }
});

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#login-btn');
  const errEl = $('#login-error');
  errEl.classList.add('hidden');
  busy(btn, true, 'Проверяю…');
  try {
    const email = $('#login-email').value.trim().toLowerCase();
    const doc = await fetchUsersDocPublic();
    const me = doc.users.find((u) => (u.email || '').toLowerCase() === email);
    if (me && me.invite && !me.verifier) {
      errEl.textContent = 'Вы ещё не установили пароль — откройте персональную ссылку-приглашение.';
      errEl.classList.remove('hidden');
      return;
    }
    const derived = me
      ? await cr.deriveKeys($('#login-password').value, me.salt, doc.kdf.iterations)
      : null;
    if (!me || derived.verifier !== me.verifier) {
      errEl.textContent = 'Неверный email или пароль.';
      errEl.classList.remove('hidden');
      return;
    }
    const dataKeyRaw = await decryptObjFromDoc(derived.encKey, me.encDataKey);
    state.session = { userId: me.id, dataKeyRaw };
    state.me = me;
    state.usersDoc = doc;
    state.userKeyRaw = cr.b64encode(derived.encKeyRaw);
    state.dataKey = await cr.importEncKey(dataKeyRaw);
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(state.session));
    $('#login-password').value = '';
    await afterLogin();
  } catch (err) {
    console.error(err);
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
  } finally {
    busy(btn, false);
  }
});

async function connectStore() {
  if (DEV) { state.store = new DevStore(); return; }
  state.store = null;
  if (state.usersDoc.encToken) {
    try {
      const token = await decryptObjFromDoc(state.dataKey, state.usersDoc.encToken);
      const store = new GitHubStore(token);
      await store.validate();
      state.store = store;
    } catch (e) {
      console.warn('Сохранённый в репозитории токен не подошёл:', e);
    }
  }
}

async function afterLogin() {
  await connectStore();
  if (!state.store) {
    if (isAdmin()) {
      await tryLegacyTokenMigration();
    }
    if (!state.store) {
      if (isAdmin()) { showScreen('token'); return; }
      state.store = new ReadOnlyStore();
    }
  }
  await enterApp();
}

async function enterApp() {
  setModeBadge();
  await loadAll();
  const who = `${state.me.displayName} (${state.me.role === 'admin' ? 'админ' : 'пользователь'})`;
  $('#whoami').textContent = who;
  $('#my-whoami').textContent = who;
  if (isAdmin()) {
    showScreen('main');
  } else {
    fillMy();
    showScreen('my');
  }
}

// Токен из v1 хранился в localStorage, зашифрованный ключом администратора.
async function tryLegacyTokenMigration() {
  const legacy = localStorage.getItem(LEGACY_TOKEN_KEY);
  if (!legacy || !state.userKeyRaw) return;
  try {
    const userKey = await cr.importEncKey(state.userKeyRaw);
    const token = await cr.decryptString(userKey, legacy);
    const store = new GitHubStore(token);
    await store.validate();
    state.usersDoc.encToken = await encryptObjForDoc(state.dataKey, token);
    state.store = store;
    await saveUsers('Токен перенесён из локального хранилища администратора');
    localStorage.removeItem(LEGACY_TOKEN_KEY);
    toast('GitHub-токен перенесён в зашифрованное хранилище сервиса.');
  } catch (e) {
    console.warn('Миграция локального токена не удалась:', e);
  }
}

$('#token-save').addEventListener('click', async () => {
  const btn = $('#token-save');
  const errEl = $('#token-error');
  errEl.classList.add('hidden');
  const token = $('#token-input').value.trim();
  if (!token) { errEl.textContent = 'Вставьте токен.'; errEl.classList.remove('hidden'); return; }
  busy(btn, true, 'Проверяю токен…');
  try {
    const store = new GitHubStore(token);
    await store.validate();
    state.usersDoc.encToken = await encryptObjForDoc(state.dataKey, token);
    state.store = store;
    await saveUsers('Обновлён GitHub-токен сервиса');
    $('#token-input').value = '';
    toast('Сохранение подключено для всех сотрудников.');
    await enterApp();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
  } finally {
    busy(btn, false);
  }
});

$('#token-skip').addEventListener('click', async () => {
  // Не понижаем уже работающее подключение до «только просмотр»
  if (!(state.store && state.store.canWrite)) state.store = new ReadOnlyStore();
  await enterApp();
});

$('#token-back').addEventListener('click', () => {
  showScreen(isAdmin() ? 'main' : 'my');
});

$('#btn-token').addEventListener('click', () => {
  const working = !!(state.store && state.store.canWrite && !state.store.isDev);
  $('#token-status').classList.toggle('hidden', !working);
  $('#token-back').classList.remove('hidden');
  $('#token-error').classList.add('hidden');
  showScreen('token');
});

for (const id of ['#btn-logout', '#my-logout']) {
  $(id).addEventListener('click', () => {
    sessionStorage.removeItem(SESSION_KEY);
    location.reload();
  });
}

$('#btn-refresh').addEventListener('click', async () => { await loadAll(); toast('Данные обновлены.'); });
$('#my-refresh').addEventListener('click', async () => { await loadAll(); fillMy(); toast('Данные обновлены.'); });

// ---------- Данные ----------
// Страховка от старых клиентов/данных: у каждого сотрудника — loginEmail и signatures[].
function normalizeEmployees(list) {
  for (const e of list) {
    if (!e.loginEmail) e.loginEmail = e.email || '';
    if (!Array.isArray(e.signatures) || !e.signatures.length) {
      e.signatures = [{
        templateId: e.templateId || (state.templates[0] && state.templates[0].id),
        email: e.email || e.loginEmail,
      }];
    }
    delete e.email;
    delete e.templateId;
  }
  return list;
}

async function loadAll() {
  const usersFile = await state.store.getFile('data/users.json');
  if (usersFile) {
    state.usersDoc = JSON.parse(usersFile.text);
    state.me = state.usersDoc.users.find((u) => u.id === state.session.userId) || state.me;
  }

  const tplFile = await state.store.getFile('data/templates.json');
  if (!tplFile) throw new Error('Не найден data/templates.json');
  state.templates = JSON.parse(tplFile.text).templates;

  const empFile = await state.store.getFile('data/employees.json.enc');
  if (empFile) {
    const data = await cr.decryptJson(state.dataKey, empFile.text);
    state.employees = normalizeEmployees(data.employees || []);
  } else {
    state.employees = [];
  }
  if (isAdmin()) {
    renderEmployees();
    renderTemplatesTab();
    fillDeptFilter();
  }
}

async function saveEmployees(message) {
  const payload = await cr.encryptJson(state.dataKey, { v: 3, employees: state.employees });
  await state.store.putFile('data/employees.json.enc', payload, message);
}

async function saveUsers(message) {
  await state.store.putFile(
    'data/users.json',
    JSON.stringify(state.usersDoc, null, 2) + '\n',
    message
  );
}

async function saveTemplates(message) {
  await state.store.putFile(
    'data/templates.json',
    JSON.stringify({ templates: state.templates }, null, 2) + '\n',
    message
  );
}

// ---------- Вкладки (администратор) ----------
$$('.tab').forEach((btn) => btn.addEventListener('click', () => {
  $$('.tab').forEach((b) => b.classList.toggle('active', b === btn));
  $('#tab-employees').classList.toggle('hidden', btn.dataset.tab !== 'employees');
  $('#tab-templates').classList.toggle('hidden', btn.dataset.tab !== 'templates');
}));

// ---------- Список сотрудников (администратор) ----------
function templateById(id) {
  return state.templates.find((t) => t.id === id) || state.templates[0];
}

function userByEmployee(empId) {
  return state.usersDoc.users.find((u) => u.employeeId === empId);
}

function initials(emp) {
  return ((emp.firstName[0] || '') + (emp.lastName[0] || '')).toUpperCase();
}

function photoSrc(emp) {
  if (!emp.photo) return null;
  if (/^(https?:|blob:|data:)/.test(emp.photo)) return emp.photo;
  return emp.photo + (emp.photoVersion > 1 ? `?v=${emp.photoVersion}` : '');
}

// Представление сотрудника для конкретной подписи (email из подписи).
function sigView(emp, sig) {
  return { ...emp, email: (sig && sig.email) || emp.loginEmail };
}

function anySigNotReady(emp) {
  return emp.signatures.some((s) => missingRequired(templateById(s.templateId), sigView(emp, s)).length > 0);
}

function renderEmployees() {
  const q = $('#emp-search').value.trim().toLowerCase();
  const dept = $('#emp-dept-filter').value;
  const list = $('#emp-list');
  list.innerHTML = '';
  const filtered = state.employees.filter((e) => {
    if (dept && e.department !== dept) return false;
    if (!q) return true;
    return [e.firstName, e.lastName, e.position, e.loginEmail, e.department,
      ...e.signatures.map((s) => s.email)]
      .join(' ').toLowerCase().includes(q);
  });
  $('#emp-empty').classList.toggle('hidden', filtered.length > 0);
  for (const emp of filtered) {
    const row = document.createElement('div');
    row.className = 'emp-row';
    const src = photoSrc(emp);
    const user = userByEmployee(emp.id);
    const roleChip = user
      ? `<span class="role-chip ${user.role}">${user.role === 'admin' ? 'Админ' : 'Пользователь'}${user.invite ? ' · ждёт входа' : ''}</span>`
      : '<span class="role-chip none">Без доступа</span>';
    const tplNames = emp.signatures.map((s) => templateById(s.templateId)?.name || '—');
    row.innerHTML = `
      ${src ? `<img class="avatar" src="${src}" alt="">` : `<div class="avatar">${initials(emp)}</div>`}
      <div class="emp-info">
        <div class="emp-name"></div>
        <div class="emp-sub"></div>
      </div>
      ${anySigNotReady(emp) ? '<span class="role-chip none" title="Не заполнены обязательные поля">⚠ не готова</span>' : ''}
      ${roleChip}
      <span class="chip"></span>
      <div class="emp-actions">
        <button class="primary small act-sig">Подписи</button>
        <button class="secondary small act-edit">Изменить</button>
      </div>`;
    row.querySelector('.emp-name').textContent = `${emp.firstName} ${emp.lastName}`;
    row.querySelector('.emp-sub').textContent =
      [emp.position, emp.department, emp.loginEmail].filter(Boolean).join(' · ');
    row.querySelector('.chip').textContent = tplNames.join(' + ');
    row.querySelector('.act-sig').addEventListener('click', () => openSigModal(emp.id));
    row.querySelector('.act-edit').addEventListener('click', () => openEmpModal(emp.id));
    list.appendChild(row);
  }
}

function fillDeptFilter() {
  const sel = $('#emp-dept-filter');
  const current = sel.value;
  const depts = [...new Set(state.employees.map((e) => e.department).filter(Boolean))].sort();
  sel.innerHTML = '<option value="">Все отделы</option>' +
    depts.map((d) => `<option>${d}</option>`).join('');
  sel.value = depts.includes(current) ? current : '';
  $('#dept-list').innerHTML = depts.map((d) => `<option value="${d}">`).join('');
}

$('#emp-search').addEventListener('input', renderEmployees);
$('#emp-dept-filter').addEventListener('change', renderEmployees);
$('#btn-add-emp').addEventListener('click', () => openEmpModal(null));

// ---------- Редактор сотрудника (администратор) ----------
function renderSigRows(emp) {
  const wrap = $('#f-signatures');
  wrap.innerHTML = '';
  state.templates.forEach((tpl, idx) => {
    const sig = emp?.signatures?.find((s) => s.templateId === tpl.id);
    const row = document.createElement('div');
    row.className = 'sig-row';
    row.innerHTML = `
      <label class="cb"><input type="checkbox" class="sig-on" value="${tpl.id}"> <span></span></label>
      <input type="email" class="sig-email" placeholder="email в этой подписи — как для входа">`;
    row.querySelector('.cb span').textContent = tpl.name;
    const on = row.querySelector('.sig-on');
    const emailInput = row.querySelector('.sig-email');
    on.checked = emp ? !!sig : idx === 0; // у нового сотрудника — первый шаблон по умолчанию
    emailInput.value = sig?.email || '';
    emailInput.disabled = !on.checked;
    on.addEventListener('change', () => { emailInput.disabled = !on.checked; });
    wrap.appendChild(row);
  });
}

function openEmpModal(id) {
  state.editingId = id;
  state.pendingPhoto = null;
  state.cropSourceUrl = null;
  state.cropTarget = 'emp';
  const emp = state.employees.find((e) => e.id === id);
  const user = emp ? userByEmployee(emp.id) : null;
  $('#emp-form-title').textContent = emp ? 'Редактирование сотрудника' : 'Приглашение сотрудника';
  $('#f-firstName').value = emp?.firstName || '';
  $('#f-lastName').value = emp?.lastName || '';
  $('#f-position').value = emp?.position || '';
  $('#f-department').value = emp?.department || '';
  $('#f-mobile').value = emp?.mobile || '';
  $('#f-email').value = emp?.loginEmail || '';
  $('#f-linkedin').value = emp?.socials?.linkedin || '';
  renderSigRows(emp);
  $('#emp-delete').classList.toggle('hidden', !emp);
  $('#emp-photo-recrop').classList.add('hidden');
  $('#acc-none').classList.toggle('hidden', !!user);
  $('#acc-linked').classList.toggle('hidden', !user);
  $('#f-invite').checked = !emp;
  if (user) {
    $('#acc-email').textContent = user.email + (user.invite ? ' (ещё не установил пароль)' : '');
    $('#f-role2').value = user.role;
  }
  const prev = $('#emp-photo-preview');
  const src = emp ? photoSrc(emp) : null;
  prev.innerHTML = src ? `<img src="${src}" alt="">` : '<span>Фото</span>';
  $('#modal-emp').classList.remove('hidden');
}

function closeEmpModal() {
  $('#modal-emp').classList.add('hidden');
  if (state.cropper) { state.cropper.destroy(); state.cropper = null; }
}

$('#emp-cancel').addEventListener('click', closeEmpModal);

// Приглашение: одноразовый конверт dataKey под токеном из персональной ссылки.
// Пароль сотрудник придумает сам при первом входе.
async function createInvite(emp, role, existingUser) {
  const token = genCode();
  const salt = cr.b64encode(cr.randomBytes(16));
  const derived = await cr.deriveKeys(token, salt, state.usersDoc.kdf.iterations);
  const invite = {
    salt,
    verifier: derived.verifier,
    encDataKey: await encryptObjForDoc(derived.encKey, state.session.dataKeyRaw),
    createdAt: new Date().toISOString().slice(0, 10),
  };
  let user = existingUser;
  if (user) {
    delete user.salt;
    delete user.verifier;
    delete user.encDataKey;
    user.invite = invite;
    if (role) user.role = role;
    user.email = emp.loginEmail;
    user.displayName = `${emp.firstName} ${emp.lastName}`;
  } else {
    user = {
      id: 'u-' + hex8(),
      employeeId: emp.id,
      email: emp.loginEmail,
      displayName: `${emp.firstName} ${emp.lastName}`,
      role: role || 'user',
      invite,
      invitedAt: new Date().toISOString().slice(0, 10),
    };
    state.usersDoc.users.push(user);
  }
  return { user, link: `${BASE_URL}#invite=${user.id}.${token}` };
}

function inviteText(emp, link, role) {
  const sigNames = emp.signatures
    .map((s) => templateById(s.templateId)?.name).filter(Boolean);
  const lines = [
    `Здравствуйте, ${emp.firstName}!`,
    '',
    'Приглашаю вас в наш корпоративный сервис email-подписей.',
    '',
    'Ваша персональная ссылка для входа:',
    link,
    '',
    'Что сделать:',
    '1. Откройте ссылку и придумайте себе пароль.',
    '2. Проверьте свои данные и загрузите фотографию.',
    '3. Скопируйте готовую подпись для своей почтовой программы — инструкция будет на экране.',
  ];
  if (sigNames.length) {
    lines.push('', sigNames.length > 1
      ? `Для вас уже подготовлены подписи: ${sigNames.join(', ')}.`
      : `Для вас уже подготовлена подпись «${sigNames[0]}».`);
  }
  if (role === 'admin') {
    lines.push('',
      'Вам назначена роль администратора сервиса. Это значит, что вы можете:',
      '— приглашать новых сотрудников и удалять уволившихся;',
      '— видеть и редактировать подписи всех сотрудников;',
      '— создавать и настраивать шаблоны подписей (логотип, соцсети, обязательные поля).');
  }
  lines.push('', 'Ссылка персональная и одноразовая — пожалуйста, не пересылайте её другим.');
  return lines.join('\n');
}

function showInviteModal(emp, link, role) {
  $('#inv-name').textContent = `${emp.firstName} ${emp.lastName}`;
  $('#inv-email').textContent = emp.loginEmail;
  $('#inv-link').textContent = link;
  const subject = 'Приглашение в сервис email-подписей';
  const body = inviteText(emp, link, role);
  $('#inv-mailto').href =
    `mailto:${encodeURIComponent(emp.loginEmail)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  $('#inv-copy-text').onclick = async () => {
    await copyPlainText(body);
    toast('Текст приглашения со ссылкой скопирован — вставьте его в чат сотруднику.');
  };
  $('#inv-copy-link').onclick = async () => {
    await copyPlainText(link);
    toast('Ссылка скопирована.');
  };
  $('#modal-invite').classList.remove('hidden');
}

$('#inv-close').addEventListener('click', () => $('#modal-invite').classList.add('hidden'));

$('#emp-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.store.canWrite) { toast('Режим просмотра: сохранение недоступно.', true); return; }
  const btn = $('#emp-save');
  busy(btn, true, 'Сохраняю…');
  try {
    const loginEmail = $('#f-email').value.trim();
    const emailTaken = state.employees.some((x) => x.id !== state.editingId
      && (x.loginEmail || '').toLowerCase() === loginEmail.toLowerCase());
    if (emailTaken) throw new Error('Сотрудник с таким email для входа уже есть.');

    // Подписи из чекбоксов
    const sigs = [];
    $$('#f-signatures .sig-row').forEach((row) => {
      const on = row.querySelector('.sig-on');
      if (on.checked) {
        sigs.push({
          templateId: on.value,
          email: row.querySelector('.sig-email').value.trim() || loginEmail,
        });
      }
    });
    if (!sigs.length) throw new Error('Отметьте хотя бы одну подпись.');

    let emp = state.employees.find((x) => x.id === state.editingId);
    const isNew = !emp;
    if (isNew) {
      emp = { id: 'emp-' + hex8(), photoVersion: 0 };
      state.employees.push(emp);
    }
    emp.firstName = $('#f-firstName').value.trim();
    emp.lastName = $('#f-lastName').value.trim();
    emp.position = $('#f-position').value.trim();
    emp.department = $('#f-department').value.trim();
    emp.mobile = $('#f-mobile').value.trim();
    emp.loginEmail = loginEmail;
    emp.signatures = sigs;
    emp.socials = emp.socials || {};
    emp.socials.linkedin = $('#f-linkedin').value.trim();

    let photoUploaded = false;
    if (state.pendingPhoto) {
      if (state.store.isDev) {
        emp.photo = state.pendingPhoto.dataUrl;
      } else {
        const path = `assets/photos/${emp.id}.jpg`;
        const bytes = new Uint8Array(await state.pendingPhoto.blob.arrayBuffer());
        await state.store.putFile(path, bytes, `Фото: ${emp.firstName} ${emp.lastName}`);
        emp.photo = path;
        emp.photoVersion = (emp.photoVersion || 0) + 1;
        photoUploaded = true;
      }
    }

    // Доступ и роль
    const user = userByEmployee(emp.id);
    let inviteLink = null;
    let inviteRole = null;
    let usersChanged = false;
    if (user) {
      const newRole = $('#f-role2').value;
      if (user.role !== newRole || user.email !== emp.loginEmail
          || user.displayName !== `${emp.firstName} ${emp.lastName}`) {
        user.role = newRole;
        user.email = emp.loginEmail;
        user.displayName = `${emp.firstName} ${emp.lastName}`;
        usersChanged = true;
      }
    } else if ($('#f-invite').checked) {
      const role = $('#f-role').value;
      const created = await createInvite(emp, role, null);
      inviteLink = created.link;
      inviteRole = role;
      usersChanged = true;
    }

    await saveEmployees(`${isNew ? 'Добавлен' : 'Обновлён'} сотрудник: ${emp.firstName} ${emp.lastName}`);
    if (usersChanged) await saveUsers(`Доступы: ${emp.firstName} ${emp.lastName}`);

    renderEmployees();
    fillDeptFilter();
    closeEmpModal();
    if (inviteLink) {
      showInviteModal(emp, inviteLink, inviteRole);
    } else {
      toast(photoUploaded
        ? 'Сохранено. Фото станет доступно по публичной ссылке через ~1 минуту.'
        : 'Сохранено.');
    }
  } catch (err) {
    console.error(err);
    toast(err.message, true, 6000);
  } finally {
    busy(btn, false);
  }
});

$('#acc-reset').addEventListener('click', async () => {
  const emp = state.employees.find((x) => x.id === state.editingId);
  const user = emp && userByEmployee(emp.id);
  if (!user) return;
  if (!confirm(`Создать новую ссылку для входа для «${user.displayName}»? Текущий пароль перестанет действовать — сотрудник придумает новый по ссылке.`)) return;
  const btn = $('#acc-reset');
  busy(btn, true, 'Генерирую…');
  try {
    const { link } = await createInvite(emp, null, user);
    await saveUsers(`Новая ссылка для входа: ${user.displayName}`);
    closeEmpModal();
    showInviteModal(emp, link, user.role);
  } catch (err) {
    toast(err.message, true, 6000);
  } finally {
    busy(btn, false);
  }
});

$('#emp-delete').addEventListener('click', async () => {
  const emp = state.employees.find((x) => x.id === state.editingId);
  if (!emp) return;
  const user = userByEmployee(emp.id);
  const msg = user
    ? `Удалить сотрудника «${emp.firstName} ${emp.lastName}»? Его доступ в сервис будет отозван, фото удалено.`
    : `Удалить сотрудника «${emp.firstName} ${emp.lastName}»? Его фото также будет удалено.`;
  if (!confirm(msg)) return;
  const btn = $('#emp-delete');
  busy(btn, true, 'Удаляю…');
  try {
    if (emp.photo && !/^(blob:|data:)/.test(emp.photo) && !state.store.isDev) {
      await state.store.deleteFile(emp.photo, `Удалено фото: ${emp.firstName} ${emp.lastName}`);
    }
    state.employees = state.employees.filter((x) => x.id !== emp.id);
    await saveEmployees(`Удалён сотрудник: ${emp.firstName} ${emp.lastName}`);
    if (user) {
      state.usersDoc.users = state.usersDoc.users.filter((u) => u.id !== user.id);
      await saveUsers(`Отозван доступ: ${user.displayName}`);
    }
    renderEmployees();
    fillDeptFilter();
    closeEmpModal();
    toast('Сотрудник удалён.');
  } catch (err) {
    toast(err.message, true, 6000);
  } finally {
    busy(btn, false);
  }
});

// ---------- Обрезка фото (общая для админа и личного кабинета) ----------
function bindPhotoInput(inputSel, recropSel, target) {
  $(inputSel).addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      state.cropSourceUrl = reader.result;
      state.cropTarget = target;
      openCropModal(reader.result);
    };
    reader.readAsDataURL(file);
    e.target.value = '';
  });
  $(recropSel).addEventListener('click', () => {
    if (state.cropSourceUrl) { state.cropTarget = target; openCropModal(state.cropSourceUrl); }
  });
}
bindPhotoInput('#emp-photo-input', '#emp-photo-recrop', 'emp');
bindPhotoInput('#my-photo-input', '#my-photo-recrop', 'my');

function openCropModal(srcUrl) {
  $('#modal-crop').classList.remove('hidden');
  const img = $('#crop-image');
  if (state.cropper) { state.cropper.destroy(); state.cropper = null; }
  state.cropBaseZoom = null;
  $('#crop-zoom').value = 1;
  img.src = srcUrl;
  state.cropper = new Cropper(img, {
    aspectRatio: 1,
    viewMode: 1,
    dragMode: 'move',
    autoCropArea: 1,
    background: false,
    guides: false,
  });
}

// Базовый масштаб фиксируем при первом движении ползунка от фактического
// состояния канвы — момент ready ненадёжен (модал ещё в раскладке).
$('#crop-zoom').addEventListener('input', (e) => {
  if (!state.cropper) return;
  const cd = state.cropper.getCanvasData();
  if (!cd.naturalWidth) return;
  if (!state.cropBaseZoom) state.cropBaseZoom = cd.width / cd.naturalWidth;
  state.cropper.zoomTo(state.cropBaseZoom * parseFloat(e.target.value));
});

$('#crop-cancel').addEventListener('click', () => {
  $('#modal-crop').classList.add('hidden');
  if (state.cropper) { state.cropper.destroy(); state.cropper = null; }
});

$('#crop-apply').addEventListener('click', () => {
  if (!state.cropper) return;
  // 260×260 = 65px в подписи × 4 (запас для Retina-экранов)
  const canvas = state.cropper.getCroppedCanvas({ width: 260, height: 260, imageSmoothingQuality: 'high' });
  const dataUrl = canvas.toDataURL('image/jpeg', 0.9);
  canvas.toBlob((blob) => {
    state.pendingPhoto = { blob, dataUrl };
    const previewSel = state.cropTarget === 'my' ? '#my-photo-preview' : '#emp-photo-preview';
    const recropSel = state.cropTarget === 'my' ? '#my-photo-recrop' : '#emp-photo-recrop';
    $(previewSel).innerHTML = `<img src="${dataUrl}" alt="">`;
    $(recropSel).classList.remove('hidden');
    $('#modal-crop').classList.add('hidden');
    state.cropper.destroy();
    state.cropper = null;
    if (state.cropTarget === 'my') refreshMyPreview();
  }, 'image/jpeg', 0.9);
});

// ---------- Вкладка «Шаблоны» (администратор) ----------
const SAMPLE_EMPLOYEE = {
  firstName: 'Глеб', lastName: 'Цыганков', position: 'Управляющий партнер',
  mobile: '+7 915 122-25-25', loginEmail: 'g.tsygankov@estatecrm.io',
  department: 'Руководство', signatures: [],
  photo: 'assets/photos/emp-70a88b91.jpg', photoVersion: 1, socials: {},
};

function tplPreviewEmployee(tpl) {
  const sample = state.employees[0] || SAMPLE_EMPLOYEE;
  const sig = (sample.signatures || []).find((s) => s.templateId === tpl.id);
  return sigView(sample, sig);
}

function renderTemplatesTab() {
  const wrap = $('#tpl-list');
  wrap.innerHTML = '';
  for (const tpl of state.templates) {
    const card = document.createElement('div');
    card.className = 'tpl-card';
    const usedBy = state.employees
      .filter((e) => e.signatures.some((s) => s.templateId === tpl.id)).length;
    const sigHtml = renderSignature(tpl, tplPreviewEmployee(tpl), BASE_URL);
    const reqLabels = (tpl.config.required || [])
      .map((r) => EMPLOYEE_FIELDS.find((f) => f.id === r)?.label).filter(Boolean);
    card.innerHTML = `
      <div class="row space-between">
        <h3></h3>
        <div class="tpl-actions">
          <button class="secondary small tpl-edit">Настроить</button>
          <button class="secondary small tpl-dup">Дублировать</button>
        </div>
      </div>
      <p class="muted small-text">Используют: ${usedBy} сотр. ·
        Обязательные поля: ${reqLabels.length ? reqLabels.join(', ') : 'нет'}</p>
      <div class="tpl-preview"><iframe></iframe></div>
      <h4>Соцсети в подписи</h4>
      <div class="socials-grid"></div>
      <div class="row gap">
        <button class="primary tpl-socials-save">Сохранить соцсети</button>
        <span class="per-emp-note">«Личная ссылка» — если у сотрудника указан свой профиль, он подставится вместо общего.</span>
      </div>`;
    card.querySelector('h3').textContent = tpl.name;
    card.querySelector('iframe').srcdoc =
      `<!doctype html><meta charset="utf-8"><body style="margin:14px;background:#fff;">${sigHtml}</body>`;
    card.querySelector('.tpl-edit').addEventListener('click', () => openTplModal(tpl.id));
    card.querySelector('.tpl-dup').addEventListener('click', async (e) => {
      if (!state.store.canWrite) { toast('Режим просмотра: сохранение недоступно.', true); return; }
      busy(e.target, true, 'Копирую…');
      try {
        const copy = JSON.parse(JSON.stringify(tpl));
        copy.id = 'tpl-' + hex8();
        copy.name = `${tpl.name} (копия)`;
        state.templates.push(copy);
        await saveTemplates(`Дублирован шаблон: ${tpl.name}`);
        renderTemplatesTab();
        toast('Шаблон продублирован.');
      } catch (err) {
        toast(err.message, true, 6000);
      } finally {
        busy(e.target, false);
      }
    });

    const grid = card.querySelector('.socials-grid');
    for (const net of NETWORKS) {
      let s = (tpl.config.socials || []).find((x) => x.network === net.id);
      if (!s) {
        s = { network: net.id, enabled: false, url: '', perEmployee: false };
        tpl.config.socials = tpl.config.socials || [];
        tpl.config.socials.push(s);
      }
      const row = document.createElement('div');
      row.className = 'social-row';
      row.innerHTML = `
        <img src="${net.icon}" alt="">
        <label class="cb"><input type="checkbox" class="s-enabled"> вкл.</label>
        <input type="url" class="s-url" placeholder="https://…">
        <label class="cb" title="Использовать личную ссылку сотрудника, если она указана">
          <input type="checkbox" class="s-per"> личная</label>`;
      row.querySelector('.s-enabled').checked = !!s.enabled;
      row.querySelector('.s-url').value = s.url || '';
      row.querySelector('.s-per').checked = !!s.perEmployee;
      row.querySelector('.s-enabled').addEventListener('change', (ev) => { s.enabled = ev.target.checked; });
      row.querySelector('.s-url').addEventListener('input', (ev) => { s.url = ev.target.value.trim(); });
      row.querySelector('.s-per').addEventListener('change', (ev) => { s.perEmployee = ev.target.checked; });
      grid.appendChild(row);
    }

    card.querySelector('.tpl-socials-save').addEventListener('click', async (e) => {
      if (!state.store.canWrite) { toast('Режим просмотра: сохранение недоступно.', true); return; }
      busy(e.target, true, 'Сохраняю…');
      try {
        await saveTemplates(`Настройки соцсетей: ${tpl.name}`);
        renderTemplatesTab();
        toast('Настройки шаблона сохранены.');
      } catch (err) {
        toast(err.message, true, 6000);
      } finally {
        busy(e.target, false);
      }
    });
    wrap.appendChild(card);
  }
}

// ---------- Конструктор шаблона ----------
$('#btn-add-tpl').addEventListener('click', () => openTplModal(null));

function tplLogoPreviewSrc(cfg) {
  if (!cfg.logo || !cfg.logo.src) return null;
  if (/^(data:|blob:)/.test(cfg.logo.src)) return cfg.logo.src;
  return cfg.logo.src + (cfg.logo.v > 1 ? `?v=${cfg.logo.v}` : '');
}

function openTplModal(id) {
  state.editingTplId = id;
  state.pendingLogo = null;
  const tpl = state.templates.find((t) => t.id === id);
  const cfg = tpl ? tpl.config : defaultTemplateConfig();
  $('#tpl-form-title').textContent = tpl ? `Шаблон: ${tpl.name}` : 'Новый шаблон';
  const logoSrc = tplLogoPreviewSrc(cfg);
  $('#t-logo-preview').innerHTML = logoSrc
    ? `<img src="${logoSrc}" alt="">`
    : '<span class="muted">Нет логотипа</span>';
  $('#t-logo-enabled').checked = !!logoSrc;
  $('#t-logo-height').value = cfg.logo?.height || 32;
  $('#t-name').value = tpl ? tpl.name : '';
  $('#t-greeting').value = cfg.greeting || '';
  $('#t-companyName').value = cfg.companyName || '';
  $('#t-companyPhone').value = cfg.companyPhone || '';
  $('#t-webLabel').value = cfg.website?.label || '';
  $('#t-webUrl').value = cfg.website?.url || '';
  $('#t-accent').value = cfg.colors?.accent || '#1D325C';
  $('#t-text').value = cfg.colors?.text || '#212121';
  $('#t-btnEnabled').checked = !!cfg.button?.enabled;
  $('#t-btnUrl').value = cfg.button?.url || '';
  const usedBy = tpl
    ? state.employees.filter((e) => e.signatures.some((s) => s.templateId === tpl.id)).length
    : 0;
  const delBtn = $('#tpl-delete');
  delBtn.classList.toggle('hidden', !tpl);
  delBtn.disabled = usedBy > 0 || state.templates.length < 2;
  delBtn.title = usedBy > 0 ? 'Шаблон используется сотрудниками' : '';

  const reqWrap = $('#t-required');
  reqWrap.innerHTML = '';
  for (const f of EMPLOYEE_FIELDS) {
    const label = document.createElement('label');
    label.innerHTML = `<input type="checkbox" value="${f.id}"> ${f.label}`;
    label.querySelector('input').checked = (cfg.required || []).includes(f.id);
    reqWrap.appendChild(label);
  }
  $('#modal-tpl').classList.remove('hidden');
  tplPrevMode = 'desktop';
  $$('#tpl-prev-mode .seg').forEach((b) => b.classList.toggle('active', b.dataset.mode === 'desktop'));
  refreshTplPreview();
}

$('#tpl-cancel').addEventListener('click', () => $('#modal-tpl').classList.add('hidden'));

// Живой предпросмотр конструктора: шаблон собирается из текущих значений формы.
function tplFormTemplate() {
  const existing = state.templates.find((t) => t.id === state.editingTplId);
  const cfg = JSON.parse(JSON.stringify(existing ? existing.config : defaultTemplateConfig()));
  cfg.greeting = $('#t-greeting').value.trim();
  cfg.companyName = $('#t-companyName').value.trim();
  cfg.companyPhone = $('#t-companyPhone').value.trim();
  cfg.website = { label: $('#t-webLabel').value.trim(), url: $('#t-webUrl').value.trim() };
  cfg.colors = { accent: $('#t-accent').value, text: $('#t-text').value };
  cfg.button = cfg.button || defaultTemplateConfig().button;
  cfg.button.enabled = $('#t-btnEnabled').checked;
  cfg.button.url = $('#t-btnUrl').value.trim();
  const h = Math.max(20, Math.min(60, parseInt($('#t-logo-height').value, 10) || 32));
  if (!$('#t-logo-enabled').checked) {
    cfg.logo = null;
  } else if (state.pendingLogo) {
    cfg.logo = {
      src: state.pendingLogo.dataUrl,
      width: Math.round(state.pendingLogo.ratio * h),
      height: h,
      alt: $('#t-name').value.trim(),
      href: cfg.website.url || '#',
    };
  } else if (cfg.logo && cfg.logo.src) {
    const ratio = cfg.logo.width / cfg.logo.height;
    cfg.logo.height = h;
    cfg.logo.width = Math.round(ratio * h);
  }
  return {
    id: existing ? existing.id : 'tpl-preview',
    name: $('#t-name').value.trim() || 'Шаблон',
    renderer: existing ? existing.renderer : 'estatecrm-classic',
    config: cfg,
  };
}

let tplPrevMode = 'desktop';
let tplPreviewTimer = null;
function refreshTplPreview() {
  if ($('#modal-tpl').classList.contains('hidden')) return;
  const tpl = tplFormTemplate();
  const sample = tplPreviewEmployee(tpl);
  const html = renderSignature(tpl, sample, BASE_URL);
  setPreview($('#tpl-preview'), html, tplPrevMode, `${sample.firstName} ${sample.lastName}`);
}

for (const ev of ['input', 'change']) {
  $('#tpl-form').addEventListener(ev, () => {
    clearTimeout(tplPreviewTimer);
    tplPreviewTimer = setTimeout(refreshTplPreview, 350);
  });
}

$$('#tpl-prev-mode .seg').forEach((b) => b.addEventListener('click', () => {
  $$('#tpl-prev-mode .seg').forEach((x) => x.classList.toggle('active', x === b));
  tplPrevMode = b.dataset.mode;
  refreshTplPreview();
}));

// Логотип шаблона: нормализуем в PNG высотой до 120px (запас для Retina),
// ширина в подписи считается по пропорциям от выбранной высоты.
$('#t-logo-input').addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const img = new Image();
    img.onload = () => {
      const h = Math.min(120, img.naturalHeight);
      const w = Math.round(img.naturalWidth * (h / img.naturalHeight));
      const canvas = document.createElement('canvas');
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext('2d');
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(img, 0, 0, w, h);
      const dataUrl = canvas.toDataURL('image/png');
      canvas.toBlob((blob) => {
        state.pendingLogo = { blob, dataUrl, ratio: img.naturalWidth / img.naturalHeight };
        $('#t-logo-preview').innerHTML = `<img src="${dataUrl}" alt="">`;
        $('#t-logo-enabled').checked = true;
        refreshTplPreview();
      }, 'image/png');
    };
    img.onerror = () => toast('Не удалось прочитать файл логотипа.', true);
    img.src = reader.result;
  };
  reader.readAsDataURL(file);
  e.target.value = '';
});

$('#tpl-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.store.canWrite) { toast('Режим просмотра: сохранение недоступно.', true); return; }
  const btn = $('#tpl-save-btn');
  busy(btn, true, 'Сохраняю…');
  try {
    let tpl = state.templates.find((t) => t.id === state.editingTplId);
    const isNew = !tpl;
    if (isNew) {
      tpl = { id: 'tpl-' + hex8(), name: '', renderer: 'estatecrm-classic', config: defaultTemplateConfig() };
      state.templates.push(tpl);
    }
    tpl.name = $('#t-name').value.trim();
    const cfg = tpl.config;
    cfg.greeting = $('#t-greeting').value.trim();
    cfg.companyName = $('#t-companyName').value.trim();
    cfg.companyPhone = $('#t-companyPhone').value.trim();
    cfg.website = { label: $('#t-webLabel').value.trim(), url: $('#t-webUrl').value.trim() };
    cfg.colors = { accent: $('#t-accent').value, text: $('#t-text').value };
    cfg.button = cfg.button || defaultTemplateConfig().button;
    cfg.button.enabled = $('#t-btnEnabled').checked;
    cfg.button.url = $('#t-btnUrl').value.trim();
    cfg.required = $$('#t-required input:checked').map((i) => i.value);

    // Логотип
    const logoHeight = Math.max(20, Math.min(60, parseInt($('#t-logo-height').value, 10) || 32));
    if (!$('#t-logo-enabled').checked) {
      cfg.logo = null;
    } else if (state.pendingLogo) {
      const prevV = cfg.logo?.v || 0;
      let src;
      if (state.store.isDev) {
        src = state.pendingLogo.dataUrl;
      } else {
        src = `assets/logos/${tpl.id}.png`;
        const bytes = new Uint8Array(await state.pendingLogo.blob.arrayBuffer());
        await state.store.putFile(src, bytes, `Логотип шаблона: ${tpl.name}`);
      }
      cfg.logo = {
        src,
        width: Math.round(state.pendingLogo.ratio * logoHeight),
        height: logoHeight,
        alt: tpl.name,
        href: cfg.website.url || '#',
        v: prevV + 1,
      };
    } else if (cfg.logo && cfg.logo.src) {
      const ratio = cfg.logo.width / cfg.logo.height;
      cfg.logo.height = logoHeight;
      cfg.logo.width = Math.round(ratio * logoHeight);
      cfg.logo.href = cfg.website.url || cfg.logo.href;
      cfg.logo.alt = tpl.name;
    }

    await saveTemplates(`${isNew ? 'Создан' : 'Обновлён'} шаблон: ${tpl.name}`);
    renderTemplatesTab();
    renderEmployees();
    $('#modal-tpl').classList.add('hidden');
    toast(isNew ? 'Шаблон создан.' : 'Шаблон обновлён.');
  } catch (err) {
    toast(err.message, true, 6000);
  } finally {
    busy(btn, false);
  }
});

$('#tpl-delete').addEventListener('click', async () => {
  const tpl = state.templates.find((t) => t.id === state.editingTplId);
  if (!tpl) return;
  if (!confirm(`Удалить шаблон «${tpl.name}»?`)) return;
  const btn = $('#tpl-delete');
  busy(btn, true, 'Удаляю…');
  try {
    state.templates = state.templates.filter((t) => t.id !== tpl.id);
    await saveTemplates(`Удалён шаблон: ${tpl.name}`);
    renderTemplatesTab();
    $('#modal-tpl').classList.add('hidden');
    toast('Шаблон удалён.');
  } catch (err) {
    toast(err.message, true, 6000);
  } finally {
    busy(btn, false);
  }
});

// ---------- Установка подписи: подпись → программа → шрифт ----------
const FONT_CHOICES = [
  { id: 'aptos', label: 'Aptos / Calibri', family: "Aptos,Calibri,'Segoe UI',Arial,sans-serif" },
  { id: 'arial', label: 'Arial', family: 'Arial,Helvetica,sans-serif' },
  { id: 'helvetica', label: 'Helvetica', family: 'Helvetica,Arial,sans-serif' },
  { id: 'verdana', label: 'Verdana', family: 'Verdana,Geneva,sans-serif' },
  { id: 'tahoma', label: 'Tahoma', family: 'Tahoma,Geneva,sans-serif' },
  { id: 'georgia', label: 'Georgia', family: 'Georgia,serif' },
  { id: 'times', label: 'Times New Roman', family: "'Times New Roman',Times,serif" },
];
const FONT_SIZES = [12, 13, 14, 15, 16, 17, 18];
// Шрифты «по умолчанию» почтовых программ (Outlook — Aptos/Calibri 11pt≈15px,
// Apple Mail — Helvetica; на iPhone текст крупнее).
const CLIENT_FONT_DEFAULTS = {
  'outlook-win': { font: 'aptos', size: 15 },
  'outlook-mac': { font: 'aptos', size: 15 },
  'mail-mac': { font: 'helvetica', size: 12 },
  'mail-iphone': { font: 'helvetica', size: 16 },
};

// Компонент установки: сначала явный выбор подписи (если их несколько),
// затем панель конкретной подписи — программа, шрифт, превью, копирование.
function createInstaller(root, cfg) {
  root.innerHTML = `
  <div class="inst-picker hidden"></div>
  <div class="inst-panel hidden">
    <div class="row gap" style="margin-bottom:6px;">
      <button type="button" class="inst-back secondary small hidden">← Все подписи</button>
      <div class="inst-title"></div>
    </div>
    <div class="inst-missing warn-box hidden"></div>
    <div class="inst-step">1. Куда устанавливаете подпись?</div>
    <div class="inst-clients"></div>
    <div class="inst-step">2. Шрифт письма и подписи</div>
    <div class="inst-fontrow">
      <label>Шрифт <select class="inst-font"></select></label>
      <label>Размер <select class="inst-size"></select></label>
      <span class="inst-badge hidden"></span>
      <button type="button" class="inst-reset secondary small hidden">Вернуть рекомендуемый</button>
    </div>
    <div class="inst-step">3. Проверьте и скопируйте</div>
    <div class="row gap sig-toolbar">
      <div class="segmented inst-mode">
        <button type="button" class="seg" data-mode="desktop">Компьютер</button>
        <button type="button" class="seg" data-mode="mobile">iPhone</button>
      </div>
    </div>
    <div class="sig-preview-wrap"><iframe class="inst-preview" title="Превью письма"></iframe></div>
    <div class="row gap wrap" style="margin-top:14px;">
      <button type="button" class="primary inst-copy">Скопировать подпись</button>
      <button type="button" class="secondary inst-htm hidden">Скачать .htm</button>
      <button type="button" class="secondary small inst-html">HTML-код</button>
    </div>
    <details class="inst-howto instructions" style="margin-top:12px;"><summary></summary><ol></ol></details>
  </div>`;
  const el = (s) => root.querySelector(s);
  const st = { sigIndex: null, clientId: 'outlook-win', fontId: 'aptos', size: 15, custom: false, mode: 'desktop' };

  el('.inst-font').innerHTML = FONT_CHOICES
    .map((f) => `<option value="${f.id}">${f.label}</option>`).join('');
  el('.inst-size').innerHTML = FONT_SIZES
    .map((s) => `<option value="${s}">${s} px</option>`).join('');
  const clientsWrap = el('.inst-clients');
  for (const c of MAIL_CLIENTS) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'inst-client';
    b.dataset.id = c.id;
    b.innerHTML = `<span class="ic-icon">${c.icon}</span><span>${c.name}</span>`;
    b.addEventListener('click', () => { st.clientId = c.id; applyClientDefaults(); render(); });
    clientsWrap.appendChild(b);
  }

  function fontOpts() {
    const f = FONT_CHOICES.find((x) => x.id === st.fontId) || FONT_CHOICES[1];
    return { fontFamily: f.family, fontSize: st.size };
  }
  function applyClientDefaults() {
    const d = CLIENT_FONT_DEFAULTS[st.clientId];
    st.fontId = d.font;
    st.size = d.size;
    st.custom = false;
    st.mode = st.clientId === 'mail-iphone' ? 'mobile' : 'desktop';
  }
  function renderPicker() {
    const wrap = el('.inst-picker');
    wrap.innerHTML = '<div class="inst-step">Выберите, какую подпись установить:</div>';
    cfg.getSignatures().forEach((sig, i) => {
      const ctx = cfg.context(i, { fontFamily: 'Arial,Helvetica,sans-serif', fontSize: 14 });
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'inst-pick';
      b.innerHTML = `<span class="ip-name"></span><span class="ip-email"></span>${ctx.missing.length ? '<span class="role-chip none">⚠ не готова</span>' : ''}<span class="ip-arrow">→</span>`;
      b.querySelector('.ip-name').textContent = ctx.tpl.name;
      b.querySelector('.ip-email').textContent = ctx.emp.email || '';
      b.addEventListener('click', () => select(i));
      wrap.appendChild(b);
    });
  }
  function select(i) {
    st.sigIndex = i;
    applyClientDefaults();
    el('.inst-picker').classList.add('hidden');
    el('.inst-panel').classList.remove('hidden');
    el('.inst-back').classList.toggle('hidden', cfg.getSignatures().length < 2);
    if (cfg.onSelect) cfg.onSelect(i);
    render();
  }
  function render() {
    if (st.sigIndex === null) return;
    const ctx = cfg.context(st.sigIndex, fontOpts());
    const client = MAIL_CLIENTS.find((c) => c.id === st.clientId);
    el('.inst-title').textContent = `Подпись «${ctx.tpl.name}» · ${ctx.emp.email || ''}`;
    clientsWrap.querySelectorAll('.inst-client')
      .forEach((b) => b.classList.toggle('active', b.dataset.id === st.clientId));
    el('.inst-font').value = st.fontId;
    el('.inst-size').value = String(st.size);
    const badge = el('.inst-badge');
    badge.classList.toggle('hidden', st.custom);
    badge.textContent = `✓ Рекомендуемый для ${client.name}`;
    el('.inst-reset').classList.toggle('hidden', !st.custom);
    el('.inst-mode').querySelectorAll('.seg')
      .forEach((b) => b.classList.toggle('active', b.dataset.mode === st.mode));
    setPreview(el('.inst-preview'), ctx.html, st.mode,
      `${ctx.emp.firstName} ${ctx.emp.lastName}`, fontOpts());
    const dis = ctx.missing.length > 0;
    const warn = el('.inst-missing');
    warn.classList.toggle('hidden', !dis);
    if (dis) {
      warn.textContent = 'Подпись нельзя установить, пока не заполнены обязательные поля: '
        + ctx.missing.map((f) => f.label).join(', ') + '.';
    }
    el('.inst-copy').disabled = dis;
    el('.inst-htm').disabled = dis;
    el('.inst-html').disabled = dis;
    el('.inst-htm').classList.toggle('hidden', st.clientId !== 'outlook-win');
    el('.inst-howto summary').textContent = `Как вставить в ${client.name}`;
    el('.inst-howto ol').innerHTML = client.steps.map((s) => `<li>${s}</li>`).join('');
  }
  el('.inst-back').addEventListener('click', () => {
    st.sigIndex = null;
    el('.inst-panel').classList.add('hidden');
    el('.inst-picker').classList.remove('hidden');
    renderPicker();
    if (cfg.onBack) cfg.onBack();
  });
  el('.inst-font').addEventListener('change', (e) => { st.fontId = e.target.value; st.custom = true; render(); });
  el('.inst-size').addEventListener('change', (e) => { st.size = parseInt(e.target.value, 10); st.custom = true; render(); });
  el('.inst-reset').addEventListener('click', () => { applyClientDefaults(); render(); });
  el('.inst-mode').querySelectorAll('.seg').forEach((b) =>
    b.addEventListener('click', () => { st.mode = b.dataset.mode; render(); }));
  el('.inst-copy').addEventListener('click', async () => {
    const ctx = cfg.context(st.sigIndex, fontOpts());
    if (ctx.missing.length) return;
    const client = MAIL_CLIENTS.find((c) => c.id === st.clientId);
    const ok = await copyRichHtml(ctx.html, ctx.plain);
    toast(ok ? `Подпись скопирована — вставьте в ${client.name}.` : 'Не удалось скопировать.', !ok);
  });
  el('.inst-htm').addEventListener('click', () => {
    const ctx = cfg.context(st.sigIndex, fontOpts());
    if (ctx.missing.length) return;
    downloadFile(`signature-${ctx.emp.id}.htm`,
      fullHtmlDocument(ctx.html, `${ctx.emp.firstName} ${ctx.emp.lastName}`), 'text/html;charset=utf-8');
    toast('Файл .htm скачан.');
  });
  el('.inst-html').addEventListener('click', async () => {
    const ctx = cfg.context(st.sigIndex, fontOpts());
    await copyPlainText(ctx.html);
    toast('HTML-код подписи скопирован как текст.');
  });
  return {
    open() {
      const sigs = cfg.getSignatures();
      if (!sigs.length) return;
      if (sigs.length === 1) {
        select(0);
      } else {
        st.sigIndex = null;
        renderPicker();
        el('.inst-panel').classList.add('hidden');
        el('.inst-picker').classList.remove('hidden');
        if (cfg.onBack) cfg.onBack();
      }
    },
    refresh: render,
    get sigIndex() { return st.sigIndex; },
  };
}

// ---------- Превью «как настоящее письмо» ----------
const CHROME_FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif";
// Короткий текст письма перед подписью
const PREVIEW_MAIL_TEXT = `<p style="margin:0 0 12px;">Добрый день!</p>
<p style="margin:0 0 16px;">Отправляю материалы по нашему проекту — посмотрите, пожалуйста, до встречи в четверг, обсудим детали.</p>`;

// mode 'desktop' — окно почтовой программы; 'mobile' — iPhone 17 Pro Max
// (экран 440pt, поля Почты ~15px — переносы в подписи такие же, как на телефоне).
// fontOpts задаёт шрифт всего письма (текст + подпись рендерятся согласованно).
function previewDoc(sigHtml, mode, senderName, fontOpts) {
  const fam = fontOpts?.fontFamily || 'Arial,Helvetica,sans-serif';
  const fs = fontOpts?.fontSize || 14;
  const name = escapeHtml(senderName || 'Сотрудник');
  const initials = escapeHtml((senderName || 'С')
    .split(/\s+/).map((w) => w[0] || '').join('').slice(0, 2).toUpperCase());
  const body = PREVIEW_MAIL_TEXT + sigHtml;
  if (mode === 'mobile') {
    return `<!doctype html><html><head><meta charset="utf-8"></head><body style="margin:0;background:#e9edf3;padding:14px 0;display:flex;justify-content:center;font-family:${CHROME_FONT};">
<div style="width:440px;background:#0b0b0f;border-radius:58px;padding:10px;box-shadow:0 18px 50px rgba(15,25,50,.35);flex-shrink:0;">
<div style="background:#fff;border-radius:48px;overflow:hidden;">
<div style="height:56px;position:relative;background:#f7f8fa;">
<div style="position:absolute;top:13px;left:50%;transform:translateX(-50%);width:126px;height:34px;background:#0b0b0f;border-radius:20px;"></div>
<div style="position:absolute;top:19px;left:32px;font-size:15px;font-weight:600;color:#111;">9:41</div>
<div style="position:absolute;top:21px;right:30px;display:flex;gap:6px;align-items:center;">
<span style="font-size:10px;color:#111;letter-spacing:1px;">●●●</span>
<span style="display:inline-block;width:24px;height:12px;border:1.5px solid #9aa1ad;border-radius:3px;position:relative;"><span style="position:absolute;left:1px;top:1px;bottom:1px;width:70%;background:#111;border-radius:1px;"></span></span>
</div>
</div>
<div style="padding:10px 16px;border-bottom:1px solid #eef1f5;color:#4F7CFF;font-size:16px;background:#fff;">‹ Входящие</div>
<div style="padding:12px 16px;border-bottom:1px solid #eef1f5;">
<div style="display:flex;gap:10px;align-items:center;">
<div style="width:38px;height:38px;border-radius:50%;background:#1D325C;color:#fff;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;">${initials}</div>
<div><div style="font-weight:600;font-size:15px;color:#111;">${name}</div>
<div style="font-size:13px;color:#6b7280;">Кому: Вам</div></div>
</div>
<div style="font-weight:700;font-size:17px;margin-top:10px;color:#111;">Материалы по проекту</div>
</div>
<div style="padding:16px 15px 10px;font-family:${fam};font-size:${fs}px;line-height:1.5;color:#212121;">${body}</div>
<div style="height:28px;position:relative;"><div style="position:absolute;bottom:8px;left:50%;transform:translateX(-50%);width:148px;height:5px;background:#111;border-radius:3px;"></div></div>
</div></div></body></html>`;
  }
  return `<!doctype html><html><head><meta charset="utf-8"></head><body style="margin:0;background:#e9edf3;padding:16px;font-family:${CHROME_FONT};">
<div style="max-width:632px;margin:0 auto;background:#fff;border-radius:12px;border:1px solid #dfe4ee;box-shadow:0 14px 40px rgba(15,25,50,.16);overflow:hidden;">
<div style="background:linear-gradient(#f7f8fa,#eef0f4);padding:11px 14px;display:flex;align-items:center;gap:7px;border-bottom:1px solid #e2e6ef;">
<span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#ff5f57;"></span>
<span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#febc2e;"></span>
<span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#28c840;"></span>
<span style="flex:1;text-align:center;color:#6b7280;font-size:13px;font-weight:600;">Материалы по проекту</span>
<span style="width:54px;"></span>
</div>
<div style="padding:9px 18px;border-bottom:1px solid #eef1f5;font-size:13px;color:#6b7280;">Кому:&nbsp;<span style="background:#eef3ff;color:#1D325C;border-radius:10px;padding:2px 10px;font-weight:600;">Иван Партнёров</span></div>
<div style="padding:9px 18px;border-bottom:1px solid #eef1f5;font-size:13px;color:#6b7280;">Тема:&nbsp;<span style="color:#111;font-weight:600;">Материалы по проекту</span></div>
<div style="padding:18px;font-family:${fam};font-size:${fs}px;line-height:1.5;color:#212121;">${body}</div>
</div></body></html>`;
}

function setPreview(iframe, sigHtml, mode, senderName, fontOpts) {
  iframe.style.width = (mode === 'mobile' ? 492 : 664) + 'px';
  iframe.style.height = (mode === 'mobile' ? 840 : 620) + 'px';
  iframe.srcdoc = previewDoc(sigHtml, mode, senderName, fontOpts);
  iframe.onload = () => {
    try {
      const h = iframe.contentDocument.body.scrollHeight + 6;
      iframe.style.height = Math.max(420, h) + 'px';
    } catch (e) { /* превью без авто-высоты */ }
  };
}

// ---------- Просмотр подписей (администратор) ----------
function adminSigContext(i, fontOpts) {
  const emp = state.employees.find((e) => e.id === state.sigEmployeeId);
  const sig = emp.signatures[Math.min(i, emp.signatures.length - 1)];
  const tpl = templateById(sig.templateId);
  const viewEmp = sigView(emp, sig);
  return {
    emp: viewEmp, sig, tpl,
    missing: missingRequired(tpl, viewEmp),
    html: renderSignature(tpl, viewEmp, BASE_URL, fontOpts),
    plain: renderPlainText(tpl, viewEmp),
  };
}

const sigInstaller = createInstaller($('#sig-installer'), {
  getSignatures: () => {
    const emp = state.employees.find((e) => e.id === state.sigEmployeeId);
    return emp ? emp.signatures : [];
  },
  context: adminSigContext,
});

function openSigModal(empId) {
  state.sigEmployeeId = empId;
  const emp = state.employees.find((e) => e.id === empId);
  $('#sig-title').textContent = `Подписи: ${emp.firstName} ${emp.lastName}`;
  sigInstaller.open();
  $('#modal-sig').classList.remove('hidden');
}

$('#sig-close').addEventListener('click', () => $('#modal-sig').classList.add('hidden'));

// ---------- Личный кабинет пользователя ----------
function myEmployee() {
  return state.employees.find((e) => e.id === state.me.employeeId);
}

// Черновик: данные сотрудника с учётом несохранённых правок формы.
function myDraft() {
  const emp = myEmployee();
  if (!emp) return null;
  const draft = { ...emp, socials: { ...(emp.socials || {}) } };
  draft.firstName = $('#mf-firstName').value.trim();
  draft.lastName = $('#mf-lastName').value.trim();
  draft.position = $('#mf-position').value.trim();
  draft.department = $('#mf-department').value.trim();
  draft.mobile = $('#mf-mobile').value.trim();
  draft.socials.linkedin = $('#mf-linkedin').value.trim();
  draft.signatures = state.mySigs;
  if (state.pendingPhoto) { draft.photo = state.pendingPhoto.dataUrl; }
  return draft;
}

function myInstallContext(i, fontOpts) {
  const draft = myDraft();
  const sig = draft.signatures[Math.min(i, draft.signatures.length - 1)];
  const tpl = templateById(sig.templateId);
  const viewEmp = sigView(draft, sig);
  return {
    emp: viewEmp, sig, tpl,
    missing: missingRequired(tpl, viewEmp),
    html: renderSignature(tpl, viewEmp, BASE_URL, fontOpts),
    plain: renderPlainText(tpl, viewEmp),
  };
}

const myInstaller = createInstaller($('#my-installer'), {
  getSignatures: () => state.mySigs,
  context: myInstallContext,
  onSelect: (i) => {
    state.mySigIndex = i;
    const sig = state.mySigs[i];
    $('#l-mf-sigEmail').classList.remove('hidden');
    $('#mf-sigEmail').value = sig.email || '';
    updateMyReqMarks();
  },
  onBack: () => $('#l-mf-sigEmail').classList.add('hidden'),
});

// Пометки обязательных/незаполненных полей формы по шаблону выбранной подписи
function updateMyReqMarks() {
  const i = myInstaller.sigIndex;
  if (i === null) return;
  const draft = myDraft();
  const sig = draft.signatures[Math.min(i, draft.signatures.length - 1)];
  const tpl = templateById(sig.templateId);
  const req = tpl.config.required || [];
  const missing = missingRequired(tpl, sigView(draft, sig));
  for (const f of EMPLOYEE_FIELDS) {
    if (f.id === 'photo') continue;
    const label = $(f.id === 'email' ? '#l-mf-sigEmail' : `#l-mf-${f.id}`);
    if (!label) continue;
    label.classList.toggle('req', req.includes(f.id));
    label.classList.toggle('miss', missing.some((m) => m.id === f.id));
  }
}

function fillMy() {
  const emp = myEmployee();
  if (!emp) {
    toast('Ваша карточка сотрудника не найдена. Обратитесь к администратору.', true, 8000);
    return;
  }
  state.pendingPhoto = null;
  state.cropSourceUrl = null;
  state.mySigs = emp.signatures.map((s) => ({ ...s }));
  state.mySigIndex = 0;
  $('#mf-firstName').value = emp.firstName || '';
  $('#mf-lastName').value = emp.lastName || '';
  $('#mf-position').value = emp.position || '';
  $('#mf-department').value = emp.department || '';
  $('#mf-mobile').value = emp.mobile || '';
  $('#mf-linkedin').value = emp.socials?.linkedin || '';
  const src = photoSrc(emp);
  $('#my-photo-preview').innerHTML = src ? `<img src="${src}" alt="">` : '<span>Фото</span>';
  $('#my-photo-recrop').classList.add('hidden');
  $('#l-mf-sigEmail').classList.add('hidden');
  myInstaller.open();
}

let myPreviewTimer = null;
function refreshMyPreview() {
  if (myInstaller.sigIndex === null) return;
  myInstaller.refresh();
  updateMyReqMarks();
}

$('#mf-sigEmail').addEventListener('input', () => {
  const sig = state.mySigs[state.mySigIndex];
  if (sig) sig.email = $('#mf-sigEmail').value.trim();
  clearTimeout(myPreviewTimer);
  myPreviewTimer = setTimeout(refreshMyPreview, 400);
});

$('#my-form').addEventListener('input', () => {
  clearTimeout(myPreviewTimer);
  myPreviewTimer = setTimeout(refreshMyPreview, 400);
});

$('#my-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.store.canWrite) {
    toast('Сохранение появится после настройки администратором.', true);
    return;
  }
  const btn = $('#my-save');
  busy(btn, true, 'Сохраняю…');
  try {
    const emp = myEmployee();
    if (!emp) throw new Error('Карточка сотрудника не найдена.');
    emp.firstName = $('#mf-firstName').value.trim();
    emp.lastName = $('#mf-lastName').value.trim();
    emp.position = $('#mf-position').value.trim();
    emp.department = $('#mf-department').value.trim();
    emp.mobile = $('#mf-mobile').value.trim();
    emp.socials = emp.socials || {};
    emp.socials.linkedin = $('#mf-linkedin').value.trim();
    emp.signatures = state.mySigs.map((s) => ({ ...s, email: (s.email || '').trim() || emp.loginEmail }));

    let photoUploaded = false;
    if (state.pendingPhoto) {
      if (state.store.isDev) {
        emp.photo = state.pendingPhoto.dataUrl;
      } else {
        const path = `assets/photos/${emp.id}.jpg`;
        const bytes = new Uint8Array(await state.pendingPhoto.blob.arrayBuffer());
        await state.store.putFile(path, bytes, `Фото: ${emp.firstName} ${emp.lastName}`);
        emp.photo = path;
        emp.photoVersion = (emp.photoVersion || 0) + 1;
        photoUploaded = true;
      }
    }
    await saveEmployees(`Сотрудник обновил данные: ${emp.firstName} ${emp.lastName}`);

    // Синхронизация имени в записи пользователя
    if (state.me.displayName !== `${emp.firstName} ${emp.lastName}`) {
      state.me.displayName = `${emp.firstName} ${emp.lastName}`;
      await saveUsers(`Обновлены данные входа: ${state.me.displayName}`);
    }
    state.pendingPhoto = null;
    fillMy();
    toast(photoUploaded
      ? 'Сохранено. Фото станет доступно получателям через ~1 минуту.'
      : 'Сохранено.');
  } catch (err) {
    console.error(err);
    toast(err.message, true, 6000);
  } finally {
    busy(btn, false);
  }
});

// Закрытие модалов по клику на подложку
$$('.modal').forEach((m) => m.addEventListener('mousedown', (e) => {
  if (e.target === m && !['modal-crop', 'modal-invite'].includes(m.id)) m.classList.add('hidden');
}));

init();
