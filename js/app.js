// Основная логика интерфейса (v2 — многопользовательский режим).
//
// Криптосхема («конверт»):
//   dataKey (случайный AES-256) шифрует employees.json.enc и GitHub-токен (encToken).
//   Для каждого пользователя dataKey зашифрован его личным ключом, выведенным
//   из кода доступа (PBKDF2). users.json хранит только соли, верификаторы и конверты —
//   по ним нельзя восстановить ни коды, ни данные.
import { BASE_URL } from './config.js?v=3';
import * as cr from './crypto.js?v=3';
import { GitHubStore, DevStore, ReadOnlyStore } from './github.js?v=3';
import {
  NETWORKS, EMPLOYEE_FIELDS, renderSignature, renderPlainText, fullHtmlDocument,
  missingRequired, defaultTemplateConfig,
} from './templates.js?v=3';
import { MAIL_CLIENTS, copyRichHtml, copyPlainText, downloadFile } from './clients.js?v=3';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const DEV = location.hash.includes('dev');
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
  editingId: null,
  editingTplId: null,
  pendingPhoto: null, // { blob, dataUrl } — обрезанное фото до сохранения
  pendingLogo: null,  // { blob, dataUrl, ratio } — логотип шаблона до сохранения
  cropper: null,
  cropBaseZoom: null,
  cropSourceUrl: null,
  cropTarget: 'emp',  // 'emp' (модал администратора) | 'my' (личный кабинет)
  sigEmployeeId: null,
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

// Код доступа: 16 символов base58 (без похожих букв), ~93 бита энтропии.
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
  for (const id of ['login', 'token', 'main', 'my']) {
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

// ---------- Вход ----------
async function fetchUsersDocPublic() {
  const res = await fetch(`data/users.json?t=${Date.now()}`, { cache: 'no-store' });
  if (!res.ok) throw new Error('Не удалось загрузить список пользователей');
  return res.json();
}

async function init() {
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
    const derived = me
      ? await cr.deriveKeys($('#login-password').value, me.salt, doc.kdf.iterations)
      : null;
    if (!me || derived.verifier !== me.verifier) {
      errEl.textContent = 'Неверный email или код доступа.';
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
// Соль администратора сохранена при миграции, поэтому ключ совпадает — переносим в репозиторий.
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
  state.store = new ReadOnlyStore();
  await enterApp();
});

$('#btn-token').addEventListener('click', () => showScreen('token'));

for (const id of ['#btn-logout', '#my-logout']) {
  $(id).addEventListener('click', () => {
    sessionStorage.removeItem(SESSION_KEY);
    location.reload();
  });
}

$('#btn-refresh').addEventListener('click', async () => { await loadAll(); toast('Данные обновлены.'); });
$('#my-refresh').addEventListener('click', async () => { await loadAll(); fillMy(); toast('Данные обновлены.'); });

// ---------- Данные ----------
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
    state.employees = data.employees || [];
  } else {
    state.employees = [];
  }
  if (isAdmin()) {
    renderEmployees();
    renderTemplatesTab();
    fillTemplateSelect();
    fillDeptFilter();
  }
}

async function saveEmployees(message) {
  const payload = await cr.encryptJson(state.dataKey, { employees: state.employees });
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

function renderEmployees() {
  const q = $('#emp-search').value.trim().toLowerCase();
  const dept = $('#emp-dept-filter').value;
  const list = $('#emp-list');
  list.innerHTML = '';
  const filtered = state.employees.filter((e) => {
    if (dept && e.department !== dept) return false;
    if (!q) return true;
    return [e.firstName, e.lastName, e.position, e.email, e.department]
      .join(' ').toLowerCase().includes(q);
  });
  $('#emp-empty').classList.toggle('hidden', filtered.length > 0);
  for (const emp of filtered) {
    const row = document.createElement('div');
    row.className = 'emp-row';
    const src = photoSrc(emp);
    const user = userByEmployee(emp.id);
    const roleChip = user
      ? `<span class="role-chip ${user.role}">${user.role === 'admin' ? 'Админ' : 'Пользователь'}</span>`
      : '<span class="role-chip none">Без доступа</span>';
    const missing = missingRequired(templateById(emp.templateId), emp);
    row.innerHTML = `
      ${src ? `<img class="avatar" src="${src}" alt="">` : `<div class="avatar">${initials(emp)}</div>`}
      <div class="emp-info">
        <div class="emp-name"></div>
        <div class="emp-sub"></div>
      </div>
      ${missing.length ? '<span class="role-chip none" title="Не заполнены обязательные поля">⚠ не готова</span>' : ''}
      ${roleChip}
      <span class="chip"></span>
      <div class="emp-actions">
        <button class="primary small act-sig">Подпись</button>
        <button class="secondary small act-edit">Изменить</button>
      </div>`;
    row.querySelector('.emp-name').textContent = `${emp.firstName} ${emp.lastName}`;
    row.querySelector('.emp-sub').textContent =
      [emp.position, emp.department, emp.email].filter(Boolean).join(' · ');
    row.querySelector('.chip').textContent = templateById(emp.templateId)?.name || '—';
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

function fillTemplateSelect() {
  $('#f-template').innerHTML = state.templates
    .map((t) => `<option value="${t.id}">${t.name}</option>`).join('');
}

$('#emp-search').addEventListener('input', renderEmployees);
$('#emp-dept-filter').addEventListener('change', renderEmployees);
$('#btn-add-emp').addEventListener('click', () => openEmpModal(null));

// ---------- Редактор сотрудника (администратор) ----------
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
  $('#f-email').value = emp?.email || '';
  $('#f-linkedin').value = emp?.socials?.linkedin || '';
  if (emp) $('#f-template').value = emp.templateId;
  $('#emp-delete').classList.toggle('hidden', !emp);
  $('#emp-photo-recrop').classList.add('hidden');
  $('#acc-none').classList.toggle('hidden', !!user);
  $('#acc-linked').classList.toggle('hidden', !user);
  $('#f-invite').checked = !emp;
  if (user) {
    $('#acc-email').textContent = user.email;
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

// Создание доступа: конверт dataKey под новым кодом сотрудника.
async function createAccessRecord(emp, role) {
  const code = genCode();
  const salt = cr.b64encode(cr.randomBytes(16));
  const derived = await cr.deriveKeys(code, salt, state.usersDoc.kdf.iterations);
  const rec = {
    id: 'u-' + hex8(),
    employeeId: emp.id,
    email: emp.email,
    displayName: `${emp.firstName} ${emp.lastName}`,
    role,
    salt,
    verifier: derived.verifier,
    encDataKey: await encryptObjForDoc(derived.encKey, state.session.dataKeyRaw),
    invitedAt: new Date().toISOString().slice(0, 10),
  };
  return { rec, code };
}

function inviteEmailText(emp, code) {
  return [
    `Здравствуйте, ${emp.firstName}!`,
    '',
    'Для вас создана корпоративная email-подпись EstateCRM.',
    '',
    'Как установить:',
    `1. Откройте сервис: ${BASE_URL}`,
    `2. Войдите — email: ${emp.email}, код доступа: ${code}`,
    '3. Проверьте свои данные и при необходимости загрузите фотографию.',
    '4. Нажмите «Скопировать подпись» для вашей почтовой программы и следуйте короткой инструкции на экране.',
    '',
    'Код доступа личный — пожалуйста, не передавайте его коллегам.',
  ].join('\n');
}

function showInviteModal(emp, code) {
  $('#inv-name').textContent = `${emp.firstName} ${emp.lastName}`;
  $('#inv-email').textContent = emp.email;
  $('#inv-code').textContent = code;
  const subject = 'Ваша корпоративная email-подпись EstateCRM';
  const body = inviteEmailText(emp, code);
  $('#inv-mailto').href =
    `mailto:${encodeURIComponent(emp.email)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  $('#inv-copy-text').onclick = async () => {
    await copyPlainText(`${subject}\n\n${body}`);
    toast('Текст приглашения скопирован.');
  };
  $('#inv-copy-code').onclick = async () => {
    await copyPlainText(code);
    toast('Код доступа скопирован.');
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
    const email = $('#f-email').value.trim();
    const emailTaken = state.employees.some((x) => x.id !== state.editingId
      && (x.email || '').toLowerCase() === email.toLowerCase());
    if (emailTaken) throw new Error('Сотрудник с таким email уже есть.');

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
    emp.email = email;
    emp.templateId = $('#f-template').value;
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
    let inviteCode = null;
    let usersChanged = false;
    if (user) {
      const newRole = $('#f-role2').value;
      if (user.role !== newRole || user.email !== emp.email
          || user.displayName !== `${emp.firstName} ${emp.lastName}`) {
        user.role = newRole;
        user.email = emp.email;
        user.displayName = `${emp.firstName} ${emp.lastName}`;
        usersChanged = true;
      }
    } else if ($('#f-invite').checked) {
      const { rec, code } = await createAccessRecord(emp, $('#f-role').value);
      state.usersDoc.users.push(rec);
      inviteCode = code;
      usersChanged = true;
    }

    await saveEmployees(`${isNew ? 'Добавлен' : 'Обновлён'} сотрудник: ${emp.firstName} ${emp.lastName}`);
    if (usersChanged) await saveUsers(`Доступы: ${emp.firstName} ${emp.lastName}`);

    renderEmployees();
    fillDeptFilter();
    closeEmpModal();
    if (inviteCode) {
      showInviteModal(emp, inviteCode);
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
  if (!confirm(`Сбросить код доступа для «${user.displayName}»? Старый код перестанет работать.`)) return;
  const btn = $('#acc-reset');
  busy(btn, true, 'Генерирую…');
  try {
    const code = genCode();
    const salt = cr.b64encode(cr.randomBytes(16));
    const derived = await cr.deriveKeys(code, salt, state.usersDoc.kdf.iterations);
    user.salt = salt;
    user.verifier = derived.verifier;
    user.encDataKey = await encryptObjForDoc(derived.encKey, state.session.dataKeyRaw);
    await saveUsers(`Сброшен код доступа: ${user.displayName}`);
    closeEmpModal();
    showInviteModal(emp, code);
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
  mobile: '+7 915 122-25-25', email: 'g.tsygankov@estatecrm.io',
  department: 'Руководство',
  photo: 'assets/photos/emp-a-balanov.jpg', photoVersion: 1, socials: {},
};

function renderTemplatesTab() {
  const wrap = $('#tpl-list');
  wrap.innerHTML = '';
  for (const tpl of state.templates) {
    const card = document.createElement('div');
    card.className = 'tpl-card';
    const usedBy = state.employees.filter((e) => e.templateId === tpl.id).length;
    const sample = state.employees[0] || SAMPLE_EMPLOYEE;
    const sigHtml = renderSignature(tpl, sample, BASE_URL);
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
        fillTemplateSelect();
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
  const usedBy = tpl ? state.employees.filter((e) => e.templateId === tpl.id).length : 0;
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
}

$('#tpl-cancel').addEventListener('click', () => $('#modal-tpl').classList.add('hidden'));

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
      // Логотип не менялся — обновляем высоту (ширина по прежним пропорциям) и ссылку
      const ratio = cfg.logo.width / cfg.logo.height;
      cfg.logo.height = logoHeight;
      cfg.logo.width = Math.round(ratio * logoHeight);
      cfg.logo.href = cfg.website.url || cfg.logo.href;
      cfg.logo.alt = tpl.name;
    }
    await saveTemplates(`${isNew ? 'Создан' : 'Обновлён'} шаблон: ${tpl.name}`);
    renderTemplatesTab();
    fillTemplateSelect();
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
    fillTemplateSelect();
    $('#modal-tpl').classList.add('hidden');
    toast('Шаблон удалён.');
  } catch (err) {
    toast(err.message, true, 6000);
  } finally {
    busy(btn, false);
  }
});

// ---------- Карточки почтовых программ (общее) ----------
function renderClientCards(container, ctxGetter) {
  container.innerHTML = '';
  for (const client of MAIL_CLIENTS) {
    const card = document.createElement('div');
    card.className = 'client-card';
    card.innerHTML = `
      <div class="cc-head"><span>${client.icon}</span><span>${client.name}</span></div>
      <div class="cc-hint">${client.hint}</div>
      <button class="primary small cc-copy">Скопировать подпись</button>
      ${client.id === 'outlook-win' ? '<button class="secondary small cc-htm cc-extra">Скачать .htm</button>' : ''}
      <details><summary>Как вставить</summary><ol>${client.steps.map((s) => `<li>${s}</li>`).join('')}</ol></details>`;
    card.querySelector('.cc-copy').addEventListener('click', async () => {
      const ctx = ctxGetter();
      if (ctx.missing.length) return;
      const ok = await copyRichHtml(ctx.html, ctx.plain);
      toast(ok ? `Подпись скопирована — вставьте в ${client.name}.` : 'Не удалось скопировать.', !ok);
    });
    const htmBtn = card.querySelector('.cc-htm');
    if (htmBtn) htmBtn.addEventListener('click', () => {
      const ctx = ctxGetter();
      if (ctx.missing.length) return;
      downloadFile(`signature-${ctx.emp.id}.htm`,
        fullHtmlDocument(ctx.html, `${ctx.emp.firstName} ${ctx.emp.lastName}`), 'text/html;charset=utf-8');
      toast('Файл .htm скачан.');
    });
    container.appendChild(card);
  }
}

function setCardsDisabled(container, missing, warnEl) {
  const disabled = missing.length > 0;
  container.querySelectorAll('.cc-copy, .cc-htm').forEach((b) => { b.disabled = disabled; });
  warnEl.classList.toggle('hidden', !disabled);
  if (disabled) {
    warnEl.textContent = 'Подпись нельзя установить, пока не заполнены обязательные поля: '
      + missing.map((f) => f.label).join(', ') + '.';
  }
}

function sigContext(emp) {
  const tpl = templateById(emp.templateId);
  const missing = missingRequired(tpl, emp);
  return {
    emp, tpl, missing,
    html: renderSignature(tpl, emp, BASE_URL),
    plain: renderPlainText(tpl, emp),
  };
}

// ---------- Просмотр подписи (администратор) ----------
function currentSigContext() {
  const emp = state.employees.find((e) => e.id === state.sigEmployeeId);
  return sigContext(emp);
}

function openSigModal(empId) {
  state.sigEmployeeId = empId;
  const ctx = currentSigContext();
  $('#sig-title').textContent = `Подпись: ${ctx.emp.firstName} ${ctx.emp.lastName}`;
  $('#sig-preview').srcdoc =
    `<!doctype html><meta charset="utf-8"><body style="margin:16px;background:#fff;">${ctx.html}</body>`;
  $$('#modal-sig .seg').forEach((b) => b.classList.toggle('active', b.dataset.width === '600'));
  $('#sig-preview').style.width = '600px';
  renderClientCards($('#sig-clients'), currentSigContext);
  setCardsDisabled($('#sig-clients'), ctx.missing, $('#sig-missing'));
  $('#sig-copy-html').disabled = ctx.missing.length > 0;
  $('#modal-sig').classList.remove('hidden');
}

$$('#modal-sig .seg').forEach((btn) => btn.addEventListener('click', () => {
  $$('#modal-sig .seg').forEach((b) => b.classList.toggle('active', b === btn));
  $('#sig-preview').style.width = btn.dataset.width + 'px';
}));

$('#sig-copy-html').addEventListener('click', async () => {
  const { html } = currentSigContext();
  await copyPlainText(html);
  toast('HTML-код подписи скопирован как текст.');
});

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
  draft.email = $('#mf-email').value.trim();
  draft.socials.linkedin = $('#mf-linkedin').value.trim();
  if (state.pendingPhoto) { draft.photo = state.pendingPhoto.dataUrl; }
  return draft;
}

function myContext() {
  const draft = myDraft();
  const tpl = templateById(draft.templateId);
  return {
    emp: draft, tpl,
    missing: missingRequired(tpl, draft),
    html: renderSignature(tpl, draft, BASE_URL),
    plain: renderPlainText(tpl, draft),
  };
}

function fillMy() {
  const emp = myEmployee();
  if (!emp) {
    toast('Ваша карточка сотрудника не найдена. Обратитесь к администратору.', true, 8000);
    return;
  }
  state.pendingPhoto = null;
  state.cropSourceUrl = null;
  $('#mf-firstName').value = emp.firstName || '';
  $('#mf-lastName').value = emp.lastName || '';
  $('#mf-position').value = emp.position || '';
  $('#mf-department').value = emp.department || '';
  $('#mf-mobile').value = emp.mobile || '';
  $('#mf-email').value = emp.email || '';
  $('#mf-linkedin').value = emp.socials?.linkedin || '';
  const src = photoSrc(emp);
  $('#my-photo-preview').innerHTML = src ? `<img src="${src}" alt="">` : '<span>Фото</span>';
  $('#my-photo-recrop').classList.add('hidden');

  // Пометить обязательные поля шаблона звёздочкой
  const req = templateById(emp.templateId).config.required || [];
  for (const f of EMPLOYEE_FIELDS) {
    if (f.id === 'photo') continue;
    const label = $(`#l-mf-${f.id}`);
    if (label) label.classList.toggle('req', req.includes(f.id));
  }
  renderClientCards($('#my-clients'), myContext);
  refreshMyPreview();
}

let myPreviewTimer = null;
function refreshMyPreview() {
  const ctx = myContext();
  if (!ctx) return;
  $('#my-preview').srcdoc =
    `<!doctype html><meta charset="utf-8"><body style="margin:16px;background:#fff;">${ctx.html}</body>`;
  setCardsDisabled($('#my-clients'), ctx.missing, $('#my-missing'));
  // Подсветить незаполненные обязательные поля
  for (const f of EMPLOYEE_FIELDS) {
    if (f.id === 'photo') continue;
    const label = $(`#l-mf-${f.id}`);
    if (label) label.classList.toggle('miss', ctx.missing.some((m) => m.id === f.id));
  }
}

$('#my-form').addEventListener('input', () => {
  clearTimeout(myPreviewTimer);
  myPreviewTimer = setTimeout(refreshMyPreview, 400);
});

$$('#my-seg .seg').forEach((btn) => btn.addEventListener('click', () => {
  $$('#my-seg .seg').forEach((b) => b.classList.toggle('active', b === btn));
  $('#my-preview').style.width = btn.dataset.width + 'px';
}));

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
    emp.email = $('#mf-email').value.trim();
    emp.socials = emp.socials || {};
    emp.socials.linkedin = $('#mf-linkedin').value.trim();

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

    // Синхронизация записи пользователя (email/имя для входа)
    if (state.me.email !== emp.email || state.me.displayName !== `${emp.firstName} ${emp.lastName}`) {
      state.me.email = emp.email;
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
