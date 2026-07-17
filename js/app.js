// Основная логика интерфейса.
import { BASE_URL } from './config.js';
import * as cr from './crypto.js';
import { GitHubStore, DevStore, ReadOnlyStore } from './github.js';
import { NETWORKS, renderSignature, renderPlainText, fullHtmlDocument } from './templates.js';
import { MAIL_CLIENTS, copyRichHtml, copyPlainText, downloadFile } from './clients.js';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const DEV = location.hash.includes('dev');
const SESSION_KEY = 'ecsig.key';
const TOKEN_KEY = 'ecsig.token';

const state = {
  encKey: null,
  store: null,
  employees: [],
  templates: [],
  editingId: null,
  pendingPhoto: null,   // { blob, dataUrl } — обрезанное фото до сохранения
  cropper: null,
  cropSourceUrl: null,
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

function uid() {
  const arr = cr.randomBytes(4);
  return 'emp-' + [...arr].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function showScreen(name) {
  $('#screen-login').classList.toggle('hidden', name !== 'login');
  $('#screen-token').classList.toggle('hidden', name !== 'token');
  $('#screen-main').classList.toggle('hidden', name !== 'main');
}

function setModeBadge() {
  const badge = $('#mode-badge');
  if (state.store && state.store.isDev) {
    badge.textContent = 'ДЕМО-РЕЖИМ: изменения не сохраняются';
    badge.classList.remove('hidden');
  } else if (state.store && !state.store.canWrite) {
    badge.textContent = 'Только просмотр';
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}

function busy(btn, on, label) {
  if (on) { btn.dataset.label = btn.textContent; btn.textContent = label || 'Подождите…'; btn.disabled = true; }
  else { btn.textContent = btn.dataset.label || btn.textContent; btn.disabled = false; }
}

// ---------- Вход ----------
async function init() {
  const saved = sessionStorage.getItem(SESSION_KEY);
  if (saved) {
    try {
      state.encKey = await cr.importEncKey(saved);
      await afterLogin();
      return;
    } catch (e) {
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
    const res = await fetch(`data/auth.json?t=${Date.now()}`, { cache: 'no-store' });
    if (!res.ok) throw new Error('Не удалось загрузить данные авторизации');
    const auth = await res.json();
    const derived = await cr.deriveKeys($('#login-password').value, auth.salt, auth.iterations);
    if (derived.verifier !== auth.verifier) {
      errEl.textContent = 'Неверный пароль.';
      errEl.classList.remove('hidden');
      return;
    }
    state.encKey = derived.encKey;
    sessionStorage.setItem(SESSION_KEY, cr.b64encode(derived.encKeyRaw));
    $('#login-password').value = '';
    await afterLogin();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
  } finally {
    busy(btn, false);
  }
});

async function afterLogin() {
  if (DEV) {
    state.store = new DevStore();
    setModeBadge();
    await loadAll();
    showScreen('main');
    return;
  }
  const tokenEnc = localStorage.getItem(TOKEN_KEY);
  if (tokenEnc) {
    try {
      const token = await cr.decryptString(state.encKey, tokenEnc);
      const store = new GitHubStore(token);
      await store.validate();
      state.store = store;
    } catch (e) {
      console.warn('Сохранённый токен не подошёл:', e);
      localStorage.removeItem(TOKEN_KEY);
    }
  }
  if (!state.store) {
    showScreen('token');
    return;
  }
  setModeBadge();
  await loadAll();
  showScreen('main');
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
    localStorage.setItem(TOKEN_KEY, await cr.encryptString(state.encKey, token));
    state.store = store;
    $('#token-input').value = '';
    setModeBadge();
    await loadAll();
    showScreen('main');
    toast('GitHub подключён — сохранение работает.');
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
  } finally {
    busy(btn, false);
  }
});

$('#token-skip').addEventListener('click', async () => {
  state.store = new ReadOnlyStore();
  setModeBadge();
  await loadAll();
  showScreen('main');
});

$('#btn-logout').addEventListener('click', () => {
  sessionStorage.removeItem(SESSION_KEY);
  location.reload();
});

$('#btn-refresh').addEventListener('click', async () => {
  await loadAll();
  toast('Данные обновлены.');
});

// ---------- Данные ----------
async function loadAll() {
  const tplFile = await state.store.getFile('data/templates.json');
  if (!tplFile) throw new Error('Не найден data/templates.json');
  state.templates = JSON.parse(tplFile.text).templates;

  const empFile = await state.store.getFile('data/employees.json.enc');
  if (empFile) {
    const data = await cr.decryptJson(state.encKey, empFile.text);
    state.employees = data.employees || [];
  } else {
    state.employees = [];
  }
  renderEmployees();
  renderTemplatesTab();
  fillTemplateSelect();
  fillDeptFilter();
}

async function saveEmployees(message) {
  const payload = await cr.encryptJson(state.encKey, { employees: state.employees });
  await state.store.putFile('data/employees.json.enc', payload, message);
}

// ---------- Вкладки ----------
$$('.tab').forEach((btn) => btn.addEventListener('click', () => {
  $$('.tab').forEach((b) => b.classList.toggle('active', b === btn));
  $('#tab-employees').classList.toggle('hidden', btn.dataset.tab !== 'employees');
  $('#tab-templates').classList.toggle('hidden', btn.dataset.tab !== 'templates');
}));

// ---------- Список сотрудников ----------
function templateName(id) {
  const t = state.templates.find((t) => t.id === id);
  return t ? t.name : '—';
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
    row.innerHTML = `
      ${src ? `<img class="avatar" src="${src}" alt="">` : `<div class="avatar">${initials(emp)}</div>`}
      <div class="emp-info">
        <div class="emp-name"></div>
        <div class="emp-sub"></div>
      </div>
      <span class="chip"></span>
      <div class="emp-actions">
        <button class="primary small act-sig">Подпись</button>
        <button class="secondary small act-edit">Изменить</button>
      </div>`;
    row.querySelector('.emp-name').textContent = `${emp.firstName} ${emp.lastName}`;
    row.querySelector('.emp-sub').textContent =
      [emp.position, emp.department, emp.email].filter(Boolean).join(' · ');
    row.querySelector('.chip').textContent = templateName(emp.templateId);
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

// ---------- Редактор сотрудника ----------
function openEmpModal(id) {
  state.editingId = id;
  state.pendingPhoto = null;
  state.cropSourceUrl = null;
  const emp = state.employees.find((e) => e.id === id);
  $('#emp-form-title').textContent = emp ? 'Редактирование сотрудника' : 'Новый сотрудник';
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

$('#emp-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.store.canWrite) { toast('Режим просмотра: подключите GitHub-токен.', true); return; }
  const btn = $('#emp-save');
  busy(btn, true, 'Сохраняю…');
  try {
    let emp = state.employees.find((x) => x.id === state.editingId);
    const isNew = !emp;
    if (isNew) {
      emp = { id: uid(), photoVersion: 0 };
      state.employees.push(emp);
    }
    emp.firstName = $('#f-firstName').value.trim();
    emp.lastName = $('#f-lastName').value.trim();
    emp.position = $('#f-position').value.trim();
    emp.department = $('#f-department').value.trim();
    emp.mobile = $('#f-mobile').value.trim();
    emp.email = $('#f-email').value.trim();
    emp.templateId = $('#f-template').value;
    const li = $('#f-linkedin').value.trim();
    emp.socials = emp.socials || {};
    emp.socials.linkedin = li;

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

    await saveEmployees(`${isNew ? 'Добавлен' : 'Обновлён'} сотрудник: ${emp.firstName} ${emp.lastName}`);
    renderEmployees();
    fillDeptFilter();
    closeEmpModal();
    toast(photoUploaded
      ? 'Сохранено. Фото станет доступно по публичной ссылке через ~1 минуту (деплой GitHub Pages).'
      : 'Сохранено.');
  } catch (err) {
    console.error(err);
    toast(err.message, true, 6000);
  } finally {
    busy(btn, false);
  }
});

$('#emp-delete').addEventListener('click', async () => {
  const emp = state.employees.find((x) => x.id === state.editingId);
  if (!emp) return;
  if (!confirm(`Удалить сотрудника «${emp.firstName} ${emp.lastName}»? Его фото также будет удалено из репозитория.`)) return;
  const btn = $('#emp-delete');
  busy(btn, true, 'Удаляю…');
  try {
    if (emp.photo && !/^(blob:|data:)/.test(emp.photo) && !state.store.isDev) {
      await state.store.deleteFile(emp.photo, `Удалено фото: ${emp.firstName} ${emp.lastName}`);
    }
    state.employees = state.employees.filter((x) => x.id !== emp.id);
    await saveEmployees(`Удалён сотрудник: ${emp.firstName} ${emp.lastName}`);
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

// ---------- Обрезка фото ----------
$('#emp-photo-input').addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    state.cropSourceUrl = reader.result;
    openCropModal(reader.result);
  };
  reader.readAsDataURL(file);
  e.target.value = '';
});

$('#emp-photo-recrop').addEventListener('click', () => {
  if (state.cropSourceUrl) openCropModal(state.cropSourceUrl);
});

function openCropModal(srcUrl) {
  $('#modal-crop').classList.remove('hidden');
  const img = $('#crop-image');
  if (state.cropper) { state.cropper.destroy(); state.cropper = null; }
  img.src = srcUrl;
  state.cropper = new Cropper(img, {
    aspectRatio: 1,
    viewMode: 1,
    dragMode: 'move',
    autoCropArea: 1,
    background: false,
    guides: false,
    ready() {
      const data = state.cropper.getImageData();
      state.cropBaseZoom = data.width / data.naturalWidth;
      $('#crop-zoom').value = 1;
    },
  });
}

$('#crop-zoom').addEventListener('input', (e) => {
  if (!state.cropper || !state.cropBaseZoom) return;
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
    $('#emp-photo-preview').innerHTML = `<img src="${dataUrl}" alt="">`;
    $('#emp-photo-recrop').classList.remove('hidden');
    $('#modal-crop').classList.add('hidden');
    state.cropper.destroy();
    state.cropper = null;
  }, 'image/jpeg', 0.9);
});

// ---------- Вкладка «Шаблоны» ----------
const SAMPLE_EMPLOYEE = {
  firstName: 'Глеб', lastName: 'Цыганков', position: 'Управляющий партнер',
  mobile: '+7 915 122-25-25', email: 'g.tsygankov@estatecrm.io',
  photo: 'assets/photos/emp-a-balanov.jpg', photoVersion: 1, socials: {},
};

function renderTemplatesTab() {
  const wrap = $('#tpl-list');
  wrap.innerHTML = '';
  for (const tpl of state.templates) {
    const card = document.createElement('div');
    card.className = 'tpl-card';
    const sample = state.employees[0] || SAMPLE_EMPLOYEE;
    const sigHtml = renderSignature(tpl, sample, BASE_URL);
    card.innerHTML = `
      <h3></h3>
      <p class="muted small-text">Рендер: <code>${tpl.renderer}</code> · Используют:
        ${state.employees.filter((e) => e.templateId === tpl.id).length} сотр.</p>
      <div class="tpl-preview"><iframe></iframe></div>
      <h4>Соцсети в подписи</h4>
      <div class="socials-grid"></div>
      <div class="row gap">
        <button class="primary tpl-save">Сохранить настройки</button>
        <span class="per-emp-note">«Личная ссылка» — если у сотрудника указан свой профиль, он подставится вместо общего.</span>
      </div>`;
    card.querySelector('h3').textContent = tpl.name;
    card.querySelector('iframe').srcdoc =
      `<!doctype html><meta charset="utf-8"><body style="margin:14px;background:#fff;">${sigHtml}</body>`;

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
      row.querySelector('.s-enabled').addEventListener('change', (e) => { s.enabled = e.target.checked; });
      row.querySelector('.s-url').addEventListener('input', (e) => { s.url = e.target.value.trim(); });
      row.querySelector('.s-per').addEventListener('change', (e) => { s.perEmployee = e.target.checked; });
      grid.appendChild(row);
    }

    card.querySelector('.tpl-save').addEventListener('click', async (e) => {
      if (!state.store.canWrite) { toast('Режим просмотра: подключите GitHub-токен.', true); return; }
      busy(e.target, true, 'Сохраняю…');
      try {
        await state.store.putFile(
          'data/templates.json',
          JSON.stringify({ templates: state.templates }, null, 2) + '\n',
          `Настройки соцсетей: ${tpl.name}`
        );
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

// ---------- Просмотр и копирование подписи ----------
function currentSigContext() {
  const emp = state.employees.find((e) => e.id === state.sigEmployeeId);
  const tpl = state.templates.find((t) => t.id === emp.templateId) || state.templates[0];
  return { emp, tpl, html: renderSignature(tpl, emp, BASE_URL), plain: renderPlainText(tpl, emp) };
}

function openSigModal(empId) {
  state.sigEmployeeId = empId;
  const { emp, html } = currentSigContext();
  $('#sig-title').textContent = `Подпись: ${emp.firstName} ${emp.lastName}`;
  $('#sig-preview').srcdoc =
    `<!doctype html><meta charset="utf-8"><body style="margin:16px;background:#fff;">${html}</body>`;
  $$('#modal-sig .seg').forEach((b) => b.classList.toggle('active', b.dataset.width === '600'));
  $('#sig-preview').style.width = '600px';

  const cards = $('#sig-clients');
  cards.innerHTML = '';
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
      const { html, plain } = currentSigContext();
      const ok = await copyRichHtml(html, plain);
      toast(ok ? `Подпись скопирована — вставьте в ${client.name}.` : 'Не удалось скопировать.', !ok);
    });
    const htmBtn = card.querySelector('.cc-htm');
    if (htmBtn) htmBtn.addEventListener('click', () => {
      const { emp, html } = currentSigContext();
      downloadFile(`signature-${emp.id}.htm`,
        fullHtmlDocument(html, `${emp.firstName} ${emp.lastName}`), 'text/html;charset=utf-8');
      toast('Файл .htm скачан.');
    });
    cards.appendChild(card);
  }
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

// Закрытие модалов по клику на подложку
$$('.modal').forEach((m) => m.addEventListener('mousedown', (e) => {
  if (e.target === m && m.id !== 'modal-crop') m.classList.add('hidden');
}));

init();
