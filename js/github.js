// Клиент GitHub Contents API: чтение и запись файлов репозитория.
import { OWNER, REPO, BRANCH } from './config.js?v=7';
import { b64encode, b64decode } from './crypto.js?v=7';

const API = 'https://api.github.com';

export class GitHubStore {
  constructor(token) {
    this.token = token;
    this.canWrite = true;
    // Кэш sha по путям: Contents API отдаёт свежую версию с задержкой,
    // поэтому после записи запоминаем sha из ответа, а не перечитываем.
    this.shaCache = new Map();
  }

  headers() {
    return {
      'Authorization': `Bearer ${this.token}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    };
  }

  // Проверяет, что токен действителен и даёт право записи в репозиторий.
  async validate() {
    const res = await fetch(`${API}/repos/${OWNER}/${REPO}`, { headers: this.headers() });
    if (res.status === 401) throw new Error('GitHub: токен недействителен или отозван (401).');
    if (res.status === 404) {
      throw new Error(`Токен не видит репозиторий ${REPO}. В настройках токена: Repository access → «Only select repositories» → выберите ${REPO}.`);
    }
    if (!res.ok) throw new Error(`GitHub: ${res.status} ${res.statusText}`);
    const repo = await res.json();
    if (!repo.permissions || !repo.permissions.push) {
      throw new Error('Токен действителен, но не даёт права записи (Contents: Read and write).');
    }
    // GET /repos отражает права ПОЛЬЗОВАТЕЛЯ, а не токена (частая ловушка fine-grained
    // токенов) — поэтому реально проверяем доступ токена к содержимому.
    const probe = await fetch(
      `${API}/repos/${OWNER}/${REPO}/contents/data/users.json?ref=${BRANCH}&t=${Date.now()}`,
      { headers: this.headers(), cache: 'no-store' }
    );
    if (probe.status === 403 || probe.status === 404) {
      throw new Error('Токену не хватает права на содержимое репозитория. В настройках токена: Permissions → Repository permissions → Contents → «Read and write», Repository access → только ' + REPO + '.');
    }
    if (!probe.ok) throw new Error(`GitHub: проверка доступа не удалась (${probe.status}).`);
    return true;
  }

  // Возвращает {text, bytes, sha} или null, если файла нет.
  async getFile(path) {
    const res = await fetch(
      `${API}/repos/${OWNER}/${REPO}/contents/${path}?ref=${BRANCH}&t=${Date.now()}`,
      { headers: this.headers(), cache: 'no-store' }
    );
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`GitHub: не удалось прочитать ${path} (${res.status})`);
    const data = await res.json();
    const bytes = b64decode(data.content.replace(/\n/g, ''));
    if (!this.shaCache.has(path)) this.shaCache.set(path, data.sha);
    return { bytes, text: new TextDecoder().decode(bytes), sha: data.sha };
  }

  async currentSha(path) {
    if (this.shaCache.has(path)) return this.shaCache.get(path);
    const existing = await this.getFile(path);
    return existing ? existing.sha : null;
  }

  // Записывает файл (создаёт или обновляет). content — Uint8Array или строка.
  async putFile(path, content, message) {
    const bytes = typeof content === 'string' ? new TextEncoder().encode(content) : content;
    const attempt = async (sha) => {
      const body = { message, content: b64encode(bytes), branch: BRANCH };
      if (sha) body.sha = sha;
      return fetch(`${API}/repos/${OWNER}/${REPO}/contents/${path}`, {
        method: 'PUT',
        headers: { ...this.headers(), 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    };
    let res = await attempt(await this.currentSha(path));
    if (res.status === 409 || res.status === 422) {
      // sha устарел или отсутствовал — перечитываем и повторяем один раз
      this.shaCache.delete(path);
      const fresh = await this.getFile(path);
      res = await attempt(fresh ? fresh.sha : null);
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const hint = res.status === 403
        ? ' Токену не хватает права Contents: Read and write — проверьте настройки токена.'
        : '';
      throw new Error(`GitHub: не удалось сохранить ${path} (${res.status}) ${err.message || ''}${hint}`);
    }
    const data = await res.json();
    this.shaCache.set(path, data.content.sha);
    return data;
  }

  async deleteFile(path, message) {
    const sha = await this.currentSha(path);
    if (!sha) return;
    const attempt = (s) => fetch(`${API}/repos/${OWNER}/${REPO}/contents/${path}`, {
      method: 'DELETE',
      headers: { ...this.headers(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, sha: s, branch: BRANCH }),
    });
    let res = await attempt(sha);
    if (res.status === 409 || res.status === 422) {
      this.shaCache.delete(path);
      const fresh = await this.getFile(path);
      if (!fresh) return;
      res = await attempt(fresh.sha);
    }
    if (!res.ok && res.status !== 404) throw new Error(`GitHub: не удалось удалить ${path} (${res.status})`);
    this.shaCache.delete(path);
  }
}

// Демо-режим (#dev): чтение с сайта, запись только в память браузера.
export class DevStore {
  constructor() {
    this.memory = new Map();
    this.canWrite = true;
    this.isDev = true;
  }

  async validate() { return true; }

  async getFile(path) {
    if (this.memory.has(path)) {
      const bytes = this.memory.get(path);
      return { bytes, text: new TextDecoder().decode(bytes), sha: 'dev' };
    }
    const res = await fetch(`${path}?t=${Date.now()}`, { cache: 'no-store' });
    if (!res.ok) return null;
    const buf = new Uint8Array(await res.arrayBuffer());
    return { bytes: buf, text: new TextDecoder().decode(buf), sha: 'dev' };
  }

  async putFile(path, content) {
    const bytes = typeof content === 'string' ? new TextEncoder().encode(content) : content;
    this.memory.set(path, bytes);
    return { content: { path } };
  }

  async deleteFile(path) {
    this.memory.delete(path);
  }
}

// Режим «только просмотр»: чтение файлов прямо с опубликованного сайта.
export class ReadOnlyStore {
  constructor() {
    this.canWrite = false;
  }

  async getFile(path) {
    const res = await fetch(`${path}?t=${Date.now()}`, { cache: 'no-store' });
    if (!res.ok) return null;
    const buf = new Uint8Array(await res.arrayBuffer());
    return { bytes: buf, text: new TextDecoder().decode(buf), sha: null };
  }

  async putFile() {
    throw new Error('Режим просмотра: сохранение недоступно. Подключите GitHub-токен.');
  }

  async deleteFile() {
    throw new Error('Режим просмотра: удаление недоступно. Подключите GitHub-токен.');
  }
}
