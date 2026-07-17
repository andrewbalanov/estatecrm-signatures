// Клиент GitHub Contents API: чтение и запись файлов репозитория.
import { OWNER, REPO, BRANCH } from './config.js';
import { b64encode, b64decode } from './crypto.js';

const API = 'https://api.github.com';

export class GitHubStore {
  constructor(token) {
    this.token = token;
    this.canWrite = true;
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
    if (!res.ok) throw new Error(`GitHub: ${res.status} ${res.statusText}`);
    const repo = await res.json();
    if (!repo.permissions || !repo.permissions.push) {
      throw new Error('Токен действителен, но не даёт права записи (Contents: Read and write).');
    }
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
    return { bytes, text: new TextDecoder().decode(bytes), sha: data.sha };
  }

  // Записывает файл (создаёт или обновляет). content — Uint8Array или строка.
  async putFile(path, content, message) {
    const existing = await this.getFile(path);
    const bytes = typeof content === 'string' ? new TextEncoder().encode(content) : content;
    const body = {
      message,
      content: b64encode(bytes),
      branch: BRANCH,
    };
    if (existing) body.sha = existing.sha;
    const res = await fetch(`${API}/repos/${OWNER}/${REPO}/contents/${path}`, {
      method: 'PUT',
      headers: { ...this.headers(), 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(`GitHub: не удалось сохранить ${path} (${res.status}) ${err.message || ''}`);
    }
    return res.json();
  }

  async deleteFile(path, message) {
    const existing = await this.getFile(path);
    if (!existing) return;
    const res = await fetch(`${API}/repos/${OWNER}/${REPO}/contents/${path}`, {
      method: 'DELETE',
      headers: { ...this.headers(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, sha: existing.sha, branch: BRANCH }),
    });
    if (!res.ok) throw new Error(`GitHub: не удалось удалить ${path} (${res.status})`);
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
