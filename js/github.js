// Клиент GitHub Contents API: чтение и запись файлов репозитория.
import { OWNER, REPO, BRANCH } from './config.js?v=20';
import { b64encode, b64decode } from './crypto.js?v=20';

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

  // Текущая вершина ветки — точка отсчёта транзакции. GET ref реплицируется
  // с задержкой, поэтому свой последний коммит помним и предпочитаем его:
  // если он устареет из-за чужой записи, транзакция получит conflict и повторится.
  async headSha() {
    if (this._lastCommitSha) return this._lastCommitSha;
    const res = await fetch(
      `${API}/repos/${OWNER}/${REPO}/git/ref/heads/${BRANCH}?t=${Date.now()}`,
      { headers: this.headers(), cache: 'no-store' }
    );
    if (!res.ok) throw new Error(`GitHub: не удалось прочитать ветку ${BRANCH} (${res.status})`);
    return (await res.json()).object.sha;
  }

  // Чтение файла на КОНКРЕТНОМ коммите — консистентный снимок для транзакции.
  // Через Git Data API (дерево + blob): Contents API отдаёт содержимое с
  // задержкой кэша и может вернуть устаревшую версию, что привело бы
  // к затиранию чужих изменений.
  async getFileAt(path, commitSha) {
    if (!this._treeCache || this._treeCache.sha !== commitSha) {
      const commitRes = await fetch(`${API}/repos/${OWNER}/${REPO}/git/commits/${commitSha}`, {
        headers: this.headers(), cache: 'no-store',
      });
      if (!commitRes.ok) throw new Error(`GitHub: не удалось прочитать коммит (${commitRes.status})`);
      const treeSha = (await commitRes.json()).tree.sha;
      const treeRes = await fetch(`${API}/repos/${OWNER}/${REPO}/git/trees/${treeSha}?recursive=1`, {
        headers: this.headers(), cache: 'no-store',
      });
      if (!treeRes.ok) throw new Error(`GitHub: не удалось прочитать дерево (${treeRes.status})`);
      const tree = await treeRes.json();
      const map = new Map();
      for (const e of tree.tree || []) if (e.type === 'blob') map.set(e.path, e.sha);
      this._treeCache = { sha: commitSha, map };
    }
    const blobSha = this._treeCache.map.get(path);
    if (!blobSha) return null;
    const blobRes = await fetch(`${API}/repos/${OWNER}/${REPO}/git/blobs/${blobSha}`, {
      headers: this.headers(), cache: 'no-store',
    });
    if (!blobRes.ok) throw new Error(`GitHub: не удалось прочитать ${path} (${blobRes.status})`);
    const bytes = b64decode((await blobRes.json()).content.replace(/\n/g, ''));
    return { bytes, text: new TextDecoder().decode(bytes), sha: blobSha };
  }

  // Записывает НЕСКОЛЬКО файлов ОДНИМ коммитом (Git Data API).
  // files: [{path, content: Uint8Array|string}] или [{path, remove: true}].
  // baseSha — коммит, на котором строились изменения: если ветка с тех пор
  // сдвинулась, GitHub отклонит обновление ссылки и вернётся conflict:true
  // (вызывающий перечитает данные и повторит — оптимистичная блокировка).
  async commitFiles(files, message, baseSha) {
    const base = baseSha || await this.headSha();
    const baseCommitRes = await fetch(`${API}/repos/${OWNER}/${REPO}/git/commits/${base}`, {
      headers: this.headers(), cache: 'no-store',
    });
    if (!baseCommitRes.ok) throw new Error(`GitHub: не удалось прочитать коммит (${baseCommitRes.status})`);
    const baseTree = (await baseCommitRes.json()).tree.sha;

    const tree = [];
    for (const f of files) {
      if (f.remove) {
        tree.push({ path: f.path, mode: '100644', type: 'blob', sha: null });
        continue;
      }
      const bytes = typeof f.content === 'string'
        ? new TextEncoder().encode(f.content) : f.content;
      const blobRes = await fetch(`${API}/repos/${OWNER}/${REPO}/git/blobs`, {
        method: 'POST',
        headers: { ...this.headers(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: b64encode(bytes), encoding: 'base64' }),
      });
      if (!blobRes.ok) {
        const err = await blobRes.json().catch(() => ({}));
        throw new Error(`GitHub: не удалось загрузить ${f.path} (${blobRes.status}) ${err.message || ''}`);
      }
      tree.push({ path: f.path, mode: '100644', type: 'blob', sha: (await blobRes.json()).sha });
    }

    const treeRes = await fetch(`${API}/repos/${OWNER}/${REPO}/git/trees`, {
      method: 'POST',
      headers: { ...this.headers(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ base_tree: baseTree, tree }),
    });
    if (!treeRes.ok) {
      const err = await treeRes.json().catch(() => ({}));
      throw new Error(`GitHub: не удалось собрать дерево (${treeRes.status}) ${err.message || ''}`);
    }

    const commitRes = await fetch(`${API}/repos/${OWNER}/${REPO}/git/commits`, {
      method: 'POST',
      headers: { ...this.headers(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, tree: (await treeRes.json()).sha, parents: [base] }),
    });
    if (!commitRes.ok) {
      const err = await commitRes.json().catch(() => ({}));
      throw new Error(`GitHub: не удалось создать коммит (${commitRes.status}) ${err.message || ''}`);
    }
    const newSha = (await commitRes.json()).sha;

    const refRes = await fetch(`${API}/repos/${OWNER}/${REPO}/git/refs/heads/${BRANCH}`, {
      method: 'PATCH',
      headers: { ...this.headers(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ sha: newSha, force: false }),
    });
    if (refRes.status === 422) { this._lastCommitSha = null; this._treeCache = null; return { conflict: true }; }
    if (!refRes.ok) {
      const err = await refRes.json().catch(() => ({}));
      const hint = refRes.status === 403
        ? ' Токену не хватает права Contents: Read and write.' : '';
      throw new Error(`GitHub: не удалось сохранить изменения (${refRes.status}) ${err.message || ''}${hint}`);
    }
    this.shaCache.clear();
    this._treeCache = null;
    this._lastCommitSha = newSha;
    return { conflict: false, sha: newSha };
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

  async headSha() { return 'dev'; }

  async getFileAt(path) { return this.getFile(path); }

  async commitFiles(files) {
    for (const f of files) {
      if (f.remove) this.memory.delete(f.path);
      else await this.putFile(f.path, f.content);
    }
    return { conflict: false, sha: 'dev' };
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

  async headSha() { return null; }

  async getFileAt(path) { return this.getFile(path); }

  async commitFiles() {
    throw new Error('Режим просмотра: сохранение недоступно. Подключите GitHub-токен.');
  }
}
