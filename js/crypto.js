// Криптография: PBKDF2-SHA256 для вывода ключа из пароля, AES-256-GCM для данных.
// Модуль работает и в браузере, и в Node (для служебных скриптов в tools/).

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

export function b64encode(bytes) {
  let bin = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}

export function b64decode(str) {
  const bin = atob(str);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

export function randomBytes(n) {
  const arr = new Uint8Array(n);
  globalThis.crypto.getRandomValues(arr);
  return arr;
}

// Из пароля выводится 64 байта: первые 32 — ключ шифрования, вторые 32 —
// материал верификатора. В репозитории хранится только SHA-256 от второй
// половины, поэтому по нему нельзя восстановить ключ шифрования.
export async function deriveKeys(password, saltB64, iterations) {
  const baseKey = await subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: b64decode(saltB64), iterations },
    baseKey,
    512
  );
  const all = new Uint8Array(bits);
  const encKeyRaw = all.slice(0, 32);
  const verifyRaw = all.slice(32, 64);
  const verifierHash = await subtle.digest('SHA-256', verifyRaw);
  const encKey = await subtle.importKey('raw', encKeyRaw, 'AES-GCM', true, ['encrypt', 'decrypt']);
  return { encKey, encKeyRaw, verifier: b64encode(verifierHash) };
}

export async function importEncKey(rawB64) {
  return subtle.importKey('raw', b64decode(rawB64), 'AES-GCM', true, ['encrypt', 'decrypt']);
}

export async function exportEncKey(encKey) {
  const raw = await subtle.exportKey('raw', encKey);
  return b64encode(raw);
}

export async function encryptString(encKey, plaintext) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, encKey, te.encode(plaintext));
  return JSON.stringify({ v: 1, alg: 'AES-256-GCM', iv: b64encode(iv), ct: b64encode(ct) }, null, 2);
}

export async function decryptString(encKey, payloadJson) {
  const payload = JSON.parse(payloadJson);
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(payload.iv) },
    encKey,
    b64decode(payload.ct)
  );
  return td.decode(pt);
}

export async function encryptJson(encKey, obj) {
  return encryptString(encKey, JSON.stringify(obj, null, 2));
}

export async function decryptJson(encKey, payloadJson) {
  return JSON.parse(await decryptString(encKey, payloadJson));
}
