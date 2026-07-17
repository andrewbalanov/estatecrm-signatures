// Конфигурация сервиса. Меняется только при переносе в другой репозиторий.
export const OWNER = 'andrewbalanov';
export const REPO = 'estatecrm-signatures';
export const BRANCH = 'main';
// Абсолютный адрес опубликованного сайта — используется в HTML подписей,
// чтобы картинки открывались у любого получателя письма.
export const BASE_URL = `https://${OWNER}.github.io/${REPO}/`;
