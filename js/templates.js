// Рендеры шаблонов подписи. Вёрстка — email-safe: таблицы, инлайн-стили,
// atributes width/height (важно для Outlook на Windows, движок Word).
//
// Изменение макета шаблона выполняется правкой этого файла (через Claude).
// Настройки соцсетей и ссылок хранятся в data/templates.json и меняются в интерфейсе.

// Каталог поддерживаемых соцсетей: иконки лежат в assets/icons/social/.
export const NETWORKS = [
  { id: 'linkedin',  label: 'LinkedIn',  icon: 'assets/icons/social/linkedin.png' },
  { id: 'telegram',  label: 'Telegram',  icon: 'assets/icons/social/telegram.png' },
  { id: 'whatsapp',  label: 'WhatsApp',  icon: 'assets/icons/social/whatsapp.png' },
  { id: 'instagram', label: 'Instagram', icon: 'assets/icons/social/instagram.png' },
  { id: 'facebook',  label: 'Facebook',  icon: 'assets/icons/social/facebook.png' },
  { id: 'youtube',   label: 'YouTube',   icon: 'assets/icons/social/youtube.png' },
  { id: 'vk',        label: 'VK',        icon: 'assets/icons/social/vk.png' },
  { id: 'twitter',   label: 'Twitter/X', icon: 'assets/icons/social/twitter.png' },
];

// Поля сотрудника, которые администратор может пометить обязательными в шаблоне.
export const EMPLOYEE_FIELDS = [
  { id: 'firstName',  label: 'Имя' },
  { id: 'lastName',   label: 'Фамилия' },
  { id: 'position',   label: 'Должность' },
  { id: 'department', label: 'Отдел' },
  { id: 'mobile',     label: 'Мобильный телефон' },
  { id: 'email',      label: 'Email' },
  { id: 'photo',      label: 'Фотография' },
];

// Незаполненные обязательные поля шаблона — пока список не пуст,
// кнопки установки подписи неактивны.
export function missingRequired(template, employee) {
  const req = template.config.required || [];
  return EMPLOYEE_FIELDS.filter((f) => {
    if (!req.includes(f.id)) return false;
    if (f.id === 'photo') return !employee.photo;
    return !String(employee[f.id] || '').trim();
  });
}

// Конфиг по умолчанию для нового шаблона, создаваемого администратором.
export function defaultTemplateConfig() {
  return {
    required: ['firstName', 'lastName', 'position', 'email'],
    greeting: 'С уважением,',
    companyName: 'EstateCRM',
    logo: { src: 'assets/logo.png', width: 169, height: 29, alt: 'EstateCRM', href: 'https://www.estatecrm.io' },
    companyPhone: '+7 495 256-22-25',
    website: { label: 'www.estatecrm.io', url: 'https://www.estatecrm.io' },
    colors: { accent: '#1D325C', text: '#212121' },
    socials: NETWORKS.map((n) => ({ network: n.id, enabled: false, url: '', perEmployee: false })),
    button: {
      enabled: false,
      image: 'assets/icons/zoom-button.png',
      width: 174,
      height: 39,
      url: '',
      alt: 'Meet me on Zoom',
    },
  };
}

export function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export function telHref(phone) {
  return 'tel:' + String(phone || '').replace(/[^+\d]/g, '');
}

function absUrl(path, baseUrl) {
  if (!path) return '';
  if (/^(https?:|blob:|data:)/.test(path)) return path;
  return baseUrl + path;
}

function photoUrl(employee, baseUrl) {
  if (!employee.photo) return '';
  const url = absUrl(employee.photo, baseUrl);
  if (/^(blob:|data:)/.test(employee.photo)) return url;
  const v = employee.photoVersion || 1;
  return v > 1 ? `${url}?v=${v}` : url;
}

// Активные соцсети шаблона с учётом персональных ссылок сотрудника.
export function resolvedSocials(template, employee) {
  const list = [];
  for (const s of template.config.socials || []) {
    if (!s.enabled) continue;
    const net = NETWORKS.find(n => n.id === s.network);
    if (!net) continue;
    let url = s.url;
    if (s.perEmployee && employee && employee.socials && employee.socials[s.network]) {
      url = employee.socials[s.network];
    }
    if (!url) continue;
    list.push({ ...net, url });
  }
  return list;
}

const FONT = "Arial,Helvetica,sans-serif";

// Основной рендер — воспроизводит образец EstateCRM (WiseStamp):
// приветствие, логотип, карточка (фото + имя/должность + соцсети),
// контакты между двумя линиями, кнопка видеозвонка.
function renderEstateCrmClassic(template, employee, baseUrl, opts = {}) {
  const cfg = template.config;
  const fam = opts.fontFamily || FONT;
  const k = (opts.fontSize || 14) / 14;
  const px = (n) => Math.max(10, Math.round(n * k));
  const accent = cfg.colors?.accent || '#1D325C';
  const textColor = cfg.colors?.text || '#212121';
  const fullName = `${employee.firstName} ${employee.lastName}`.trim();
  const photo = photoUrl(employee, baseUrl);
  const socials = resolvedSocials(template, employee);

  const linkStyle = `font-family:${fam};color:${textColor};text-decoration:none;`;
  const iconImg = (icon, alt) =>
    `<img src="${absUrl(icon, baseUrl)}" width="13" height="13" alt="${alt}" style="width:13px;height:13px;border:0;vertical-align:middle;"><!--[if mso]><span>&nbsp;</span><![endif]-->`;

  // Контактная строка: каждый элемент — атомарная мини-таблица (align=left).
  // Такие блоки переносятся на новую строку ЦЕЛИКОМ (иконка вместе с текстом),
  // даже если почтовая программа вычистит запреты переносов у текста —
  // это надёжнее спанов с white-space:nowrap.
  const contactItem = (icon, alt, href, text) =>
    `<table align="left" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;"><tr><td style="font-family:${fam};font-size:${px(12)}px;line-height:1.5;color:${textColor};white-space:nowrap;padding:0 12px 2px 0;">${iconImg(icon, alt)}<a href="${href}" target="_blank" rel="nofollow noreferrer" style="${linkStyle}"><span style="color:${textColor};white-space:nowrap;">&nbsp;${escapeHtml(text)}</span></a></td></tr></table>`;

  const contactItems = [];
  if (cfg.companyPhone) {
    contactItems.push(contactItem('assets/icons/phone.png', 'тел', telHref(cfg.companyPhone), cfg.companyPhone));
  }
  if (employee.mobile) {
    contactItems.push(contactItem('assets/icons/mobile.png', 'моб', telHref(employee.mobile), employee.mobile));
  }
  if (cfg.website && cfg.website.url) {
    contactItems.push(contactItem('assets/icons/globe.png', 'сайт', escapeHtml(cfg.website.url), cfg.website.label || cfg.website.url));
  }
  const contactsLine1 = contactItems.join('');
  const contactsLine2 = employee.email
    ? contactItem('assets/icons/email.png', 'email', `mailto:${escapeHtml(employee.email)}`, employee.email)
    : '';

  const socialsHtml = socials.map(s =>
    `<a href="${escapeHtml(s.url)}" target="_blank" rel="nofollow noreferrer" style="text-decoration:none;"><img src="${absUrl(s.icon, baseUrl)}" width="25" height="25" alt="${s.label}" style="width:25px;height:25px;border:0;display:inline-block;"></a>`
  ).join('&nbsp;');

  // Пустая строка-отступ в самом начале подписи (до «С уважением, …»)
  const topSpacer = `<tr><td style="font-family:${fam};font-size:${px(14)}px;line-height:1.4;color:${textColor};">&nbsp;</td></tr>`;

  const greeting = cfg.greeting
    ? `<tr><td style="font-family:${fam};font-size:${px(14)}px;line-height:1.4;color:${textColor};padding:0 0 14px 0;">${escapeHtml(cfg.greeting)}<br>${escapeHtml(fullName)}</td></tr>`
    : '';

  let logoSrc = cfg.logo && cfg.logo.src ? absUrl(cfg.logo.src, baseUrl) : '';
  if (logoSrc && cfg.logo.v > 1 && !/^(data:|blob:)/.test(cfg.logo.src)) logoSrc += `?v=${cfg.logo.v}`;
  const logo = logoSrc
    ? `<tr><td style="padding:0 0 16px 0;"><a href="${escapeHtml(cfg.logo.href || '#')}" target="_blank" rel="nofollow noreferrer" style="text-decoration:none;"><img src="${logoSrc}" width="${cfg.logo.width}" height="${cfg.logo.height}" alt="${escapeHtml(cfg.logo.alt || '')}" style="border:0;display:block;width:${cfg.logo.width}px;height:${cfg.logo.height}px;"></a></td></tr>`
    : '';

  const photoCell = photo
    ? `<td width="65" valign="top" style="width:65px;vertical-align:top;"><img src="${photo}" width="65" height="65" alt="Фото" style="display:block;width:65px;height:65px;border-radius:0;"></td>`
    : '';

  const socialsCell = socialsHtml
    ? `<td valign="bottom" align="right" style="vertical-align:bottom;text-align:right;padding:0 0 12px 30px;">${socialsHtml}</td>`
    : '';

  const button = cfg.button && cfg.button.enabled && cfg.button.url
    ? `<tr><td style="padding:16px 0 0 0;"><a href="${escapeHtml(cfg.button.url)}" target="_blank" rel="nofollow noreferrer" style="text-decoration:none;display:block;font-size:0;"><img src="${absUrl(cfg.button.image, baseUrl)}" width="${cfg.button.width}" height="${cfg.button.height}" alt="${escapeHtml(cfg.button.alt || '')}" style="border:0;display:block;width:${cfg.button.width}px;height:${cfg.button.height}px;"></a></td></tr>`
    : '';

  return `<div dir="ltr"><table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
${topSpacer}${greeting}${logo}<tr><td><table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;font-family:${fam};color:${textColor};">
<tr>${photoCell}<td valign="top" style="vertical-align:top;${photo ? 'padding:0 0 0 12px;' : ''}">
<table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
<tr><td style="font-family:${fam};line-height:1.1;padding:0 0 12px 0;"><p style="margin:0;line-height:1.12;"><span style="font-weight:bold;font-family:${fam};color:${accent};font-size:${px(18)}px;white-space:nowrap;">${escapeHtml(fullName)}</span><br><span style="font-weight:bold;font-family:${fam};color:${textColor};font-size:${px(14)}px;">${escapeHtml(employee.position || '')}${cfg.companyName ? ', ' + escapeHtml(cfg.companyName) : ''}</span></p></td>
${socialsCell}</tr>
<tr><td colspan="2" style="border-top:2px solid ${accent};border-bottom:2px solid ${accent};padding:10px 0;">
<table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
<tr><td style="padding:0;">${contactsLine1}</td></tr>
${contactsLine2 ? `<tr><td style="padding:4px 0 0 0;">${contactsLine2}</td></tr>` : ''}
</table>
</td></tr>
</table>
</td></tr>
</table></td></tr>
${button}</table></div>`;
}

const RENDERERS = {
  'estatecrm-classic': renderEstateCrmClassic,
};

export function renderSignature(template, employee, baseUrl, opts) {
  const renderer = RENDERERS[template.renderer];
  if (!renderer) throw new Error(`Неизвестный рендер шаблона: ${template.renderer}`);
  return renderer(template, employee, baseUrl, opts);
}

// Текстовая версия — попадает в буфер обмена как text/plain (запасной вариант).
export function renderPlainText(template, employee) {
  const cfg = template.config;
  const lines = [];
  if (cfg.greeting) lines.push(cfg.greeting, `${employee.firstName} ${employee.lastName}`.trim(), '');
  else lines.push(`${employee.firstName} ${employee.lastName}`.trim());
  lines.push(`${employee.position || ''}${cfg.companyName ? ', ' + cfg.companyName : ''}`);
  const contacts = [];
  if (cfg.companyPhone) contacts.push(cfg.companyPhone);
  if (employee.mobile) contacts.push(employee.mobile);
  if (cfg.website && cfg.website.label) contacts.push(cfg.website.label);
  if (contacts.length) lines.push(contacts.join('  |  '));
  if (employee.email) lines.push(employee.email);
  return lines.join('\n');
}

// Полный HTML-документ (для скачивания .htm под Outlook Windows).
export function fullHtmlDocument(signatureHtml, title) {
  return `<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head>
<body>${signatureHtml}</body></html>`;
}
