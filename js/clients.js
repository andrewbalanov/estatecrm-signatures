// Копирование подписи, оптимизированное под конкретные почтовые программы,
// и пошаговые инструкции по установке для каждой из них.

export const MAIL_CLIENTS = [
  {
    id: 'outlook-win',
    name: 'Outlook Windows',
    icon: '🪟',
    hint: 'Классический и новый Outlook на Windows',
    steps: [
      'Нажмите «Скопировать подпись».',
      'Классический Outlook: Файл → Параметры → Почта → Подписи… Новый Outlook: Настройки (шестерёнка) → Учётные записи → Подписи.',
      'Нажмите «Создать», назовите подпись (например, «EstateCRM»).',
      'Кликните в поле редактирования и вставьте: Ctrl+V.',
      'Назначьте подпись для новых писем и ответов, нажмите «ОК».',
      'Продвинутый вариант: скачайте файл .htm кнопкой ниже и положите его в папку %APPDATA%\\Microsoft\\Signatures (только классический Outlook).',
    ],
  },
  {
    id: 'outlook-mac',
    name: 'Outlook Mac',
    icon: '🍎',
    hint: 'Microsoft Outlook на macOS',
    steps: [
      'Нажмите «Скопировать подпись».',
      'Outlook → Настройки (Cmd+,) → Подписи.',
      'Нажмите «+», назовите подпись (например, «EstateCRM»).',
      'Кликните в поле редактирования и вставьте: Cmd+V.',
      'Закройте окно — подпись сохранится автоматически. Назначьте её по умолчанию в разделе «Выбор подписи по умолчанию».',
    ],
  },
  {
    id: 'mail-mac',
    name: 'Mail Mac',
    icon: '✉️',
    hint: 'Почта (Apple Mail) на macOS',
    steps: [
      'Нажмите «Скопировать подпись».',
      'Mail → Настройки (Cmd+,) → Подписи.',
      'Выберите почтовый ящик, нажмите «+».',
      'СНИМИТЕ галку «Всегда использовать мой шрифт по умолчанию для сообщений».',
      'Кликните в поле подписи, удалите автотекст и вставьте: Cmd+V.',
      'Важно: в окне настроек картинки могут не отображаться или выглядеть смещёнными — это особенность Apple Mail. В реальных письмах подпись будет выглядеть правильно: отправьте себе тестовое письмо для проверки.',
    ],
  },
  {
    id: 'mail-iphone',
    name: 'Mail iPhone',
    icon: '📱',
    hint: 'Почта на iPhone / iPad',
    steps: [
      'Откройте этот сервис в Safari на iPhone и нажмите «Скопировать подпись» на этом же экране.',
      'Откройте Настройки → Приложения → Почта → Подпись (на старых iOS: Настройки → Почта → Подпись).',
      'Удалите старый текст и вставьте подпись (долгое нажатие → «Вставить»).',
      'iOS уберёт часть форматирования — сразу ВСТРЯХНИТЕ телефон и нажмите «Вернуть» (Undo). Форматирование восстановится.',
      'Проверьте: отправьте себе письмо из приложения Почта.',
    ],
  },
];

// Копирование в буфер: text/html + text/plain. Именно так подпись «идеально»
// вставляется в редакторы подписей — они читают HTML-часть буфера.
export async function copyRichHtml(html, plainText) {
  if (navigator.clipboard && window.ClipboardItem) {
    try {
      await navigator.clipboard.write([
        new ClipboardItem({
          'text/html': new Blob([html], { type: 'text/html' }),
          'text/plain': new Blob([plainText], { type: 'text/plain' }),
        }),
      ]);
      return true;
    } catch (e) {
      // падаем в запасной вариант ниже
    }
  }
  return copyViaSelection(html);
}

// Запасной вариант: скрытый contenteditable + выделение + execCommand('copy').
function copyViaSelection(html) {
  const holder = document.createElement('div');
  holder.contentEditable = 'true';
  holder.style.cssText = 'position:fixed;left:-10000px;top:0;opacity:0;';
  holder.innerHTML = html;
  document.body.appendChild(holder);
  const range = document.createRange();
  range.selectNodeContents(holder);
  const sel = window.getSelection();
  sel.removeAllRanges();
  sel.addRange(range);
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
  sel.removeAllRanges();
  holder.remove();
  return ok;
}

export async function copyPlainText(text) {
  await navigator.clipboard.writeText(text);
}

export function downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime || 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
