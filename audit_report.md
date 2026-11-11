# Аудит безопасности приложения VeloShop

## 1. Резюме
**Область аудита:** APK-файл приложения VeloShop.
**Методика:** OWASP MASVS v2, статический анализ (Lint, ручной аудит манифеста и BuildConfig), динамический анализ (adb, logcat).
**Итог:** 8 находок: 2 критических, 4 высоких, 2 средних.

## 2. Методика и инструменты
- **Статический анализ:** Android Studio Lint, просмотр `AndroidManifest.xml`, `build.gradle.kts`.
- **Динамический анализ:** `adb logcat`, `adb shell am`, `adb backup`.

## 3. Находки (Findings)

### FIND-001: Экспортированная Activity без прав доступа
- **MASVS:** MASVS-PLATFORM-1 (Компоненты)
- **CVSS:** 8.2 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)
- **Шаги воспроизведения:** Выполнить `adb shell am start -n com.example.veloshop/.ui.screens.misc.DeleteNoteActivity --es note_id "123"`
- **Доказательство:** В логах `adb logcat | grep AUDIT_VULN` появляется запись об удалении заметки. Любое приложение может вызвать эту Activity и удалить данные пользователя.
- **Рекомендация:** Установить `android:exported="false"` в манифесте.

### FIND-002: Токен в SharedPreferences и разрешенные бэкапы
- **MASVS:** MASVS-STORAGE-1 (Хранение данных)
- **CVSS:** 7.5 (AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)
- **Шаги:** Выполнить `adb backup -f backup.ab com.example.veloshop`, распаковать `dd if=backup.ab bs=1 skip=24 | tar -xzf -` и открыть `veloshop_prefs.xml`.
- **Доказательство:** Токен `super_secret_token_123` хранится в открытом виде и извлекается через бэкап.
- **Рекомендация:** `android:allowBackup="false"`, использовать EncryptedSharedPreferences.

### FIND-003: Передача данных по HTTP (Cleartext)
- **MASVS:** MASVS-NETWORK-1 (Сеть)
- **CVSS:** 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
- **Шаги:** Проверить манифест на наличие `android:usesCleartextTraffic="true"` и загрузку `http://api.notes.example` в WebView.
- **Доказательство:** Приложение разрешает незашифрованный трафик.
- **Рекомендация:** Использовать только HTTPS, настроить Network Security Config.

### FIND-004: API-ключ в BuildConfig / репозитории
- **MASVS:** MASVS-STORAGE-2 (Утечка через репозиторий)
- **CVSS:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **Шаги:** Открыть `app/build.gradle.kts`, найти `buildConfigField("String", "API_KEY", ...)`.
- **Доказательство:** Ключ `AIzaSyFakeKey...` захардкожен.
- **Рекомендация:** Ротировать ключ, вынести в `local.properties` (не коммитить в Git).

### FIND-005: Логирование токена авторизации
- **MASVS:** MASVS-STORAGE-2 / MASVS-PLATFORM-2
- **CVSS:** 6.0 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **Шаги:** Авторизоваться, выполнить `adb logcat | grep "token="`.
- **Доказательство:** В логах появляется `Token=secret_admin_token_123`.
- **Рекомендация:** Удалить все `Log.d` с чувствительными данными.

### FIND-006: Уязвимый WebView с javascriptInterface
- **MASVS:** MASVS-PLATFORM-2
- **CVSS:** 7.4 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)
- **Шаги:** Открыть `WebViewScreen.kt`. Включен `javaScriptEnabled` и добавлен `addJavascriptInterface`.
- **Доказательство:** Любой загруженный сайт может вызвать `AndroidBridge.getSecretData()` и украсть данные.
- **Рекомендация:** Убрать `addJavascriptInterface`, если он не нужен.

### FIND-007: Отключена обфускация R8
- **MASVS:** MASVS-RESILIENCE-1
- **CVSS:** 5.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)
- **Шаги:** Открыть `build.gradle.kts`, проверить `isMinifyEnabled = false`.
- **Рекомендация:** Включить `isMinifyEnabled = true` и `shrinkResources = true`.

### FIND-008: Утечка через Clipboard (буфер обмена)
- **MASVS:** MASVS-PLATFORM-3
- **CVSS:** 4.0 (AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)
- **Шаги:** Открыть экран заметок, кликнуть на заметку (она скопируется в буфер), открыть другое приложение и вставить.
- **Доказательство:** Текст заметки доступен в буфере обмена бесконечно долго.
- **Рекомендация:** Очищать буфер обмена через 30 секунд (или использовать `ClipDescription.EXTRA_IS_SENSITIVE` на Android 13+).

## 4. Триаж (Приоритеты)

| ID       | Название               | CVSS | Приоритет | Когда чинить          |
|----------|------------------------|------|-----------|-----------------------|
| FIND-004 | API-ключ в BuildConfig | 9.1  | P0        | Немедленно (Ротация!) |
| FIND-001 | Exported Activity      | 8.2  | P0        | До релиза             |
| FIND-002 | Токен в бэкапе         | 7.5  | P1        | В текущем спринте     |
| FIND-006 | WebView JS-мост        | 7.4  | P1        | В текущем спринте     |
| FIND-003 | Cleartext HTTP         | 6.5  | P1        | В текущем спринте     |
| FIND-005 | Логирование токена     | 6.0  | P2        | Следующий спринт      |
| FIND-007 | Отключен R8            | 5.0  | P2        | Перед релизом         |
| FIND-008 | Clipboard              | 4.0  | P3        | Бэклог                |

## 5. План Hardening и проверка закрытия

| ID       | Находка                  | Примененное исправление                                                                                    | Доказательство закрытия                                    |
|----------|--------------------------|------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| FIND-001 | Exported Activity        | В манифесте установлено `android:exported="false"`.                                                        | Команда `adb shell am start` вызывает `SecurityException`. |
| FIND-002 | Бэкапы и открытые данные | `allowBackup="false"`. Внедрен `EncryptedSharedPreferences` из Jetpack Security. Токен больше не хранится. | `adb backup` завершается ошибкой.                          |
| FIND-003 | Cleartext HTTP           | Удален `usesCleartextTraffic="true"`. В WebView URL заменен на `https://`.                                 | Попытка загрузить `http://` не проходит.                   |
| FIND-004 | API-ключ в коде          | Удален `buildConfigField`. Ключ должен передаваться через CI/CD.                                           | Ключ отсутствует в сборке (поиск по проекту).              |
| FIND-005 | Логирование токена       | Удалены вызовы `Log.d(...)` с чувствительными данными.                                                     | `adb logcat \| grep token` не выдает результатов.          |
| FIND-006 | Небезопасный WebView     | Удален `addJavascriptInterface`.                                                                           | JS-код на странице не может вызвать Java-методы.           |
| FIND-007 | Отключен R8              | В `build.gradle.kts` установлено `isMinifyEnabled = true` и `isShrinkResources = true`.                    | Сборка release проходит успешно, код обфусцирован.         |
| FIND-008 | Clipboard                | Добавлена корутина, очищающая буфер обмена через 30 секунд после копирования.                              | Через 30 сек `getText()` возвращает пустую строку.         |

### 6. План ротации ключа (FIND-004)
Поскольку API-ключ `AIzaSyFakeKey...` был закоммичен в историю Git, простого удаления из кода недостаточно.
1. **Ротация:** Старый ключ отозван в консоли Google Cloud (имитация).
2. **Генерация:** Создан новый ключ.
3. **Хранение:** Новый ключ добавлен в `local.properties` (который в `.gitignore`) и читается в `build.gradle.kts` через `localProperties.getProperty("api.key")`.
4. **Git:** История очищена с помощью `git filter-repo` (или BFG Repo-Cleaner), после чего ключ добавлен в pre-commit hook `gitleaks`.