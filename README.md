<div align="center">

# Step-CA UI

**Вебінтерфейс для [Smallstep step-ca](https://smallstep.com/docs/step-ca/) на власному сервері — керуйте своєю PKI з браузера.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Made with Go](https://img.shields.io/badge/Made%20with-Go%201.22-00ADD8.svg)](https://go.dev)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docs.docker.com/compose/)
[![Current version](https://img.shields.io/badge/version-v1.7.0-success.svg)](https://github.com/UncleFi1/step-ca-ui/releases/tag/v1.7.0)
[![Latest release](https://img.shields.io/badge/release-v1.7.0-success.svg)](https://github.com/UncleFi1/step-ca-ui/releases/latest)

🇺🇦 **Українська** · [🇬🇧 English](README.en.md) · [🇷🇺 Русский](README.ru.md)

</div>

---

> Зручний вебінтерфейс над `smallstep/step-ca` для невеликих команд. Без хмарних сервісів, телеметрії й прив’язки до постачальника — усе працює на вашому сервері в трьох контейнерах Docker.

## Цей форк

Гілка `uk` — наша версія, `main` — upstream без змін (зміни upstream потрапляють у `uk` злиттям після перегляду
коду). Відмінності від upstream:

- **Інтерфейс українською й англійською** з перемикачем UA / EN (бічна панель, меню облікового запису, сторінка
  входу). Вибір зберігається в профілі й cookie; без вибору — за мовою браузера, інакше українська. Українська —
  мова вихідного тексту, англійський каталог — `step-ui-go/i18n/locales/en.json` (докладніше — нижче, «Переклад»).
- **«Адмін → Огляд → Усі сертифікати CA»** — усе, що підписав step-ca (ACME, випуск з CLI, сам інтерфейс), а не
  лише облік UI. Потрібні step-ca на PostgreSQL і `CA_DB_URL` — роль лише для читання таблиць `x509_certs`,
  `x509_certs_data` і `revoked_x509_certs`. Дії: завантажити сертифікат, відкликати будь-який чинний, випустити
  заново з тими самими іменами (новий ключ, в обліку UI); за замовчуванням показано лише чинні.
- **Кілька імен під час випуску** — поле «Додаткові імена (SAN)»; поновлення зберігає всі імена сертифіката.
- **Робота за зворотним проксі** (TLS на проксі, застосунок — HTTP): перевірки «Preflight» не вважають помилкою
  відсутній власний сертифікат і незмонтований `ca.json` зовнішнього CA.
- **Повідомлення на сторінках адмінки** (помилки й результати дій) — в upstream більшість сторінок їх губила.

Збирання й розгортання нашої версії — у документації інфраструктури (репозиторій `xDevOps/xInfra`, `docs/deploy/pki.md`).

## Поточний реліз upstream

**Остання стабільна версія:** [v1.7.0](https://github.com/UncleFi1/step-ca-ui/releases/tag/v1.7.0)

Головне:
- обмежена консоль адміністратора з наперед визначеними командами діагностики, тайм-аутом, обмеженням виводу й журналом аудиту
- відновлення пароля: нейтральне повідомлення про результат, без розкриття наявності облікових записів, поле очищається після надсилання
- відновлення пароля через SMTP: токени зі строком дії, обмеження частоти, події аудиту
- посилений аудит дій адміністратора: користувачі, завантаження ключів, резервні копії, зміни налаштувань
- адаптивне верхнє меню з випадними групами для вузьких вікон
- TOTP 2FA: підключення застосунку-автентифікатора, QR-код і коди відновлення
- запит 2FA під час входу після перевірки пароля
- оновлені головна сторінка, сторінка 2FA й список сертифікатів
- адаптивний список сертифікатів для настільних комп’ютерів, ноутбуків і вузьких вікон браузера

## Можливості

- 📋 **Керування сертифікатами** — випуск, поновлення, відкликання й імпорт сертифікатів X.509
- 👥 **Доступ за ролями** — `admin` / `manager` / `viewer`
- 🔄 **Два режими CA** — вбудований step-ca в контейнері або підключення до наявного (на хості чи віддаленого) Smallstep CA
- ⏱️ **Тимчасові користувачі** — короткострокові гостьові облікові записи, що вимикаються автоматично
- 📅 **Власний вибір дати** — в оформленні сайту, без вбудованого віджета браузера
- 🌍 **Часовий пояс** — задається змінною середовища `TZ`
- 🎨 **4 теми** — темна, світла, синя, автоматична (як в ОС)
- 🧭 **Робочий простір адміністратора** — окремий інтерфейс адмінки в тих самих темах
- 🛡️ **Вбудований захист** — токени CSRF, обмеження частоти, блокування IP, журнал безпеки
- 🌐 **Перегляд провізіонерів** — перелік провізіонерів CA і випуск сертифікатів від зареєстрованих JWK
- 💾 **Експорт резервних копій** — архіви з контрольними сумами в маніфесті, з інтерфейсу й з командного рядка
- 🔎 **Перевірки цілісності CA** — ланцюжок кореневого й проміжного сертифікатів, обмеження провізіонерів, синхронізація пароля, закріплений образ step-ca
- 🔬 **Подробиці сертифіката** — SAN, відбитки, призначення ключа, перевірка пари сертифікат / ключ і ланцюжка
- 🧩 **Шаблони сертифікатів** — сервер, внутрішній сервіс, wildcard, клієнтський
- 🔔 **Сповіщення через вебхуки** — тестовий вебхук, помилки випуску й поновлення, серії невдалих входів, спливання строку
- 🔐 **TOTP 2FA** — підключення застосунку-автентифікатора, QR-код, запит під час входу, коди відновлення
- 🔁 **Відновлення пароля** — посилання через SMTP зі строком дії, обмеженням частоти, аудитом і нейтральними відповідями
- 🖥️ **Обмежена консоль адміністратора** — лише дозволені команди діагностики в контейнері UI, із записом у журнал

## Швидкий старт

```bash
git clone https://github.com/UncleFi1/step-ca-ui.git
cd step-ca-ui
sudo ./install.sh
```

Інсталятор працює російською або англійською і підтримує як чисте встановлення, так і безпечне оновлення:

```bash
sudo ./install.sh --mode install --lang en
sudo ./install.sh --mode update --lang en
```

Режим оновлення спершу робить резервну копію, зберігає `.env` і томи Docker, потім запускає
`docker compose up -d --build`. `docker compose down -v` він не виконує.

От і все. Інсталятор:
1. Визначає ОС і за потреби встановлює Docker
2. Сам знаходить IP сервера (з підтвердженням)
3. Генерує надійні паролі для всього
4. Записує `.env` і `credentials.txt` (права 600)
5. Збирає й запускає контейнери
6. Виводить адресу й пароль адміністратора

На чистій віртуальній машині це займає 2–4 хвилини.

## Вимоги

|                | Мінімум | Рекомендовано | Високе навантаження |
|----------------|---------|---------------|---------------------|
| **CPU**        | 1 vCPU  | 2 vCPU        | 4+ vCPU             |
| **RAM**        | 1 ГБ    | 2 ГБ          | 4+ ГБ               |
| **Диск**       | 5 ГБ    | 20 ГБ SSD     | 50+ ГБ NVMe         |
| **Мережа**     | 10 Мбіт/с | 100 Мбіт/с  | 1 Гбіт/с            |
| **Користувачі**| до 50   | до 500        | 500+                |
| **Сертифікати**| до 500  | до 10 тис.    | 10 тис.+            |

**Програмне забезпечення:**
- ядро Linux 4.4+ (Ubuntu 20.04+, Debian 11+, CentOS Stream 9+, Rocky 9+, Alma 9+)
- Docker Engine 20.10+ з плагіном Compose v2+
- відкриті порти: `443/tcp` (HTTPS інтерфейсу), за потреби `9000/tcp` (API step-ca)

> Не перевірялося, але має працювати: macOS / Windows через Docker Desktop (лише для розробки). \
> **Не підтримується:** хостинг без Docker, Raspberry Pi Zero (замало пам’яті).

## Стек

| Рівень       | Технологія                  |
|--------------|-----------------------------|
| Бекенд       | Go 1.22, маршрутизатор [chi](https://github.com/go-chi/chi) |
| Фронтенд     | HTML, що рендериться на сервері, + звичайний JS, без збирання |
| База даних   | PostgreSQL 16 |
| CA           | [smallstep/step-ca](https://hub.docker.com/r/smallstep/step-ca) |
| Розгортання  | Docker Compose |
| ОС контейнера| Alpine 3.19 + tzdata        |

## Архітектура

```
                          ┌────────────┐
   Браузер  ─── HTTPS ───►│  step-ui   │  вебзастосунок на Go, порт 8443
                          │  (chi)     │
                          └──┬─────┬───┘
                             │     │
                  SQL ◄──────┘     └──────► HTTPS API
                             │     │
                          ┌──▼──┐ ┌▼──────────┐
                          │ pg  │ │ step-ca   │  порт 9000
                          │ 16  │ │ (PKI)     │
                          └─────┘ └───────────┘

   step-ui відкриває :443  →  усередині переспрямовує на :8443
   step-ca відкриває :9000 →  за замовчуванням лише всередині
```

## Ролі

| Роль    | Перегляд | Випуск / імпорт | Відкликання | Керування користувачами |
|---------|----------|-----------------|-------------|-------------------------|
| viewer  | ✅       | ❌              | ❌          | ❌                      |
| manager | ✅       | ✅              | ❌          | ❌                      |
| admin   | ✅       | ✅              | ✅          | ✅                      |

**Тимчасові користувачі** можуть мати будь-яку роль; щойно мине `expires_at`, їх автоматично блокує фонова перевірка (щохвилини).

## Безпека

- ✅ **Захист від CSRF** — токени в кожній формі й перевірка на сервері для POST-маршрутів
- ✅ **Обмеження частоти** — 5 невдалих спроб входу → блокування IP на 15 хвилин
- ✅ **Заголовки безпеки** — CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, за бажанням HSTS
- ✅ **Тайм-аут сесії** — 8 годин, продовжується під час роботи
- ✅ **Журнал входів** — кожна спроба входу записується з IP і User-Agent
- ✅ **Самопідписаний TLS** — створюється автоматично під час першого запуску, строк — 10 років
- ✅ **Хешування паролів** — bcrypt для нових і змінених паролів; старі хеші SHA-256 прозоро переводяться на bcrypt після наступного вдалого входу

> 🔒 **Порада для продакшну:** поставте step-ui за зворотний проксі (Caddy / nginx) зі справжнім сертифікатом TLS, обмежте доступ через VPN / Tailscale і регулярно робіть резервні копії тому `step-ca-data`.

## Налаштування

Усі налаштування — у `.env`. Інсталятор створює цей файл сам, але його можна змінити вручну:

```env
# CA mode: bundled (Docker container) or external (native/remote step-ca)
CA_MODE=bundled
COMPOSE_FILE=docker-compose.yml:docker-compose.bundled.yml
# CA_HOST_PATH=/etc/step-ca        # optional: bind mount host CA directory

HOST_IP=192.168.1.100              # SAN in self-signed cert; step-ca DNS
UI_HTTPS_PORT=443                  # external HTTPS port
PROVISIONER=admin                  # step-ca provisioner identifier
CA_PASSWORD=<generated>            # step-ca provisioner password (bundled mode)
STEP_CA_IMAGE=smallstep/step-ca:0.30.2 # pinned step-ca image (bundled mode)
SECRET_KEY=<generated>             # session/CSRF signing key + CA password encryption
SESSION_SECURE=true                # secure session cookie over HTTPS
ENABLE_HSTS=false                  # enable only when using a trusted TLS certificate
POSTGRES_PASSWORD=<generated>      # database password
TZ=UTC                             # container timezone
STEPCA_DEFAULT_TLS_CERT_DURATION=8760h
STEPCA_MAX_TLS_CERT_DURATION=87600h
# fork: step-ca database (PostgreSQL, read-only role) for Admin -> All CA certificates
# CA_DB_URL=postgres://stepui_ro:<password>@<ca-db-host>:5432/stepca?sslmode=disable
```

У режимі `external` адреса CA, ім’я й пароль провізіонера, кореневий і проміжний сертифікати задаються просто у вебінтерфейсі: **Адмін → Налаштування CA** (`/admin/ca`).

Після зміни `.env` перестворіть контейнери:

```bash
sudo docker compose up -d --force-recreate
```

## Часті питання

<details>
<summary><b>Як змінити порт HTTPS з 443?</b></summary>

Змініть `docker-compose.yml`:
```yaml
services:
  step-ui:
    ports:
      - "8443:8443"   # was "443:8443"
```
Потім перезапустіть: `sudo docker compose up -d --force-recreate step-ui`.
</details>

<details>
<summary><b>Як зробити резервну копію даних і відновити їх?</b></summary>

В інтерфейсі: `Адмін → Резервна копія → Завантажити резервну копію`.

Також можна з командного рядка:

```bash
sudo ./install.sh --mode backup --lang en
```

Копія містить PostgreSQL, `step-ca-data`, дані, сертифікати й завантаження Step-CA UI та `manifest.json` з
контрольними сумами SHA-256. Відновлення навмисно ручне — за [BACKUP_RESTORE.md](BACKUP_RESTORE.md).
</details>

<details>
<summary><b>Як додати й налаштувати провізіонери (web, mTLS, client, acme, scep, sshpop, custom)?</b></summary>

Не кладіть пароль JWK `admin` вебінтерфейсу на хости сервісів. Створюйте провізіонери командним рядком на хості Docker:

```bash
sudo ./provisioner.sh --mode create --playbook web --lang en
```

Рецепти — у `playbooks/provisioners/`:
- `web` — JWK для вебсерверів і проксі з необов’язковим **обмеженням доменів у SAN** (напр., лише `*.corp.local`);
- `mtls` — JWK для автентифікації між сервісами (сервер / клієнт);
- `client` — JWK для клієнтських сертифікатів (VPN, робочі станції);
- `acme` — вбудований сервер ACME для автоматизації з Certbot, Caddy, Traefik (DNS-01, HTTP-01, TLS-ALPN-01);
- `scep` — протокол SCEP для керованого мережевого обладнання (комутатори, маршрутизатори, точки доступу Wi-Fi);
- `sshpop` — поновлення й заміна ключів SSH-сертифікатів хостів (SSHPOP);
- `custom` — інтерактивне налаштування будь-якого типу (JWK / ACME / SCEP / SSHPOP).

Для JWK командний рядок запитує ім’я, строк за замовчуванням і максимальний (`720h` / `4380h` / `8760h` / `87600h`),
обмеження доменів у SAN і пароль JWK (згенерований або введений). `--mode create` записує налаштування в `ca.json`
(вбудованого контейнера або CA на тому самому хості через `CA_HOST_PATH`, за замовчуванням `/etc/step-ca`),
перечитує step-ca (SIGHUP) і реєструє пароль у PostgreSQL для випуску з вебінтерфейсу. Провізіонери ACME, SCEP і
SSHPOP працюють своїми протоколами й паролів у базі UI не зберігають. `register-only` — для наявного JWK, який
треба лише зареєструвати в UI.

Якщо провізіонер уже є в CA:

```bash
sudo ./provisioner.sh --mode update --playbook web --lang en
sudo ./provisioner.sh --mode register-only --playbook web --lang en
sudo ./provisioner.sh --mode list --lang en
```

`--mode update` змінює налаштування наявного провізіонера (строки, обмеження SAN, виклики ACME, виклик SCEP):
налаштування оновлюються в `ca.json` через `step ca provisioner update`, CA м’яко перечитує їх (SIGHUP), а
обмеження строків оновлюються в базі UI. Для JWK наявні приватний ключ і пароль за замовчуванням зберігаються.

Потім на сторінці **Випустити сертифікат** виберіть провізіонер. Шаблони UI (`server` / `internal` / …) лише
заповнюють форму й провізіонер CA не змінюють. Строк не може перевищувати максимум цього JWK. Системний
провізіонер (`admin`) цим командним рядком не перезаписується.

</details>

<details>
<summary><b>Як створити JWK-провізіонер з паролем на зовнішньому step-ca (Ubuntu 24 на хості чи віддалений)?</b></summary>

Step-CA UI працює з step-ca через **JWK-провізіонер** з паролем і підтримує шаблони сертифікатів строком до 10 років (`87600h`).

1. На машині зі step-ca створіть JWK-провізіонер із подовженими обмеженнями строку:

```bash
step ca provisioner add admin \
  --type JWK \
  --create \
  --x509-default-dur 8760h \
  --x509-max-dur 87600h
```
*(Якщо налаштування CA лежать в іншому місці, додайте `--ca-config /etc/step-ca/config/ca.json`)*.

`step` запитає пароль, яким буде зашифровано приватний ключ нового JWK.

2. Якщо провізіонер з таким ім’ям уже є, оновіть його обмеження строку:

```bash
step ca provisioner update admin \
  --x509-default-dur 8760h \
  --x509-max-dur 87600h \
  --ca-config /etc/step-ca/config/ca.json
```

3. Перезапустіть `step-ca`, щоб застосувати зміни:

```bash
sudo systemctl restart step-ca
```

4. У Step-CA UI відкрийте **Адмін → Налаштування CA** (`/admin/ca`):
- введіть адресу зовнішнього CA (напр., `https://192.168.1.50:9443` або `https://ca.internal:443`);
- введіть ім’я провізіонера (`admin`) і заданий пароль;
- завантажте `root_ca.crt` і `intermediate_ca.crt` (тека `certs/` step-ca) або змонтуйте шлях через `CA_HOST_PATH`;
- натисніть **Зберегти налаштування**, потім **Перевірити зв’язок із CA**.
</details>

<details>
<summary><b>Як скинути пароль адміністратора?</b></summary>

```bash
sudo docker compose exec postgres psql -U stepui -d stepui -c \
  "UPDATE users SET password_hash = encode(sha256('newpass'::bytea), 'hex') WHERE username='admin';"
```
Потім увійдіть як `admin` / `newpass` і змініть пароль в інтерфейсі.
Старий формат SHA-256 приймається для відновлення й після входу переводиться на bcrypt.
</details>

<details>
<summary><b>Браузер попереджає про самопідписаний сертифікат. Як поставити свій?</b></summary>

Замініть `step-ui-go/ssl/server.crt` і `server.key` своїми сертифікатом і ключем (напр., від Let’s Encrypt чи
внутрішнього CA) і перезапустіть `step-ui`. Сертифікат має містити ваш `HOST_IP` або ім’я хоста.
</details>

<details>
<summary><b>Чи можна запустити це за Cloudflare / Caddy / nginx?</b></summary>

Так. Направте зворотний проксі на `step-ui:8443` (HTTPS) або переведіть step-ui на звичайний HTTP і завершуйте TLS
на проксі (без файлу `server.crt` застосунок сам слухає HTTP). Передавайте `X-Forwarded-Proto: https`, щоб step-ui
формував правильні адреси.
</details>

<details>
<summary><b>Як оновитися до нової версії?</b></summary>

```bash
sudo ./install.sh --mode update --lang en
```
Режим оновлення спершу робить резервну копію, зберігає наявні томи Docker, за бажанням перемикається на вибраний
тег, а міграції виконуються автоматично під час запуску. Спершу завжди читайте
[примітки до релізів](https://github.com/UncleFi1/step-ca-ui/releases) — великі версії можуть бути несумісними.
</details>

## Участь у розробці

Pull request’и вітаються. Для великих змін спершу відкрийте issue й обговоріть, що саме хочете змінити.

```bash
git clone https://github.com/UncleFi1/step-ca-ui.git
cd step-ca-ui/step-ui-go
go mod download
go run .  # requires running postgres + step-ca
```

Перед надсиланням:
- виконайте `gofmt -w .` і `go vet ./...`
- оновіть відповідні тести
- робіть коміти змістовними й зосередженими на одній зміні

### Переклад (форк)

Українська — мова вихідного тексту й ключ перекладу: у шаблонах текст обгорнуто в `{{T "..."}}`, англійський
каталог — `step-ui-go/i18n/locales/en.json`. Новий або змінений текст інтерфейсу — додати його переклад у
`en.json`: тест `TestTemplateKeysTranslated` не пропустить шаблон без перекладу, а `TestTemplatesExecute` —
українське слово на англійській сторінці. Апостроф — типографський (’), щоб не обривати рядки в JS / HTML.

## Структура проєкту

```
.
├── docker-compose.yml         # 3 services: postgres, step-ca, step-ui
├── .env.example               # configuration template
├── install.sh                 # one-shot installer
├── LICENSE                    # GPL-3.0
├── README.md                  # this file (Ukrainian, shown by default)
├── README.en.md               # English
├── README.ru.md               # Russian
└── step-ui-go/
    ├── main.go                # entry point, router setup
    ├── config/                # env-based config loader
    ├── db/                    # all SQL queries
    ├── handlers/              # HTTP handlers (one file per area)
    ├── i18n/                  # translation (Ukrainian source, locales/en.json)
    ├── middleware/            # auth, security headers, CSRF
    ├── models/                # data structs
    ├── security/              # password hashing, rate limiting, CSRF
    ├── templates/             # HTML templates (Go html/template)
    ├── static/                # CSS, JS, favicon, images
    ├── Dockerfile             # multi-stage Alpine build
    └── entrypoint.sh          # waits for deps, generates SSL, starts app
```

## Ліцензія

Проєкт поширюється за ліцензією **GNU General Public License v3.0** — див. файл [LICENSE](LICENSE).

Коротко: програму можна використовувати, змінювати й поширювати, але похідні роботи теж мають виходити під GPLv3.
