<!--
SPDX-FileCopyrightText: 2026-Present DVB Studio

SPDX-License-Identifier: AGPL-3.0-only
-->

# Как развернуть свой DV Auth

Инструкция для тех, кто скачал исходный код и хочет запустить сервис у себя. Ничего, кроме
PostgreSQL и вашего сервера, не нужно. Чужих сервисов в коде нет.

Порядок: подготовить базу, настроить dvauth.env, применить миграции, запустить, поставить за
прокси публичный порт, подключить приложение.

## 1. Что понадобится

- Сервер с Linux (подойдёт и маленький).
- PostgreSQL 14 или новее. Отдельная база и пользователь для DV Auth.
- Node.js 22 или новее, либо Docker.
- Для основного способа (подтверждение в чате): сервер Matrix (Synapse) и приложение чата с
  поддержкой подтверждения. Без них можно пользоваться только кодами из приложения.
- Для публичного порта: обратный прокси с HTTPS (nginx, Caddy и т.п.) и доменное имя.

## 2. База данных

Создайте пользователя и базу:

    sudo -u postgres psql -c "CREATE USER dvauth WITH PASSWORD 'придумайте-пароль'"
    sudo -u postgres psql -c "CREATE DATABASE dvauth OWNER dvauth"

Таблицы сервис создаёт сам при миграции (шаг 4).

## 3. Настройки

Скопируйте образец и заполните:

    cp dvauth.env.example dvauth.env
    chmod 600 dvauth.env

Что в нём важно:

- **DVAUTH_DATABASE_URL**: адрес базы из шага 2.
- **DVAUTH_CLIENTS**: список ваших приложений. У каждого свои id, название (его увидит человек в
  приложении чата, например «DV Cloud») и секрет не короче 32 символов. Секрет получите командой
  `openssl rand -hex 32`. Тот же секрет вы укажете в настройках самого приложения.
- **DVAUTH_TOTP_KEY**: ключ шифрования секретов TOTP, не короче 32 символов (`openssl rand -hex 32`).
  Сохраните его в надёжном месте: без него записанные коды из приложений не расшифровать,
  придётся включать заново. Пусто: способ «коды из приложения» выключен.
- **DVAUTH_MATRIX_SERVER_NAME** и **DVAUTH_MATRIX_URL**: имя вашего Matrix-сервера и адрес, по
  которому DV Auth может обратиться к Synapse. Пусто: способ «подтверждение в чате» выключен.
  Требования к Synapse описаны в docs/CHAT.md.

Нужен хотя бы один из двух способов, иначе сервис не запустится.

Файл dvauth.env содержит секреты: не добавляйте его в git (он в .gitignore) и не показывайте
в чатах и журналах.

## 4. Миграции и запуск

Вариант без Docker:

    npm ci --omit=dev
    node --env-file=dvauth.env src/migrate-cli.js
    node --env-file=dvauth.env src/main.js

В журнале появится строка «DV Auth: публичный ..., внутренний ..., приложений: N». Проверка:

    curl http://127.0.0.1:3011/health
    curl http://127.0.0.1:3010/health

Каждый ответ содержит `"status":"ok"`.

### Запуск как служба (systemd)

Создайте /etc/systemd/system/dvauth.service (пути поправьте под себя):

    [Unit]
    Description=DV Auth
    After=network.target postgresql.service

    [Service]
    User=dvauth
    WorkingDirectory=/opt/dvauth
    ExecStartPre=/usr/bin/node --env-file=/etc/dvauth/dvauth.env src/migrate-cli.js
    ExecStart=/usr/bin/node --env-file=/etc/dvauth/dvauth.env src/main.js
    Restart=on-failure
    NoNewPrivileges=true
    ProtectSystem=strict
    ProtectHome=true
    PrivateTmp=true

    [Install]
    WantedBy=multi-user.target

Затем `systemctl daemon-reload` и `systemctl enable --now dvauth`.

### Запуск в Docker

В репозитории есть Dockerfile и пример docker-compose.example.yml (сервис и своя база).

    cp docker-compose.example.yml docker-compose.yml
    cp dvauth.env.example dvauth.env          # заполните
    echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
    docker compose up -d --build

Порты в примере опубликованы только на 127.0.0.1. Миграции применяются при каждом старте
контейнера.

## 5. Публичный порт за прокси

Приложение чата ходит на публичный порт из интернета, поэтому его нужно вывести наружу через
HTTPS. **Выводите только три адреса.** Остальное закрыто и так, но лишнего открывать не стоит.

Пример для nginx:

    server {
        listen 443 ssl;
        server_name auth.example.org;
        # ... ssl_certificate и ssl_certificate_key ...

        location = /health            { proxy_pass http://127.0.0.1:3010; }
        location = /v1/chat/info      { proxy_pass http://127.0.0.1:3010; }
        location = /v1/chat/confirm   { proxy_pass http://127.0.0.1:3010; proxy_set_header X-Forwarded-For $remote_addr; }
        location /                    { return 404; }
    }

Настройте DVAUTH_TRUST_PROXY=1 (один прокси перед сервисом): тогда сервис берёт настоящий адрес
клиента из X-Forwarded-For и блокирует перебор по нему, а не по адресу прокси. Заголовок надо
**перезаписывать** на прокси (как в примере), а не дописывать, иначе клиент подставит чужой адрес.

**Внутренний порт 3011 в интернет не выводится никогда.** Если ваше приложение стоит на другой
машине, соедините их по внутренней сети или через защищённый туннель и привяжите
DVAUTH_INTERNAL_HOST к внутреннему адресу.

## 6. Подключение приложения

В настройках приложения укажите адрес внутреннего порта и секрет из DVAUTH_CLIENTS. Как приложение
пользуется сервисом: docs/INTEGRATION.md.

## 7. Обновление

    git pull
    npm ci --omit=dev
    node --env-file=dvauth.env src/migrate-cli.js
    # перезапустите службу

Миграции только добавляют, повторный запуск безопасен.

## 8. Резервные копии

Сохраняйте базу (`pg_dump dvauth`) и ключ DVAUTH_TOTP_KEY. Копия базы без ключа бесполезна для
кодов из приложения, но привязки к чату и запасные коды в ней сохранятся.

## 9. Если что-то не работает

- Сервис не стартует и пишет «DVAUTH_...»: проверьте переменную из сообщения.
- Приложение получает 503 «Сервис второго фактора недоступен»: не тот секрет приложения, не тот
  адрес внутреннего порта или сервис не запущен. Смотрите журнал DV Auth.
- Подтверждение в чате отвечает «Чат сейчас недоступен»: DV Auth не может обратиться к Synapse по
  DVAUTH_MATRIX_URL или в Synapse не включён нужный ресурс (docs/CHAT.md).
- Человек потерял телефон и запасные коды: приложение вызывает сброс (`POST /v1/reset`) по решению
  администратора, и человек настраивает второй фактор заново.
