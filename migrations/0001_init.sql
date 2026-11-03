-- DV Auth: второй фактор входа для нескольких приложений (клиентов).
-- Человек определяется парой (клиент, subject): subject это стабильный идентификатор человека в приложении.

-- Способ 1 (запасной): коды из приложения-аутентификатора (TOTP, RFC 6238). Секрет зашифрован (AES-256-GCM).
CREATE TABLE totp (
  client       text NOT NULL,
  subject      text NOT NULL,
  secret_enc   text NOT NULL,
  confirmed_at timestamptz,               -- пока NULL, TOTP ещё не включён
  last_step    bigint NOT NULL DEFAULT 0, -- последний принятый 30-секундный шаг: код нельзя применить дважды
  PRIMARY KEY (client, subject)
);

-- Запасные коды: в базе только хеш.
CREATE TABLE recovery_codes (
  id        bigserial PRIMARY KEY,
  client    text NOT NULL,
  subject   text NOT NULL,
  code_hash bytea NOT NULL,
  used_at   timestamptz,
  UNIQUE (client, subject, code_hash)
);

-- Способ 2 (основной): какой аккаунт Matrix (DVChat) подтверждает вход этого человека.
CREATE TABLE chat_links (
  client    text NOT NULL,
  subject   text NOT NULL,
  matrix_id text NOT NULL,
  linked_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (client, subject),
  UNIQUE (client, matrix_id)
);

-- Талон второго шага: выдаётся приложением после верного пароля, живёт 5 минут, пять неверных кодов его сжигают.
CREATE TABLE tickets (
  id         bigserial PRIMARY KEY,
  token_hash bytea NOT NULL UNIQUE,
  client     text NOT NULL,
  subject    text NOT NULL,
  fails      int NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL
);

-- Запрос подтверждения в чате (для входа или привязки). Его идентификатор попадает в QR-код.
CREATE TABLE challenges (
  id         text PRIMARY KEY,
  client     text NOT NULL,
  subject    text NOT NULL,
  purpose    text NOT NULL CHECK (purpose IN ('login', 'link')),
  ticket_id  bigint REFERENCES tickets(id) ON DELETE CASCADE,
  number     text NOT NULL,               -- число, которое человек вводит в приложении чата
  fails      int NOT NULL DEFAULT 0,
  matrix_id  text,                        -- заполняется при подтверждении
  state      text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'dead')),
  ip         text NOT NULL,               -- откуда запрошен вход (показывается человеку в чате)
  agent      text NOT NULL DEFAULT '',
  expires_at timestamptz NOT NULL
);
CREATE INDEX challenges_subject_idx ON challenges (client, subject, purpose);

-- Неудачные попытки: по ним ограничивается подбор кодов.
CREATE TABLE attempts (
  id  bigserial PRIMARY KEY,
  key text NOT NULL,
  ip  text NOT NULL,
  at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX attempts_key_idx ON attempts (key, at);
CREATE INDEX attempts_ip_idx ON attempts (ip, at);

-- Журнал событий безопасности (без кодов и токенов).
CREATE TABLE events (
  id      bigserial PRIMARY KEY,
  at      timestamptz NOT NULL DEFAULT now(),
  client  text NOT NULL,
  subject text NOT NULL,
  kind    text NOT NULL,
  ip      text NOT NULL DEFAULT ''
);
CREATE INDEX events_subject_idx ON events (client, subject, at);
