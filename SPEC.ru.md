# AOT-EV1 — спецификация формата доказательства (v1)

Статус: контракт для реализации. Изменения на уровне байтов допускаются только через запись в
DECISIONS_LOG; любое изменение после заморозки v1 требует `v2` (§9).
Слой доказательств под слот `evidenceHash` стандарта ERC-8325: кто заявил, что именно, и до какого
срока это верно.

## 1. Единицы формата

- `payload` — JSON-объект (см. §2). Хранится в бандле **ровно в канонических байтах** (§3).
- `evidence_hash` — 32 байта: `sha256(b"AOT-EV1" ‖ canonical_bytes)` (конкатенация без разделителя;
  канонический JSON всегда начинается с `{`, поэтому префикс однозначно отделён).
- `bundle` — zip-файл `<evidence_hash-в-hex>.aotev.zip` (§6).
- `bundle_hash` — 32 байта, привязка содержимого бандла (§7).

## 2. Payload

| Поле | Тип | Обяз. | Правила |
|---|---|---|---|
| `v` | str | да | ровно `"1"` |
| `issuer` | Identity | да | кто заявил |
| `auditor` | Identity \| null | да (может быть null) | кто независимо подтвердил |
| `subject` | Subject | да | о чём заявление |
| `claims` | object | да (может быть пустым) | произвольные значения без float |
| `valid_from` | int | да | unix-секунды, `≥ 0` |
| `valid_until` | int \| null | да | unix-секунды, `> valid_from` либо null |
| `nonce` | str | да | 64 hex-символа (32 байта), криптослучайный |
| `prev_evidence_hash` | str \| null | да | 64 hex или null (цепочка версий) |
| `revocation` | object \| null | да | `{"revoked_at": int, "reason": str}` или null |
| `superseded_by` | str \| null | нет (опционально) | 64 hex evidence_hash бандла-замены |
| `revoked_by` | str \| null | нет (опционально) | 64 hex evidence_hash бандла-отзыва |
| `domain` | object | нет (опционально) | эхо домена подписи; обязан совпадать с доменом манифеста |

`Identity = {"scheme": "ed25519"|"eip712", "key_id": str, "display": str|null}`
— для `ed25519` `key_id` = 64 hex (сырой публичный ключ); для `eip712` — адрес EIP-55 (42 символа).

`Subject = {"type": str, "hash_alg": "sha256", "hash": str, "uri": str|null}`
— `hash` = 64 hex; `uri` — необязательная ссылка на документ.

`domain` (если задан) = `{"name": "AOT-EV1", "version": "1", "chain_id": int}`.

**Запрещено:** float в любом месте; числа по модулю > 2^53−1; ключи объектов вне `[A-Za-z0-9_.-]`;
дубликаты ключей; строки с одиночными суррогатными кодами.

`superseded_by` и `revoked_by` взаимоисключающие (§5).

## 3. Канонизация (JCS RFC 8785, подмножество)

- Ключи объектов сортируются по код-поинтам (при ограничении §2 это совпадает с UTF-16-порядком JCS).
- Сериализация: `,` и `:` без пробелов; строки — `ensure_ascii=True`; `\uXXXX` в нижнем регистре hex;
  экранируются только `"`, `\` и управляющие `< 0x20` (`\b \f \n \r \t`, иначе `\u00XX`).
- Целые — без ведущих нулей, без `+`, `-0` недопустим.
- Пустой объект `{}`, пустой массив `[]`.
- Инвариант: `canonical(x)` дважды → идентичные байты; кодировка UTF-8, NFC не применяется
  (ключи уже ASCII).

## 4. Подписи

| Роль | Схема | Что подписывается |
|---|---|---|
| issuer | ed25519 | `b"AOT-EV1-sig-v1\x00" ‖ evidence_hash` |
| auditor | ed25519 | `b"AOT-EV1-aud-v1\x00" ‖ evidence_hash` |
| issuer / auditor | eip712 | typed data: домен `{"name":"AOT-EV1","version":"1","chainId":<int>}` (поле `verifyingContract` **не включается**), тип `Evidence` = поля payload, вложенные типы `Identity`, `Subject`, `Revocation`; сообщение — сам payload |

EIP-712 `chainId` берётся из `chain_id` в `manifest.domain` (§6); верификатор использует значение
из манифеста. Необязательные поля payload `superseded_by` и `revoked_by` входят в тип `Evidence`
(как `string`, null кодируется нулевым `bytes32`), поэтому подпись их связывает.
Бандлы, выпущенные до заморозки v1 без `domain` в манифесте, использовали более раннее описание
typed data без этих двух полей; они проверяются в legacy-режиме (§6) и получают `valid_legacy`.

Проверка Ed25519 — модуль `aot_ev1.ed25519_strict.verify_strict` (S<L, каноничность R и ключа, запрет
8 точек малого порядка). Схема из `issuer.scheme` обязана совпадать с фактически проверенной.
`auditor.key_id` обязан отличаться от `issuer.key_id`.

## 5. Срок, отзыв и замена

- `valid_until` входит в подписанное сообщение: продлить нельзя, не выпустив новый бандл.
- `revocation` — тоже внутри подписанного payload; отзыв постфактум = новый бандл с тем же `subject`
  и `prev_evidence_hash`, указывающим на отзываемый.
- Если задан `revocation.revoked_at`, обязателен `revoked_by` (`E_REVOCATION_INCOMPLETE`).
  `revoked_by` без `revocation.revoked_at` — тоже неполная семантика.
- `superseded_by` даёт статус `superseded`, `revoked_by` — `revoked`. Оба одновременно —
  `E_REVOCATION_CONFLICT`. Все три поля подписаны, поэтому статус нельзя приписать постфактум.
- Бандл отзыва подписывает issuer. Библиотека никогда не ходит в сеть: опрашивать ли URL — решает
  вызывающий. **Офлайн-предел:** без онлайн-проверки верификатор не узнает об отзыве, выпущенном
  после получения бандла; свежесть — ответственность вызывающего.

Статусы: `valid`, `valid_legacy`, `superseded`, `revoked`, `revocation_incomplete`,
`revocation_conflict`, `expired`. Бандл с валидной подписью в любом неактивном статусе — не
«битый»: код выхода 3 (§8).

## 6. Бандл

Записи (порядок фиксирован, `manifest.json` первым, остальные — по возрастанию имени):

```
manifest.json
payload.json                      # ровно канонические байты
signatures/issuer.ed25519         # 64 байта
signatures/issuer.eip712          # 65 байт (r||s||v), если схема eip712
signatures/auditor.ed25519        # если есть аудитор
signatures/auditor.eip712         # если есть
```

`manifest.json` (тоже канонические байты):

```json
{"v":"1","created_at":<int>,
 "domain":{"name":"AOT-EV1","version":"1","chain_id":<int>},
 "evidence_hash":"<hex>","payload_sha256":"<hex>",
 "entries":[{"name":"payload.json","sha256":"<hex>","size":<int>}, …],
 "signatures":[{"role":"issuer","scheme":"ed25519","key_id":"<hex>","file":"signatures/issuer.ed25519"}, …],
 "bundle_hash":"<hex>"}
```

`domain` — единственный носитель `chain_id` (отдельного top-level `chain_id` нет). Манифест не
подписывается: для EIP-712 домен аутентифицирован (он входит в typed-data домен), для Ed25519 он
информационный — разделение доменов там задаётся префиксами `AOT-EV1-sig-v1`/`AOT-EV1-aud-v1`.
Бандлы без `domain` — бандлы эпохи v0.1: они продолжают проверяться по legacy-формуле `bundle_hash` (§7),
получают статус `valid_legacy` и код выхода 0; молчаливого «апгрейда» нет.

Zip: `ZIP_STORED`, `date_time=(1980,1,1,0,0,0)`, `create_system=0`, `external_attr=0o100644<<16`,
`flag_bits=0`, без extra-полей и комментариев, имена — ASCII. Пределы: ≤ 32 записи, ≤ 8 МиБ
распакованных.

## 7. bundle_hash

```
digest_i = sha256(content_i)
bundle_hash = sha256( b"AOT-EV1-BUNDLE\x00" ‖ b"".join(name_i.encode() + b"\x00" + digest_i
                                                        for name_i in sorted(names)) )
```

Порядок — по возрастанию имён, разделителей между записями нет (длина имени известна из строки).
Доменный префикс не позволяет переиспользовать хэш в другом протоколе.

Legacy-бандлы (v0.1) без `domain` в манифесте используют ту же конструкцию **без** префикса
`b"AOT-EV1-BUNDLE\x00"`; больше ничего не меняется. Новые бандлы всегда используют префикс.

## 8. Верификация (12 шагов)

| # | Проверка | Код ошибки |
|---|---|---|
| 1 | файл открывается как zip | `E_BUNDLE_NOT_ZIP` |
| 2 | нет дублей имён, нет `..`/абсолютных путей, только ASCII | `E_ENTRY_NAME` |
| 3 | `manifest.json` в корне ровно один; все записи перечислены; `domain` корректен и совпадает с запрошенным `chain_id` | `E_MANIFEST` / `E_DOMAIN_MISMATCH` |
| 4 | `bundle_hash` пересчитан по §7 (с префиксом или legacy) и совпал | `E_BUNDLE_HASH` |
| 5 | sha256 каждой записи совпал с манифестом | `E_ENTRY_HASH` |
| 6 | `payload.json` == канонические байты разобранного payload | `E_CANONICAL` |
| 7 | payload проходит JSON Schema (`schema/aot-ev1.schema.json`); необязательный `domain` в payload равен домену манифеста | `E_SCHEMA` / `E_DOMAIN_MISMATCH` |
| 8 | `evidence_hash` пересчитан по §1 и совпал с манифестом | `E_EVIDENCE_HASH` |
| 9 | подпись issuer валидна для своей схемы | `E_SIGNATURE` |
| 10 | подпись auditor валидна и ключ ≠ issuer | `E_AUDITOR` |
| 11 | `valid_from ≤ now ≤ valid_until` (если задан) и статус отзыва/замены | `E_EXPIRED`, `E_SUPERSEDED`, `E_REVOKED`, `E_REVOCATION_INCOMPLETE`, `E_REVOCATION_CONFLICT` |
| 12 | если задан `--chain <prev.aotev.zip>`: `prev_evidence_hash` == его `evidence_hash` | `E_CHAIN` |

Без `--chain` шаг 12 пропускается, статус `chain: unverified` (это **не** ошибка).
Сеть не используется ни на одном шаге.

Коды выхода CLI: `0` валиден (`valid`, `valid_legacy`), `2` битый (шаги 1–10, включая
`E_DOMAIN_MISMATCH`), `3` валиден по подписи, но просрочен/заменён/отозван либо семантика отзыва
неполна/конфликтует, `4` ошибка цепочки.

## 9. Версионирование

`v` в payload и в манифесте — целое в строке. До первого внешнего пользователя контракт v1 был
один раз пересмотрен: домен подписи переехал в манифест, `bundle_hash` получил доменный префикс, а
`superseded_by`/`revoked_by` добавлены в подписанный payload. Эти правки входят в замороженный v1;
бандлы, выпущенные до них, проверяются как `valid_legacy`. После заморозки любое изменение байтов
формата = `v2` и новый `evidence_hash`-домен (`b"AOT-EV2"`). Векторы версии 1 остаются в репозитории
навсегда.
