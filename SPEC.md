# AOT-EV1 — спецификация формата доказательства (v0.1, черновик)

Статус: контракт для реализации MVP. Менять только через запись в DECISIONS_LOG.
Слой доказательств под слот `evidenceHash` стандарта ERC-8325: кто заявил, что именно, и до какого срока это верно.

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

`Identity = {"scheme": "ed25519"|"eip712", "key_id": str, "display": str|null}`
— для `ed25519` `key_id` = 64 hex (сырой публичный ключ); для `eip712` — адрес EIP-55 (42 символа).

`Subject = {"type": str, "hash_alg": "sha256", "hash": str, "uri": str|null}`
— `hash` = 64 hex; `uri` — необязательная ссылка на документ.

**Запрещено:** float в любом месте; числа по модулю > 2^53−1; ключи объектов вне `[A-Za-z0-9_.-]`;
дубликаты ключей; строки с одиночными суррогатными кодами.

## 3. Канонизация (JCS RFC 8785, подмножество)

- Ключи объектов сортируются по код-поинтам (при ограничении §2 это совпадает с UTF-16-порядком JCS).
- Сериализация: `,` и `:` без пробелов; строки — `ensure_ascii=True`; `\uXXXX` в нижнем регистре hex;
  экранируются только `"`, `\` и управляющие `< 0x20` (`\b \f \n \r \t`, иначе `\u00XX`).
- Целые — без ведущих нулей, без `+`, `-0` недопустим.
- Пустой объект `{}`, пустой массив `[]`.
- Инвариант: `canonical(x)` дважды → идентичные байты; кодировка UTF-8, NFC не применяется (вход уже ASCII-ключи).

## 4. Подписи

| Роль | Схема | Что подписывается |
|---|---|---|
| issuer | ed25519 | `b"AOT-EV1-sig-v1\x00" ‖ evidence_hash` |
| auditor | ed25519 | `b"AOT-EV1-aud-v1\x00" ‖ evidence_hash` |
| issuer / auditor | eip712 | typed data: домен `{"name":"AOT-EV1","version":"1","chainId":<int>}` (поле `verifyingContract` **не включается**), тип `Evidence` = поля payload, вложенные типы `Identity` и `Subject`; сообщение — сам payload |

Проверка Ed25519 — модуль `aot_ev1.ed25519_strict.verify_strict` (S<L, каноничность R и ключа, запрет
8 точек малого порядка). Схема из `issuer.scheme` обязана совпадать с фактически проверенной.
`auditor.key_id` обязан отличаться от `issuer.key_id`.

## 5. Срок и отзыв

- `valid_until` входит в подписанное сообщение: продлить нельзя, не выпустив новый бандл.
- `revocation` — тоже внутри подписанного payload; отзыв постфактум = новый бандл с тем же `subject`
  и `prev_evidence_hash`, указывающим на отзываемый.
- Верификатор считает просроченный или отозванный бандл **валидным по подписи**, но со статусом
  `expired` / `revoked` (код выхода 3), а не «битым».

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
{"v":"1","created_at":<int>,"evidence_hash":"<hex>","payload_sha256":"<hex>",
 "entries":[{"name":"payload.json","sha256":"<hex>","size":<int>}, …],
 "signatures":[{"role":"issuer","scheme":"ed25519","key_id":"<hex>","file":"signatures/issuer.ed25519"}, …],
 "bundle_hash":"<hex>"}
```

Zip: `ZIP_STORED`, `date_time=(1980,1,1,0,0,0)`, `create_system=0`, `external_attr=0o100644<<16`,
`flag_bits=0`, без extra-полей и комментариев, имена — ASCII. Пределы: ≤ 32 записи, ≤ 8 МиБ распакованных.

## 7. bundle_hash

```
digest_i = sha256(content_i)
bundle_hash = sha256( b"".join(name_i.encode() + b"\x00" + digest_i for name_i in sorted(names)) )
```

Порядок — по возрастанию имён, разделителей между записями нет (длина имени известна из строки).

## 8. Верификация (12 шагов)

| # | Проверка | Код ошибки |
|---|---|---|
| 1 | файл открывается как zip | `E_BUNDLE_NOT_ZIP` |
| 2 | нет дублей имён, нет `..`/абсолютных путей, только ASCII | `E_ENTRY_NAME` |
| 3 | `manifest.json` в корне ровно один; все записи перечислены | `E_MANIFEST` |
| 4 | `bundle_hash` пересчитан по §7 и совпал | `E_BUNDLE_HASH` |
| 5 | sha256 каждой записи совпал с манифестом | `E_ENTRY_HASH` |
| 6 | `payload.json` == канонические байты разобранного payload | `E_CANONICAL` |
| 7 | payload проходит JSON Schema (`schema/aot-ev1.schema.json`) | `E_SCHEMA` |
| 8 | `evidence_hash` пересчитан по §1 и совпал с манифестом | `E_EVIDENCE_HASH` |
| 9 | подпись issuer валидна для своей схемы | `E_SIGNATURE` |
| 10 | подпись auditor валидна и ключ ≠ issuer | `E_AUDITOR` |
| 11 | `valid_from ≤ now ≤ valid_until` (если задан) и `revocation == null` | `E_EXPIRED` / `E_REVOKED` |
| 12 | если задан `--chain <prev.aotev.zip>`: `prev_evidence_hash` == его `evidence_hash` | `E_CHAIN` |

Без `--chain` шаг 12 пропускается, статус `chain: unverified` (это **не** ошибка).
Сеть не используется ни на одном шаге.

Коды выхода CLI: `0` валиден, `2` битый (шаги 1–10), `3` валиден по подписи, но просрочен/отозван,
`4` ошибка цепочки.

## 9. Версионирование

`v` в payload и в манифесте — целое в строке. Любое изменение байтов формата = `v2` и новый
`evidence_hash`-домен (`b"AOT-EV2"`). Векторы версии 1 остаются в репозитории навсегда.
