# AGENTS.md — карта proxykit для ИИ-агентов

Прочитай этот файл целиком перед любой правкой. Он короткий специально.

## Суть за 30 секунд

`proxykit` — Go-библиотека (Go 1.22+, **только стандартная библиотека**), которая
превращает строку прокси в рабочий TCP-туннель:

```text
строка ──Parse──▶ Spec ──New / NewDialer──▶ *Dialer ──DialContext──▶ net.Conn
                                              ├─ Transport()  → *http.Transport
                                              ├─ Check()      → доступность цели
                                              ├─ SpeedTest()  → здоровье + скорость
                                              └─ Inspect()    → протокол, задержка, страна
```

Протоколы: HTTP CONNECT, HTTPS CONNECT, SOCKS5 CONNECT. Больше ничего.

## Инварианты (нарушение = баг, даже если тесты зелёные)

1. **Обход VPN включён по умолчанию.** `DialOptions{}` → `RouteBypass`.
   Выключается **только** через `DialOptions.Advanced` (`DisableBypass` или
   `Forward`). Не добавляй других способов выключить обход и не меняй дефолт.
2. **Нет тихих fallback.** Нет прямого соединения с целью; нет маршрута через
   VPN, если нет физического интерфейса (`ErrNoInterface`); нет перехода на
   маршрут ОС там, где обход не поддерживается (`ErrBypassUnsupported`).
3. **Конфликт настроек — ошибка, а не приоритет.** `Bypass` + `Advanced.*` → `ErrInvalid`.
4. **Вся разница между ОС — только в `platform_<os>.go`.** Портируемый код
   вызывает `backend.*` и никогда не проверяет `runtime.GOOS` (линтер это ловит).
5. **`Parse*` не ходит в сеть.** Протокол без схемы остаётся `Auto`; по порту не угадывается.
6. **Ошибки не содержат credentials и текст удалённого сервера.** Причина — через
   `errors.Is/As` на `*OpError` и sentinel `Err*` (`errors.go`).
7. **Ноль внешних зависимостей** в `go.mod`. `depguard` в линтере это проверяет.
8. Ресурсы: туннель после успешного `DialContext` принадлежит вызывающему; всё
   пробное (`Detect`, `Check`, `SpeedTest`) библиотека закрывает сама до возврата.

## Где что лежит

| Хочу изменить… | Файл |
|---|---|
| Модель прокси, валидацию | `spec.go` |
| Разбор строк / JSON / списков | `parse.go`, `parse_layout.go`, `parse_json.go`, `parse_lines.go` |
| Жизненный цикл сокета, таймауты, TLS к прокси | `dial.go` |
| **Как сокет доходит до прокси** (bypass / system / custom) | `route.go` → `buildRoute` |
| Логику обхода VPN: выбор интерфейса, DNS, DoT, кэши, перебор адресов | `bypass.go` |
| Общий маршрут для диалеров одной операции (`sharedRoute`) | `dial.go` |
| Поведение на конкретной ОС | `platform_darwin.go`, `platform_linux.go`, `platform_windows.go`, `platform_unsupported.go` |
| Контракт платформ, таблицу ОС | `platform.go` (`platformBackend`, `Platform`) |
| HTTP CONNECT / SOCKS5 handshake | `http_connect.go`, `socks5.go` |
| Проверки, автоопределение протокола, пакетные проверки | `check.go`, `detect.go`, `batch.go` |
| Скорость, страна | `speed.go`, `inspect.go` |
| Ошибки и стадии | `errors.go` |
| Браузерный relay | `relay/` |
| Параметры ротационных прокси в логине | `gateway/` |

## Платформы

| GOOS | Обход | Механизм | Таблица маршрутов |
|---|---|---|---|
| darwin | да | `IP_BOUND_IF` / `IPV6_BOUND_IF` | `sysctl NET_RT_DUMP` |
| linux | да | `SO_BINDTODEVICE` (Linux 5.7+ или `CAP_NET_RAW`) | `/proc/net/route` |
| windows | да | `IP_UNICAST_IF` | `GetIpForwardTable` |
| всё остальное | нет | — | — |

Цель — настольные Windows/macOS/Linux. `ios` и `android` только собираются
(build tags `darwin`/`linux`), мобильные сценарии не поддерживаются.

Добавить ОС: создай `platform_<os>.go` с `//go:build <os>` и
`var backend platformBackend = <os>Backend{}`, сузь build tag в
`platform_unsupported.go`, добавь цель в `CROSS_TARGETS` в `Makefile`, обнови
таблицы в `platform.go`, здесь и в `README.md`.

## Команды

```sh
make check   # ОБЯЗАТЕЛЬНО перед завершением: gofmt + vet + golangci-lint + кросс-сборка + race-тесты
make cross   # только кросс-сборка (после любой правки platform_*.go)
make lint    # только линтер
make test    # быстрые тесты
```

Тесты используют локальные TCP/TLS fixtures (`fixtures_test.go`), внешняя сеть
не нужна. Loopback-прокси никогда не привязываются к интерфейсу, поэтому тесты
с `DialOptions{}` работают на любой машине.

## Стиль

- Комментарии в коде — английские, документация (`README.md`, `docs/`) — русская.
- У каждого экспортируемого символа есть doc comment (`revive: exported`).
- Не добавляй фасадов, type aliases, `Client`-обёрток и глобального состояния.
- Новый публичный API — сначала строка в таблице `docs/architecture.md`.
- Не используй `//nolint` без причины: `nolintlint` требует объяснение.
