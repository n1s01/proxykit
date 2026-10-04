# proxykit

Независимая Go-библиотека для разбора прокси, определения протокола, TCP-туннелей,
HTTP-клиентов, проверки доступности и локального relay для браузера.
Умеет обходить VPN/WARP и отдавать полную информацию о прокси: протокол, задержку, страну.
Go 1.22+, только стандартная библиотека, без Telegram, Chromium, базы данных и фоновых сервисов.

```text
строка → proxykit.New → Dialer → TCP / HTTP transport / browser relay
             │            └── Check → результат + типизированная ошибка
             └── Parse → Detect (только при неизвестном протоколе)
```

## Быстрый старт

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/n1s01/proxykit"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    proxy, err := proxykit.New(ctx, "user:pass:proxy.example@1080", proxykit.Options{
        Target: "web.telegram.org:443",
    })
    if err != nil { log.Fatal(err) }

    result, err := proxy.Check(ctx, proxykit.CheckOptions{
        URL: "https://web.telegram.org/",
    })
    if err != nil { log.Fatal(err) }
    log.Printf("%s: tunnel=%s, total=%s", proxy.Spec(), result.TunnelLatency, result.Duration)
}
```

Адрес `proxy.example` здесь пример. Подставьте свой прокси.
`web.telegram.org` — пример цели для браузера; для MTProto выбирайте фактический
адрес Telegram DC. Библиотека не обращается к внешним сервисам сама по себе;
исключение — запрос страны в `Inspect`, который можно заменить или отключить.

`Parse` определяет **формат строки**, без сети. `Detect` определяет **протокол**
через сеть, проверяя авторизацию и открывая туннель к указанной цели.
HTTP, HTTPS и SOCKS5 могут работать на любом порту: номер порта ничего не доказывает.
Неверный пароль, недоступная цель или неизвестный TLS-сертификат могут помешать
определению даже при работающем прокси; причины доступны в `Detection.Attempts`.

`Resolve` с явным протоколом только разбирает строку; это не проверка здоровья.
С `Auto` он делает `Detect`. Для дальнейшего `Check` открывается новый туннель.
Конкретный протокол стоит сохранять после успешного определения, чтобы не делать
три пробных подключения при каждом запросе.

`New` объединяет разбор, необходимое определение протокола и создание готового
`Dialer`. Для уже разобранного `Spec` используйте `NewDialer`; он требует
конкретный протокол. Явный протокол при создании не проверяется сетевым запросом:
проверить цель можно через `Dialer.Check`.

`Options.Dial` задаёт маршрут, timeout и TLS к прокси один раз. `Dialer.Check`
принимает только настройки проверки цели, поэтому тест и реальное подключение
используют один маршрут. `Dialer.Transport` и `relay.Start(d, ...)` используют
тот же диалер. Для собственного транспорта есть `ContextDialer` и
`NewHTTPTransport`; пакет `relay` принимает свой небольшой интерфейс `Dialer`.

## Структура и архитектура

```text
proxykit/
├── go.mod, LICENSE
├── doc.go, new.go               # описание пакета и удобный конструктор
├── spec.go, errors.go            # модель, валидация и ошибки
├── parse*.go                    # строки, JSON, списки
├── dial.go, conn.go              # подключение и владение соединением
├── http_connect.go, socks5.go    # протокольные handshake
├── http.go                      # адаптер net/http
├── check.go, detect.go, batch.go # проверки и определение протокола
├── inspect.go                   # протокол, задержка и страна одним вызовом
├── bind.go, bind_*.go            # обход VPN: привязка к физическому интерфейсу
├── *_test.go                    # unit, external API, сетевые тесты, fuzz
├── relay/                       # отдельный браузерный адаптер
├── examples/{tcp,http,browser}/  # компилируемые примеры
├── docs/                        # архитектура, аудит, результаты проверок
├── Makefile
└── .github/workflows/test.yml
```

Основной импорт — `github.com/n1s01/proxykit`; браузерный адаптер подключается
как `github.com/n1s01/proxykit/relay`. Публичные типы и функции определены
напрямую в своих файлах. Фасада с алиасами и отдельных пакетов для каждого
этапа операции нет. Файлы одного Go-пакета разделяют область видимости:
разделение по файлам помогает навигации, приватные детали остаются неэкспортируемыми.

`relay` зависит от основного пакета. Основной пакет не зависит от `relay`;
вызывающий код управляет жизненным циклом адаптера. Эта граница соответствует
отдельной интеграции с браузером и не требует лишнего слоя `Client`.

Подробно: [архитектура](docs/architecture.md),
[результаты проверок](docs/verification.md).

## Подключение

```sh
go get github.com/n1s01/proxykit
```

## Форматы

Протоколы подключения: HTTP CONNECT, HTTPS CONNECT, SOCKS5 CONNECT.
`socks` и `socks5h` нормализуются в SOCKS5 с удалённым DNS цели.

В коротких строках `:` разделяет поля. `@` может разделять только соседние
**host/ip и port**, в прямом или обратном порядке. Логин и пароль используют `:`.

| Короткий вход | Значение |
|---|---|
| `host:port`, `host@port` | endpoint без авторизации |
| `port:host`, `port@host` | обратный порядок endpoint при однозначном разборе |
| `host:port:login:pass`, `host@port:login:pass` | endpoint, затем авторизация |
| `login:pass:host:port`, `login:pass:host@port` | авторизация, затем endpoint |
| `[2001:db8::1]@1080` | IPv6 endpoint |

Без префикса/default протокол остаётся Auto. `Parse` не угадывает протокол по
порту. Для готового диалера `New` с Auto требуется `Options.Target`.

Стандартные URL разбираются отдельно по URL-правилам:
`http://user:pass@host:3128`, `https://user:pass@host:8443`,
`socks5://user:pass@host:1080`. Здесь `@` — часть URL-синтаксиса авторизации.
Без схемы короткая строка `user:pass@host:port` не является поддерживаемой формой;
используйте `user:pass:host@port` или стандартный URL с префиксом.

Чтобы назначить **любой порядок четырёх полей**, задайте `ParseOptions.Layout`.
Все 24 перестановки поддерживаются с `:`. Если host и port стоят рядом, их
разделитель можно заменить на `@` — ещё 12 вариантов. В остальных позициях `@`
отклоняется. Форматы из двух или трёх полей тоже поддерживаются.

Имена полей: `host` / `ip`, `port`, `user` / `username` / `login`,
`pass` / `password`. Host и port обязательны; credentials необязательны.
Дублирование поля, в том числе через разные алиасы, запрещено.
Регистр и пробелы вокруг названий Layout не важны. Значения credentials
буквальные; внешние пробелы всей строки очищаются.

```go
spec, err := proxykit.ParseWithOptions("host.example@1080:secret:alice", proxykit.ParseOptions{
    DefaultProtocol: proxykit.SOCKS5,
    Layout: "host@port:pass:login",
})
// spec.Host = "host.example", spec.Port = 1080
// spec.Username = "alice", spec.Password = "secret"
```

Другие соответствия:

| Layout | Вход |
|---|---|
| `port@host:login:pass` | `1080@host.example:alice:secret` |
| `pass:login:host@port` | `secret:alice:host.example@1080` |
| `login:ip@port:pass` | `alice:192.0.2.1@1080:secret` |
| `host:pass:port:login` | `host.example:secret:1080:alice` |
| `password:port@host` | `secret:8080@host.example` — password без username, если протокол это допускает |

```go
d, err := proxykit.New(ctx, "socks5://host.example@1080:secret:alice", proxykit.Options{
    Parse: proxykit.ParseOptions{Layout: "host@port:pass:login"},
})
```

Явный протокол приоритетнее `DefaultProtocol`. Явный Layout задаёт роли полей
после префикса, поэтому позволяет нестандартную запись с указанным протоколом.
В автоматическом режиме credentials идут как login, затем password. Для
обратного порядка задавайте Layout: определить эти роли только по тексту нельзя.
Стандартные colon-порядки проверяются первыми, другие принимаются при единственной
трактовке. `host:123:user:456` возвращает `ErrAmbiguous`.

`HostPortUserPass` и `UserPassHostPort` — готовые Layout для стандартных
colon-порядков. Несовпадение количества полей или разделителей с явным Layout
возвращает ошибку. Форматы `login@pass`, несколько `@` и разделитель `@` между
credentials и endpoint в короткой записи не поддерживаются.

В стандартных URL credentials используют percent escaping:
`p@ss:/%` → `p%40ss%3A%2F%25`. `Spec.URL()` экспортирует URL автоматически.
В явном Layout credentials буквальные: `%40` остаётся текстом `%40`.
Для credentials с разделителями `:` / `@` используйте стандартный URL с escaping
либо объект Spec / JSON. IPv6 в строках должен быть в скобках, порт — 1–65535.
Unicode-домены предварительно преобразуйте в punycode; IPv6 zone ID не поддерживается.

`ParseJSON` принимает строку, объект Spec или кортеж
`["socks5", "host", 1080, true, "user", "pass"]`. Layout применяется к JSON-строке;
объект и кортеж уже содержат роли полей. Дробные порты и `rdns=false` отклоняются.
`ParseLines` применяет одни ParseOptions ко всем строкам, игнорирует пустые строки
и комментарии `#`, возвращает значения и ошибки с номерами строк.

## TCP и HTTP

```go
p, err := proxykit.Parse("socks5://user:pass@host:1080")
if err != nil { return err }
d, err := proxykit.NewDialer(p, proxykit.DialOptions{})
if err != nil { return err }

conn, err := d.DialContext(ctx, "tcp", "149.154.167.50:443")
if err != nil { return err }
defer conn.Close()
// Используйте conn с выбранным TCP-протоколом.

tr := d.Transport()
defer tr.CloseIdleConnections()
client := &http.Client{Transport: tr, Timeout: 20*time.Second}
```

`Dialer` безопасен для параллельного использования. Setup timeout по умолчанию
10 секунд охватывает TCP, TLS к прокси, авторизацию и CONNECT. Отмена прерывает
сам handshake и закрывает сокет. После успешного возврата туннель принадлежит
вызывающему коду: отмена исходного контекста его не закрывает, deadlines очищены.
Дальнейший timeout чтения/записи задавайте через `conn.SetDeadline`.

`Transport` не использует `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`.
Прямого fallback нет. HTTP-запросы тоже используют CONNECT, в том числе к порту 80:
upstream-прокси должен это разрешать. Forward-only HTTP-прокси без CONNECT
не поддерживаются. Поддерживаются SOCKS5 no-auth и username/password, HTTP Basic.
SOCKS4, UDP ASSOCIATE, BIND, Digest, NTLM, HTTP/2 CONNECT и цепочки прокси отсутствуют.

## Сетевой маршрут и TLS

```go
d, err := proxykit.NewDialer(p, proxykit.DialOptions{
    Forward: customNetDialer.DialContext,
    Timeout: 8*time.Second,
    TLSConfig: proxyTLSConfig,
})
```

`Forward` открывает только TCP-соединение с прокси и обязан соблюдать контекст.
Так можно подключить собственный DNS, трассировку или тестовый транспорт.
По умолчанию используется обычный маршрут ОС. Для SOCKS5 имя цели разрешается
прокси; имя самого прокси разрешает `Forward`.

### Обход VPN и WARP

```go
d, err := proxykit.NewDialer(p, proxykit.DialOptions{
    Bypass: &proxykit.BypassOptions{},
})
```

`Bypass` привязывает соединение с прокси к физическому интерфейсу (Wi-Fi или
Ethernet), минуя туннели VPN/WARP (TUN). Тем же маршрутом идут `Check`, `Detect`,
`Inspect`, `Transport` и relay: настройка задаётся один раз в `DialOptions`.

- Запасного пути через туннель нет: без физического интерфейса подключение
  завершается `ErrNoInterface`.
- Имя прокси разрешается через публичные DNS по тому же интерфейсу: системный
  DNS при включённом VPN может отдавать адреса туннеля (fake-ip). Список
  меняется в `BypassOptions.DNS`, по умолчанию 1.1.1.1, 8.8.8.8, 77.88.8.8.
- Интерфейс выбирается при каждом подключении. `BypassOptions.Interface`
  закрепляет его по имени.
- Loopback-прокси не привязываются. `Forward` и `Bypass` вместе — ошибка.
- macOS: `IP_BOUND_IF`, интерфейсы `en*`. Linux: `SO_BINDTODEVICE`. Windows:
  `IP_UNICAST_IF`. На Linux и Windows туннели отсеиваются по имени адаптера;
  при нестандартном имени задайте `Interface`. На остальных системах
  `NewDialer` возвращает `ErrBypassUnsupported`; см. `BypassSupported()`.

`DialOptions.TLSConfig` относится к **HTTPS-прокси**.
`CheckOptions.TLSConfig` и `Transport.TLSClientConfig`
относятся к **целевому серверу**.
По умолчанию сертификаты проверяются; для приватных CA передавайте `RootCAs`.
Конфигурация диалера клонируется. Общие объекты сертификатов/пулов нельзя менять
во время запросов. HTTPS-прокси согласует ALPN `http/1.1`.

## Проверки и ошибки

`d.Check(ctx, opts)` проверяет через уже настроенный диалер. Самостоятельная
`Check(ctx, spec, opts)` использует стандартные параметры подключения. Если нужны
собственный маршрут или CA HTTPS-прокси, используйте `NewDialer` и его `Check`.
Для массовых проверок задавайте их в `BatchOptions.Dial`:

```go
outcomes, err := proxykit.CheckAll(ctx, specs, proxykit.BatchOptions{
    Check: proxykit.CheckOptions{Target: "target.example:443"},
    Dial: proxykit.DialOptions{Forward: customNetDialer.DialContext},
    Concurrency: 16,
})
```


- `CheckOptions{Target: "host:443"}`: TCP + полный proxy handshake и CONNECT.
- `Target` вместе с `TLSConfig`: дополнительно проверка TLS целевого сервера.
- `CheckOptions{URL: "https://host/health"}`: TLS + GET, ожидаются HTTP 200–299.
- `StatusCodes` меняет список допустимых ответов; redirect не выполняется.
- Проверка HTTP завершается на заголовках ответа. Это не загрузка тела и не speed test.
- `TunnelLatency` измеряет создание туннеля; `Duration` — всю проверку.
  Это не ICMP ping. Геолокацию делает только `Inspect`.
- `CheckAll` запускает фиксированное количество workers, по умолчанию 16,
  сохраняет порядок результатов и отдаёт частичные результаты при отмене.
- `Detect` параллельно проверяет максимум три протокола и закрывает все пробные
  соединения перед возвратом. Если proxy поддерживает несколько протоколов,
  побеждает первый успешный. Для фиксированного выбора укажите протокол явно.

### Полная информация о прокси

```go
info, err := proxykit.Inspect(ctx, spec, proxykit.InspectOptions{
    Target: "web.telegram.org:443", // свой хост для замера
    Dial:   proxykit.DialOptions{Bypass: &proxykit.BypassOptions{}},
})
// info.Proxy.Protocol, info.Latency, info.Country, info.IP
```

`Inspect` за один вызов определяет протокол (если он `Auto`), измеряет задержку
до `Target` и узнаёт страну выходного IP. Для готового диалера есть `d.Inspect`.

- `Latency` — время одного туннеля до `Target`: TCP до прокси, TLS к прокси,
  авторизация и CONNECT. Перебор остальных протоколов и запрос страны в него
  не входят; полное время операции — в `Duration`.
- Ошибка означает, что туннель до `Target` не открылся. Сбой геолокации
  ошибкой не считается: он попадает в `Info.GeoErr`, а `Country` остаётся пустой.
- Страна запрашивается через сам прокси. По умолчанию это `IPWhoIs`
  (`https://ipwho.is/`) — единственное обращение библиотеки к стороннему
  сервису. Свой сервис задаётся в `InspectOptions.Geo`, `SkipGeo` отключает запрос.
- `Timeout` ограничивает определение и замер, `GeoTimeout` — запрос страны
  (10 и 5 секунд по умолчанию).

```go
var op *proxykit.OpError
if errors.As(err, &op) {
    // dial, proxy_tls, negotiation, auth, connect, target_tls, http, geo
    log.Printf("phase=%s protocol=%s status=%d", op.Stage, op.Protocol, op.StatusCode)
}
if errors.Is(err, proxykit.ErrAuth) { /* credentials rejected */ }
if proxykit.IsTimeout(err) { /* deadline exceeded */ }
```

Неудачная проверка конкретной цели не доказывает, что прокси полностью нерабочий:
может действовать ACL по портам/адресам, отказать DNS цели или сам сервер.
Библиотека не хранит глобальный `Online`, не выбирает аккаунты, не переключает
IP и не разрешает прямое соединение. TTL статусов, ротация, retries и политика
fail-open/fail-closed принадлежат приложению.

`Spec.String()`, `%+v`, `%#v` и тексты библиотечных ошибок скрывают credentials.
`Spec.URL()`, JSON `Spec` и JSON `CheckResult` содержат credentials намеренно:
это конфигурация, а не готовый публичный API DTO. Для UI создавайте отдельный
DTO без пароля. `errors.Unwrap` раскрывает исходную ошибку, а пользовательский
`Forward` может включать чувствительные данные в неё — не логируйте её вслепую.

## Браузерный relay

```go
// import "github.com/n1s01/proxykit/relay"
server, err := relay.Start(d, relay.Options{})
if err != nil { return err }
defer server.Close()
// Chromium: "--proxy-server=" + server.URL()
```

Relay слушает только `127.0.0.1` на случайном порту, отправляет credentials только
upstream-прокси, удаляет hop-by-hop заголовки и поддерживает обычные HTTP-запросы
через `net/http`, включая повторные запросы клиента.
`Close` останавливает listener, ожидающие подключения, запросы и активные туннели.
По умолчанию timeout заголовков 5 секунд, максимум 128 активных upstream операций.
CONNECT закрывает обе стороны при завершении одного направления; независимое
TCP half-close не реализовано. Idle timeout внутри CONNECT не навязывается.

Relay не имеет локальной авторизации: им может воспользоваться другой процесс
на этой машине. Это локальный адаптер для управляемого браузера, а не сервис
для публикации в сеть. Настройки WebRTC, DNS браузера и bypass rules Chromium
остаются обязанностью приложения.

## Проверка проекта

```sh
go test -race -coverpkg=.,./relay -coverprofile=coverage.out ./...
go vet ./...
go test . -run='^$' -fuzz='^FuzzParse$' -fuzztime=10s
go test . -run='^$' -fuzz='^FuzzParseWithLayout$' -fuzztime=10s
```

Тесты используют реальные локальные сокеты и локальные proxy/target fixtures:
HTTP, HTTPS, SOCKS5, auth failures, target rejection, remote DNS, IPv6 encoding,
TLS trust, отмена, timeout, buffered bytes, payload >64 KiB, HTTP status/redirects,
параллельные проверки и жизненный цикл relay. Внешний интернет не требуется.
Это не верификация коммерческих прокси, Telegram или Chromium.

Те же команды доступны как `make test`, `make race`, `make coverage`, `make vet`,
`make fuzz` (оба fuzz targets). `make check` выполняет vet и race tests. Unit-тесты расположены рядом
с кодом, сетевые интеграционные тесты используют пакет `proxykit_test`
и импортируют публичный API как внешний проект. `-coverpkg=.,./relay` учитывает основной пакет и relay;
исполняемые примеры компилируются, но в процент покрытия библиотеки не входят.

Протокольные источники:
[RFC 1928](https://www.rfc-editor.org/info/rfc1928/),
[RFC 1929](https://www.rfc-editor.org/info/rfc1929/),
[HTTP CONNECT, RFC 9110](https://httpwg.org/specs/rfc9110.html#CONNECT),
[Go net/http](https://pkg.go.dev/net/http).
