# TikTokProxyHunter

TikTokProxyHunter — консольный .NET 10 инструмент для сбора только явно опубликованных публичных прокси, определения их реального протокола и проверки HTTPS-доступа к TikTok. Этап 2 добавляет каталог реальных источников, health/cache, безопасный GitHub discovery, определение exit IP, геолокацию, capability-уровни TikTok, стабильность и необязательную Playwright-проверку публичного видео.

Проект принципиально не сканирует случайные IP-диапазоны, подсети или порты, не обходит CAPTCHA/Cloudflare, не использует приватные списки и не пытается эксплуатировать устройства.

## Правовые и практические ограничения

Используйте проект только там, где это разрешено законом, условиями источника и вашей организации. Бесплатные прокси недолговечны и могут перехватывать или подменять трафик. Никогда не передавайте через них пароли, токены, cookies или персональные данные. `Accessible`, `PlaybackVerified` и даже `Recommended` описывают только наблюдение в момент проверки и не доказывают безопасность или будущую работоспособность.

Источник без понятной лицензии или условий находится в каталоге с `enabled: false`. CAPTCHA, authentication и rate limit классифицируются, но не обходятся. Discovery никогда сам не включает найденный источник.

## Структура

```text
TikTokProxyHunter.sln
src/
  TikTokProxyHunter.Core/
  TikTokProxyHunter.Infrastructure/
  TikTokProxyHunter.App/
tests/
  TikTokProxyHunter.Tests/
config/
  proxy-sources.json
  proxy-sources.example.json
  discovered-proxy-sources.json       создаётся discovery-командой
```

Core содержит модели, интерфейсы и чистую логику. Infrastructure содержит источники, cache, parsers, protocol handshakes, TLS, discovery, exit/geo consensus, TikTok verification, stability, Playwright и экспорт. App содержит Generic Host, DI и CLI.

## Источники

Поддержаны `text`, `github-raw`, `csv`, `json`, `html` и `local-file`. Парсер понимает:

```text
IP:PORT
protocol://IP:PORT
protocol://USER:PASSWORD@IP:PORT
IP,PORT
IP PORT
IP:PORT COUNTRY ANONYMITY
IP,PORT,PROTOCOL,COUNTRY
```

JSON поддерживает `ip`, `host`, `address`, `port`, `protocol`, `type`, `username`, `password` и `parserOptions.path`. HTML разбирается AngleSharp.

В `config/proxy-sources.json` включены только проверенные HTTP URL из публичных GitHub-проектов с обнаруженной лицензией. Разные протоколы одного репозитория имеют общую `sourceFamily`; зеркала не повышают доверие как независимые источники.

Метаданные definition:

```json
{
  "name": "stable-source-name",
  "enabled": true,
  "url": "https://raw.githubusercontent.com/owner/repo/main/http.txt",
  "format": "github-raw",
  "declaredProtocol": "Http",
  "category": "GitHubRaw",
  "priority": 50,
  "trustWeight": 0.5,
  "license": "MIT",
  "homepage": "https://github.com/owner/repo",
  "expectedContentType": "text/plain",
  "maximumDownloadBytes": 52428800,
  "minimumExpectedCandidates": 1,
  "sourceFamily": "owner/repo",
  "notes": "Review notes",
  "timeoutSeconds": 20,
  "parserOptions": {}
}
```

## Source health и cache

`refresh-sources` проверяет HTTP status/content type/размер/время, число строк и валидных записей, valid percentage, SHA-256 и точные зеркала. Статусы: `Healthy`, `Degraded`, `Empty`, `InvalidFormat`, `RateLimited`, `AuthenticationRequired`, `Captcha`, `Unavailable`, `Oversized`, `SuspiciousContent`, `Disabled`.

Payload cache находится в `.cache/proxy-sources`. Клиент использует `ETag`, `If-None-Match`, `Last-Modified` и `If-Modified-Since`; HTTP 304 читается из cache. Ограничение применяется к распакованному потоку и защищает от бесконечного chunked response, zip bomb и огромного HTML. Бинарные payload, чрезмерно длинные строки и JSON глубже 64 уровней отклоняются.

## Discovery

`discover-sources` использует только официальный GitHub REST API. HTML GitHub не парсится. Необязательный токен читается из `TIKTOK_PROXY_HUNTER_GITHUB_TOKEN` или переменной из `--github-token-env`, не сохраняется и не логируется. Без токена команда сохраняет резерв rate limit и останавливается без бесконечных повторов.

Результаты имеют статусы `Candidate`, `AcceptedForReview`, `Duplicate`, `Rejected`, `Suspicious`, `Unavailable` и записываются в:

```text
config/discovered-proxy-sources.json
output/<run>/source-discovery-report.json
```

Импорт по умолчанию показывает diff. Даже с `--apply` definitions добавляются выключенными:

```bash
dotnet run --project src/TikTokProxyHunter.App -- import-discovered-sources
dotnet run --project src/TikTokProxyHunter.App -- import-discovered-sources --apply
```

## Streaming и лимиты

Mass processing использует bounded `System.Threading.Channels`, backpressure и фиксированные worker pools. Отдельная задача на каждый proxy не создаётся. `MaximumCandidates: 0` снимает пользовательский лимит, но `DeduplicationMemoryLimit`, payload limits и channel capacity продолжают ограничивать память.

Основные параметры находятся в `appsettings.json`:

```json
"MaximumSourcePayloadBytes": 52428800,
"MaximumCandidates": 250000,
"ChannelCapacity": 5000,
"DeduplicationMemoryLimit": 1000000,
"CheckpointIntervalSeconds": 30
```

## Exit IP и геолокация

После protocol probe минимум два HTTPS provider должны согласовать фактический exit IP. Он сравнивается с прямым IP; совпадение получает `SameAsDirectIp`. В запросы не добавляются пользовательские cookies, tokens или identifiers.

Geo resolver кэширует результат по exit IP. Страна, ASN, организация и город согласуются независимо: несовпадающие города не портят подтверждённую страну. Решения страны: `ConfirmedRussia`, `LikelyRussia`, `ConfirmedNonRussia`, `LikelyNonRussia`, `Unknown`, `Conflicting`. Confirmed/likely RU исключаются по умолчанию; unknown/conflicting допускаются к fast check, но не к `Recommended`. Успех TikTok не считается доказательством страны.

Опциональный local provider читает пользовательские MMDB-compatible country и ASN базы через `MaxMind.Db`. Базы не входят в репозиторий и не скачиваются автоматически. Укажите пути в `Geo.LocalDatabase` либо через `--geo-country-db`/`--geo-asn-db`, затем выполните `validate-geo-database`. Пользователь самостоятельно получает совместимую базу и принимает её лицензионные условия.

`all-real` пишет детерминированную воронку в `pipeline-funnel.json` и `pipeline-funnel.txt`. Между дорогими этапами применяются `PipelineLimits`; порядок определяется pre-score, затем каноническим endpoint key.

## TikTok capabilities

Уровни хранятся отдельно:

- `TikTokDnsAndTunnel`;
- `TikTokHomepage`;
- `TikTokMobilePage`;
- `TikTokOEmbed`;
- `TikTokPublicVideoPage`;
- `TikTokBrowserPlayback`.

Публичный video URL никогда не хардкодится. Добавьте его в `TikTok.PublicVideoTestUrls` или передайте `--tiktok-video-url`. URL должен принадлежать TikTok и содержать video id. Проверяются TLS, домен, meta/rehydration данные, identity video id и официальный oEmbed. oEmbed — дополнительный сигнал, а не доказательство playback.

## Playwright

Browser verification выключен по умолчанию и запускается только для лучших fast-check кандидатов. Контекст всегда чистый, системный профиль и cookies не используются, TLS errors не игнорируются. CAPTCHA только классифицируется. SOCKS4/SOCKS4a и неподдерживаемые credential-сценарии получают `Skipped`.

После первой сборки установите Chromium явно:

```bash
powershell -ExecutionPolicy Bypass -File "src/TikTokProxyHunter.App/bin/Debug/net10.0/playwright.ps1" install chromium
```

Без установленного browser executable результат будет `Unavailable`, а не ложный успех.

## Команды

```bash
dotnet restore
dotnet build TikTokProxyHunter.sln
dotnet test TikTokProxyHunter.sln

# Этап 1
dotnet run --project src/TikTokProxyHunter.App -- collect
dotnet run --project src/TikTokProxyHunter.App -- probe --input output/<run>/normalized.jsonl
dotnet run --project src/TikTokProxyHunter.App -- check-tiktok --input output/<run>/working-proxies.json
dotnet run --project src/TikTokProxyHunter.App -- all

# Этап 2
dotnet run --project src/TikTokProxyHunter.App -- refresh-sources
dotnet run --project src/TikTokProxyHunter.App -- discover-sources
dotnet run --project src/TikTokProxyHunter.App -- import-discovered-sources
dotnet run --project src/TikTokProxyHunter.App -- resolve-exit --input <file>
dotnet run --project src/TikTokProxyHunter.App -- resolve-geo --input <exit-ip-results.jsonl>
dotnet run --project src/TikTokProxyHunter.App -- verify-tiktok --input <file> --tiktok-video-url <url>
dotnet run --project src/TikTokProxyHunter.App -- verify-browser --input <file> --tiktok-video-url <url>
dotnet run --project src/TikTokProxyHunter.App -- all-real --max-candidates 2000

# Этап 2.1
dotnet run --project src/TikTokProxyHunter.App -- validate-geo-database
dotnet run --project src/TikTokProxyHunter.App -- browser-doctor
dotnet run --project src/TikTokProxyHunter.App -- all-real --max-candidates 1000 --allow-unknown-geo --allow-conflicting-geo
dotnet run --project src/TikTokProxyHunter.App -- verify-browser-live --input output/<run>/best-proxies.json --tiktok-video-file config/tiktok-test-videos.local.json --browser-limit 10
dotnet run --project src/TikTokProxyHunter.App -- export-user-list --input output/<run>/best-proxies.json --output output/<run>/user-proxies
dotnet run --project src/TikTokProxyHunter.App -- explain-proxy --input output/<run>/best-proxies.json --proxy "IP:PORT"
```

Дополнительные параметры:

```text
--github-token-env
--include-source
--exclude-source
--max-candidates
--reject-country
--preferred-country
--tiktok-video-url
--browser-check
--browser-limit
--stability-attempts
--resume
--allow-unknown-geo
--allow-conflicting-geo
--reject-likely-ru
--minimum-geo-confidence
--geo-country-db
--geo-asn-db
--tiktok-video-file
--proxy
```

`--resume` применяется только при совпадении configuration hash. `run-state.private.json` может содержать credentials, необходимые для продолжения, поэтому защитите его ACL средствами ОС.

## Экспорт этапа 2

```text
sources-health.json
sources-health.txt
source-discovery-report.json
exit-ip-results.jsonl
geo-results.jsonl
tiktok-capabilities.jsonl
stability-results.jsonl
browser-verification.jsonl
best-proxies.json
recommended-proxies.txt
page-only-proxies.txt
rejected-russian-exits.jsonl
run-checkpoint.json
pipeline-funnel.json
pipeline-funnel.txt
```

Credentials не выводятся в публичные TXT. `best-proxies.json` содержит protocol, exit IP, country/ASN, source families, latency, stability, capability/browser results, score и recommendation class.

`config/tiktok-test-videos.local.json` игнорируется Git и предназначен для локальных публичных video URL. Скопируйте структуру из `config/tiktok-test-videos.example.json`. Разрешены только HTTPS TikTok video pages без token/cookie/session query parameters. Без такого файла video и browser стадии получают `NotRun`.

`export-user-list` создаёт `recommended.txt`, `playback-verified.txt`, `page-only.txt`, отдельный `unverified-country.txt`, `proxychains.conf`, инструкции браузера и summary. Credentials исключаются из каждого пользовательского файла; системные proxy settings не изменяются.

## Тесты и live checks

Автоматические тесты не используют публичные прокси или настоящий TikTok. Локальные TCP/TLS стенды и чистые classifiers проверяют handshakes, strict TLS, CAPTCHA, timeout, source cache/304, fingerprints, streaming, consensus, RU policy, oEmbed, stability, checkpoint и browser result classification.

Live network checks выполняются только явными командами `refresh-sources`, `discover-sources` или `all-real`. Никогда не интерпретируйте отсутствие network access в среде запуска как успешную проверку.

## Этап 2.2: независимые capabilities и Embed Player

`TikTokHomepage`, диагностическая `TikTokMobilePage`, post page, oEmbed, официальный `TikTokEmbedPlayer`, stability и browser playback теперь являются независимыми наблюдениями. Ошибка mobile page не блокирует stability или video/player checks. Неудача exit-IP provider также не блокирует техническую TikTok-проверку, но endpoint без согласованного exit IP и достаточной geo confidence никогда не получает `Recommended`.

Exit-IP pool выбирает разные provider families, использует health/cooldown circuit breaker, HTTPS, явно настроенный HTTP fallback и необязательные самостоятельно размещённые `ExitIp.CustomEchoEndpoints`. Пример безопасного echo-приложения находится в `tools/TikTokProxyHunter.Echo`; оно берёт адрес из TCP peer и по умолчанию не доверяет `X-Forwarded-For`.

Video URL задаются только локально в `config/tiktok-test-videos.local.json` по шаблону `config/tiktok-test-videos.example.json`. Разрешены HTTPS post URL вида `https://www.tiktok.com/@name/video/POST_ID` без query parameters. Из `POST_ID` строится официальный URL `https://www.tiktok.com/player/v1/POST_ID`. HTML player — только предварительный signal; browser playback требует одновременно прогресса `currentTime`, отсутствия media error и успешного media response. Полные подписанные media URL и query tokens не сохраняются.

Если локальный video config отсутствует, video/player/browser capability получает `NotConfigured` с причиной; положительный результат не симулируется.

```bash
dotnet run --project src/TikTokProxyHunter.App -- test-exit-providers
dotnet run --project src/TikTokProxyHunter.App -- validate-tiktok-videos --input config/tiktok-test-videos.local.json
dotnet run --project src/TikTokProxyHunter.App -- all-real --max-candidates 3000 --allow-unknown-geo --allow-conflicting-geo
dotnet run --project src/TikTokProxyHunter.App -- retry-exit-resolution --input output/<run>/best-proxies.json --only-tiktok-accessible
dotnet run --project src/TikTokProxyHunter.App -- continue-verification --input output/<run>/best-proxies.json --tiktok-video-file config/tiktok-test-videos.local.json --browser-check
dotnet run --project src/TikTokProxyHunter.App -- verify-browser-live --input output/<run>/best-proxies.json --tiktok-video-file config/tiktok-test-videos.local.json --browser-limit 10
dotnet run --project src/TikTokProxyHunter.App -- export-user-list --input output/<run>/best-proxies.json --output output/<run>/user-proxies
```

`capability-matrix.json` показывает пересечения независимых проверок. Пользовательский экспорт разделяет `recommended.txt`, `full-playback-verified.txt`, `embed-playback-verified.txt`, `stable-page-only.txt`, `geo-unresolved-but-working.txt` и `rejected.txt`. Credentials исключаются из всех этих файлов.

## Windows Desktop

WPF-приложение `TikTokProxyHunter.Desktop` использует тот же DI-контейнер и `IHunterRunService`, что и CLI: консольный вывод не парсится, pipeline-логика во ViewModel не дублируется. Интерфейс предлагает быстрый поиск, структурированный прогресс, корректную отмену с checkpoint, результаты с фильтрами и ленивой выдачей, подробное объяснение, источники, историю, настройки и диагностику.

```powershell
dotnet run --project src/TikTokProxyHunter.Desktop

dotnet publish src/TikTokProxyHunter.Desktop `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -o publish/win-x64
```

Chromium не встраивается в executable и устанавливается только после явного подтверждения. Пользовательские настройки сохраняются атомарно в `%LocalAppData%\TikTokProxyHunter\desktop-settings.json`; cookies, proxy credentials, GitHub token и подписанные media URL туда не записываются. Приложение не изменяет системный proxy Windows.

## Не входит в проект

- БД, Entity Framework и фоновый планировщик;
- VPN/TUN-клиент и изменение системных proxy-настроек;
- активное сканирование IP, подсетей или произвольных портов;
- обход CAPTCHA, authentication или anti-bot;
- автоматическое включение найденных источников;
- сохранённые browser-профили и device-fingerprint spoofing;
- встроенное шифрование credentials — защита private-файлов делегирована ACL ОС.
