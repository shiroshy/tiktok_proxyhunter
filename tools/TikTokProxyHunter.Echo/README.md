# TikTokProxyHunter Echo

Минимальный self-hosted ASP.NET Core сервис для определения TCP client IP. Он не доверяет `X-Forwarded-For`, не хранит access logs, принимает только `GET`, ограничивает request body и использует fixed-window rate limit.

Маршруты:

- `GET /ip` → `{ "ip": "203.0.113.10" }`;
- `GET /health` → `{ "status": "ok" }`.

Разместите сервис самостоятельно за HTTPS reverse proxy. Если reverse proxy завершает TCP-соединение, `RemoteIpAddress` будет адресом reverse proxy. Осознанная настройка trusted proxy/forwarded headers остаётся обязанностью владельца deployment; по умолчанию заголовки клиента игнорируются.

```bash
dotnet run --project tools/TikTokProxyHunter.Echo --urls http://127.0.0.1:5088
```

Добавьте публичный HTTPS `/ip` URL вручную в `ExitIp.CustomEchoEndpoints`. Проект ничего не разворачивает автоматически.
