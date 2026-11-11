# Music Cloud API

HTTP API, Subsonic `/rest`, tus-загрузки, стриминг и авторизация.

Зависит от `moshms/core` по git-тегу. Для локальной сборки нужен SSH-доступ к core; в CI используется `CORE_READ_TOKEN`.

```bash
cargo build --release
docker build --secret id=core_token,src=core_token.txt -t ghcr.io/moshms/api:dev .
```
