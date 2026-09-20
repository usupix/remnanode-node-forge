# RemnaNode Node Forge

Однофайловый установщик веб-мастера RemnaNode для Ubuntu и Debian. Он ставит
Docker Engine, Docker Compose, Nginx и Certbot, создаёт `/opt/remnanode` и
показывает адрес панели после установки.

## Быстрая установка

Для публичного репозитория:

```bash
curl -fsSL https://raw.githubusercontent.com/usupix/remnanode-node-forge/main/install-remnanode-manager.sh | sudo bash
```

В конце появятся уникальный адрес и пароль, например:

```text
Open: http://203.0.113.10/4f82c0d8a191e724/
Password: generated-password
```

Путь состоит из 16 случайных символов. Backend панели остаётся на
`127.0.0.1:8765`, а наружу его публикует Nginx только по этому пути. Данные для
входа также сохраняются в `/root/remnanode-manager-access.txt`.

> Пока используется HTTP, пароль не зашифрован на пути до сервера. Используйте
> панель только для первоначальной настройки, затем ограничьте доступ или
> переведите её на HTTPS.

## Что умеет панель

- принять полный `docker-compose.yml` из Remnawave, проверить и отдельно сохранить его;
- получить актуальные теги `remnawave/node` из Docker Hub и выбрать нужную версию либо `latest`;
- фоном скачать выбранный образ, запустить ноду и показать живой прогресс установки;
- автоматически добавить read-only volume сертификатов Xray;
- проверить DNS и выпустить сертификат Let's Encrypt;
- положить `.pem` и `.key` в `/var/lib/remnawave/configs/xray/ssl`;
- обновлять сертификаты deploy-hook’ом Certbot и перезапускать ноду;
- создать Nginx-сайт-приманку и TLS fallback на `127.0.0.1:8443`;
- генерировать VLESS Reality self-steal и Hysteria 2 inbound;
- независимо включать BBR, TCP Fast Open, MTU probing, VPN-буферы и очереди;
- возвращать снятые сетевые настройки к значениям, сохранённым при установке;
- показывать состояние контейнера, образ и перезапуски без перезагрузки страницы;
- транслировать в браузер `docker logs -f` и `docker exec remnanode xlogs`;
- создавать резервные копии Compose, Nginx и sysctl перед изменениями.

Официальная последовательность Remnawave сохранена: Docker → каталог
`/opt/remnanode` → Compose из карточки ноды → `docker compose up -d`.
