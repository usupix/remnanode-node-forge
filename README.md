# RemnaNode Node Forge

Однофайловый установщик небольшой панели управления RemnaNode для Ubuntu/Debian.

## Установка

```bash
chmod 700 install-remnanode-manager.sh
sudo ./install-remnanode-manager.sh
```

Панель слушает только `127.0.0.1:8765`. Откройте SSH-туннель со своего компьютера:

```bash
ssh -L 8765:127.0.0.1:8765 root@SERVER_IP
```

Затем откройте `http://127.0.0.1:8765`. Пароль сохраняется на сервере в
`/root/remnanode-manager-access.txt`.

## Возможности

- проверка и запуск полного `docker-compose.yml` для сервиса `remnanode`;
- автоматическое добавление read-only volume с сертификатами Xray;
- выпуск сертификата Let's Encrypt после проверки DNS;
- Nginx-сайт-приманка на 80 и TLS fallback на `127.0.0.1:8443`;
- генерация VLESS Reality self-steal и Hysteria 2 inbound;
- профили BBR-only и BBR с умеренными сетевыми буферами;
- резервные копии Compose, Nginx и sysctl перед заменой;
- просмотр статуса, версии, перезапусков и последних логов ноды.

При продлении сертификата deploy-hook копирует новые файлы в каталог Xray и
перезапускает существующий контейнер `remnanode`.
