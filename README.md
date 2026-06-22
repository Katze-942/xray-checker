## Изменения в этом форке

- Исправлено смешивание профилей на одном `server:port`: каждая share-ссылка теперь проверяется как отдельный профиль, а не заменяется последней ссылкой на тот же endpoint.
- Исправлена проверка разных вариантов одного и того же сервера: RAW, XHTTP, KCP, XDNS и Encryption больше не схлопываются в один результат.
- Добавлена поддержка XDNS share-ссылок: параметр `fm` сохраняется и попадает в итоговый Xray-конфиг как `finalmask`, поэтому XDNS-профили реально запускаются и проверяются.
- Настройки транспорта из share-ссылки сохраняются, но сервер и пользователь профиля не подменяются данными из raw outbound.
- Поддержка PROXY_CHECK_CONCURRENCY, сколько одновременных проверок можно запустить.
# Xray Checker

<div align="center">

[![GitHub Release](https://img.shields.io/github/v/release/kutovoys/xray-checker?color=blue)](https://github.com/kutovoys/xray-checker/releases/latest)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/kutovoys/xray-checker/build-publish.yml)](https://github.com/kutovoys/xray-checker/actions/workflows/build-publish.yml)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/kutovoys/xray-checker/total?logo=github&color=blue)](https://github.com/kutovoys/xray-checker/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/kutovoys/xray-checker?logo=docker&label=pulls)](https://hub.docker.com/r/kutovoys/xray-checker/)
[![GitHub License](https://img.shields.io/github/license/kutovoys/xray-checker?color=greeen)](https://github.com/kutovoys/xray-checker/blob/main/LICENSE)
[![ru](https://img.shields.io/badge/lang-ru-blue)](https://github.com/kutovoys/xray-checker/blob/main/README_RU.md)
[![en](https://img.shields.io/badge/lang-en-red)](https://github.com/kutovoys/xray-checker/blob/main/README.md)

</div>
<div align="center">

[![Documentation](https://img.shields.io/badge/Docs-xray--checker.kutovoy.dev-blue)](https://xray-checker.kutovoy.dev/)
[![DockerHub](https://img.shields.io/badge/DockerHub-kutovoys%2Fxray--checker-blue)](https://hub.docker.com/r/kutovoys/xray-checker/)
[![Live Demo](https://img.shields.io/badge/Demo-live-green)](https://demo-xray-checker.kutovoy.dev/)
[![Telegram Chat](https://img.shields.io/badge/Telegram-Chat-blue?logo=telegram&)](https://t.me/+uZCGx_FRY0tiOGIy)

</div>

Xray Checker is a tool for monitoring proxy server availability with support for VLESS, VMess, Trojan, and Shadowsocks protocols. It automatically tests connections through Xray Core and provides metrics for Prometheus, as well as API endpoints for integration with monitoring systems.

<div align="center">
  <img src=".github/screen/xray-checker.webp" alt="Dashboard Screenshot">
</div>

> [!TIP]
> **Try the Live Demo:** See Xray Checker in action at [demo-xray-checker.kutovoy.dev](https://demo-xray-checker.kutovoy.dev/)

## 🚀 Key Features

- 🔍 Monitoring of Xray proxy servers (VLESS, VMess, Trojan, Shadowsocks)
- 🔄 Automatic configuration updates from subscription (multiple subscriptions supported)
- 📊 Prometheus metrics export with Pushgateway support
- 🌐 REST API with OpenAPI/Swagger documentation
- 🌓 Web interface with dark/light theme
- 🎨 Full web customization (custom logo, styles, or entire template)
- 📄 Public status page for VPN services (no authentication required)
- 📥 Endpoints for monitoring system integration (Uptime Kuma, etc.)
- 🔒 Basic Auth protection for metrics and web interface
- 🐳 Docker and Docker Compose support
- 🌍 Automatic geo files management (geoip.dat, geosite.dat)
- 📝 Flexible configuration loading:
  - URL subscriptions (base64, JSON)
  - Share links (vless://, vmess://, trojan://, ss://)
  - JSON configuration files
  - Folders with configurations

Full list of features available in the [documentation](https://xray-checker.kutovoy.dev/intro/features).

## 🚀 Quick Start

### Docker

```bash
docker run -d \
  -e SUBSCRIPTION_URL=https://your-subscription-url/sub \
  -e PROXY_CHECK_CONCURRENCY=4 \
  -p 2112:2112 \
  kutovoys/xray-checker
```

### Docker Compose

```yaml
services:
  xray-checker:
    image: kutovoys/xray-checker
    environment:
      - SUBSCRIPTION_URL=https://your-subscription-url/sub
      - PROXY_CHECK_CONCURRENCY=4
    ports:
      - "2112:2112"
```

Detailed installation and configuration documentation is available at [xray-checker.kutovoy.dev](https://xray-checker.kutovoy.dev/intro/quick-start)

## 📈 Project Statistics

<a href="https://star-history.com/#kutovoys/xray-checker&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=kutovoys/xray-checker&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=kutovoys/xray-checker&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=kutovoys/xray-checker&type=Date" />
 </picture>
</a>

## 🤝 Contributing

We welcome any contributions to Xray Checker! If you want to help:

1. Fork the repository
2. Create a branch for your changes
3. Make and test your changes
4. Create a Pull Request

For more details on how to contribute, read the [contributor's guide](https://xray-checker.kutovoy.dev/contributing/development-guide).

<p align="center">
Thanks to the all contributors who have helped improve Xray Checker:
</p>
<p align="center">
<a href="https://github.com/kutovoys/xray-checker/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=kutovoys/xray-checker" />
</a>
</p>
<p align="center">
  Made with <a rel="noopener noreferrer" target="_blank" href="https://contrib.rocks">contrib.rocks</a>
</p>

## VPN Recommendation

For secure and reliable internet access, we recommend [BlancVPN](https://getblancvpn.com/pricing?promo=klugscl&ref=xc-readme). Use promo code `KLUGSCL` for 15% off your subscription.
