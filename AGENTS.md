# Repository Guidelines

## Project Structure & Module Organization

This repository contains a Go service with a bundled web UI and a separate Astro documentation site. `main.go` wires configuration, Xray startup, proxy checks, metrics, and HTTP routes. Core packages live in `checker/`, `subscription/`, `xray/`, `config/`, `metrics/`, `models/`, and `logger/`. `web/` contains handlers, OpenAPI YAML, templates, and static assets. `docs/` is the Astro/Starlight docs project, with localized content under `docs/src/content/docs/{ru,fa}/`. Go tests live beside package code as `*_test.go`.

## Build, Test, and Development Commands

- `go mod download` installs Go module dependencies.
- `go test ./...` runs all Go unit tests.
- `go build -o xray-checker .` builds the service binary.
- `SUBSCRIPTION_URL=https://example.invalid/sub go run .` runs locally; replace the URL with a real test subscription.
- `docker build -t xray-checker .` builds the production container image.
- `cd docs && pnpm install` installs documentation dependencies.
- `cd docs && pnpm dev` starts the docs site locally.
- `cd docs && pnpm build` builds static docs.

No root `Makefile` exists; use direct Go, Docker, and pnpm commands.

## Coding Style & Naming Conventions

Use standard Go formatting: run `gofmt` on changed `.go` files. Keep package names short, lowercase, and directory-aligned, such as `checker` or `subscription`. Export only cross-package APIs that are needed. Keep CLI/env names consistent with Kong tags in `config/config.go`, for example `PROXY_CHECK_CONCURRENCY` and `--proxy-check-concurrency`. For docs, keep headings concise and add localized pages only when translated content is available.

## Testing Guidelines

Use Go's standard testing package. Name tests `TestXxx` and keep them beside the code they exercise, following `checker/checker_test.go`, `subscription/parser_test.go`, and `xray/config_test.go`. Add table-driven cases for parser and config changes. Run `go test ./...` before PRs; run `cd docs && pnpm build` when editing docs.

## Commit & Pull Request Guidelines

Recent history mixes conventional prefixes (`fix:`, `feat:`, `ci:`) with plain imperative messages. Prefer `type: short summary`, for example `fix: preserve XDNS finalmask in config`.

Pull requests should follow `.github/PULL_REQUEST_TEMPLATE.md`: describe purpose, mark change type, link issues with `Fixes #...`, confirm self-review, update docs for behavior or config changes, and state local tests run. Include screenshots for visible web UI or docs changes.

## Security & Configuration Tips

Do not commit real subscription URLs, proxy credentials, Pushgateway credentials, or generated local `xray_config.json` data. Prefer environment variables documented in `config/config.go` and README examples. Keep public dashboard changes aligned with the `--web-public` and `--metrics-protected` validation rule.
