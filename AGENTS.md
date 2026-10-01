# Repository Guidelines

## Project Structure

WP Root Guard is a WordPress security plugin. The main bootstrap is `wp-root-guard.php`; business logic is under `includes/` (`Scanner`, `Cron`, `Baseline`, `Blocker`, settings, logging, and lifecycle classes). Admin controllers and dashboard assets live in `admin/`. Translation files are in `languages/`, documentation in `docs/`, and development/package helpers in `scripts/`. Docker Compose provides the local WordPress/MySQL lab through `docker-compose.yml`. Generated release archives belong in `dist/` and must not be committed.

## Build and Local Development

```bash
docker-compose up -d
bash scripts/init-wp.sh
bash scripts/test-e2e.sh
bash scripts/build-zip.sh
```

`init-wp.sh` starts and initializes the lab. `test-e2e.sh` installs the current package and exercises baseline, uploads, root, core, blocker, and quarantine flows. `build-zip.sh` lints PHP and creates production-ready archives in `dist/`. Use `docker-compose logs -f wordpress` for runtime diagnostics. The repository currently uses ZIP installation in the lab; enable a source bind mount only when deliberately testing live files.

## Coding Style

Use PHP 8.1+ and WordPress conventions: tabs for PHP indentation, snake_case for functions/options, PascalCase for namespaced classes, and prefixed hooks/options such as `wp_root_guard_*`. Preserve namespaces, escaping, nonce checks, capability checks, path validation, and PHPDoc. Keep security-sensitive operations defensive and fail closed. Use `apply_patch` or focused edits; do not commit generated ZIPs, credentials, Docker volumes, or `.git` content.

## Testing Guidelines

Run `php -l` on changed PHP files, `bash -n` on changed shell scripts, `ruby -e 'require "yaml"; YAML.load_file("docker-compose.yml")'` for Compose syntax, and `bash scripts/test-e2e.sh` for integration coverage. Test security changes against both success and failure paths, including permissions, cron/traffic concurrency, quarantine rollback, and false positives.

## Commits and Pull Requests

Use short imperative subjects with optional conventional prefixes, for example `feat: add scan checkpoint`, `fix: prevent duplicate cron runs`, or `docs: update changelog`. Keep commits focused. Pull requests should describe the threat model, affected paths, migration/backward-compatibility impact, validation commands, Docker lab results, and any dashboard screenshots or configuration requirements. Update `README.md`, `readme.txt`, and relevant `docs/` files when behavior or release notes change.

## Security and Configuration

Never include Telegram tokens, passwords, production URLs, database dumps, or private credentials. Treat baseline, whitelist, quarantine, updater, and server-rule changes as security-sensitive. Do not claim protection is verified unless the relevant filesystem, web-server, and scheduler checks have actually passed.
