#!/bin/sh
set -eu
umask 077
fail() { printf '%s\n' 'Aether startup failed.' >&2; exit 1; }
case "${1:-}" in web|worker|scheduler|release) ;; *) fail ;; esac
[ "$#" -eq 1 ] || fail
case "${PORT:-10000}" in ''|*[!0-9]*) fail ;; esac
[ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || fail
cd /var/www/html
# Suppress pre-bootstrap native diagnostics; the application command returns fixed errors.
php artisan deployment:check --no-interaction >/dev/null 2>&1 || fail
php artisan package:discover --no-interaction >/dev/null 2>&1 || fail
php artisan config:cache --no-interaction >/dev/null 2>&1 || fail
php artisan route:cache --no-interaction >/dev/null 2>&1 || fail
php artisan view:cache --no-interaction >/dev/null 2>&1 || fail
case "$1" in
    web) exec /usr/local/bin/web.sh ;;
    worker) exec php artisan queue:work database --queue=default --sleep=3 --tries=3 --timeout=60 --backoff=30 --no-interaction ;;
    scheduler) exec php artisan schedule:run --no-interaction ;;
    release) exec php artisan migrate --force --no-interaction ;;
esac
