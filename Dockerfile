FROM node:24-bookworm-slim@sha256:91acba91b842bec0bf7ea6f5e09c644c7ccad72c4996ed9616d861d1c7cd60d4 AS assets
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY resources/ resources/
COPY vite.config.js ./
RUN npm run build

FROM php:8.3.35-apache-trixie@sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184 AS platform
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 libonig5 libxml2 libcurl4t64 libsodium23 libpng16-16t64 libjpeg62-turbo libwebp7 libzip5 \
    apache2 apache2-bin libssl3t64 openssl libexpat1 \
    libpq-dev libonig-dev libxml2-dev libcurl4-openssl-dev libsodium-dev \
    libpng-dev libjpeg62-turbo-dev libwebp-dev libzip-dev \
    && docker-php-ext-configure gd --with-jpeg --with-webp \
    && docker-php-ext-install -j2 pdo_pgsql mbstring dom simplexml xml curl sodium gd pcntl opcache zip \
    && apt-get purge -y --auto-remove libpq-dev libonig-dev libxml2-dev libcurl4-openssl-dev libsodium-dev libpng-dev libjpeg62-turbo-dev libwebp-dev libzip-dev \
    && apt-get clean \
    # Fail closed if the configured repositories cannot supply reviewed security fixes.
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' apache2-bin)" ge '2.4.69-1~deb13u1' \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libssl3t64)" ge '3.5.7-1~deb13u3' \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libexpat1)" ge '2.9.0-1~deb13u1' \
    && a2enmod rewrite headers \
    && a2dissite 000-default \
    && a2disconf other-vhosts-access-log \
    && mkdir -p /var/run/aether /var/lock/aether \
    && chown www-data:www-data /var/run/aether /var/lock/aether
WORKDIR /var/www/html

# Composer is copied from an official pinned builder; never installed on the host.
FROM composer:2.10.3@sha256:af98f42dfff7c68ba8d53c2164fd9fde1087b7d449514baa38c418b1f6bc4bac AS composer-binary
FROM platform AS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends unzip
COPY --from=composer-binary /usr/bin/composer /usr/local/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --prefer-dist --no-interaction --no-progress --no-scripts --optimize-autoloader

FROM dependencies AS test
RUN composer install --prefer-dist --no-interaction --no-progress --no-scripts --optimize-autoloader
COPY app/ app/
COPY bootstrap/app.php bootstrap/providers.php bootstrap/
COPY config/ config/
COPY database/ database/
COPY routes/ routes/
COPY resources/ resources/
COPY public/ public/
COPY tests/ tests/
COPY artisan phpunit.xml ./
COPY .env.example ./
COPY docker/database-probe.php docker/database-probe.php
COPY --from=assets /build/public/build/ public/build/
RUN mkdir -p bootstrap/cache storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs storage/app/private

FROM scratch AS context-audit
COPY . /context/

FROM platform AS runtime
COPY --from=dependencies /var/www/html/vendor/ vendor/
COPY --from=assets /build/public/build/ public/build/
COPY app/ app/
COPY bootstrap/app.php bootstrap/providers.php bootstrap/
COPY config/ config/
COPY database/ database/
COPY routes/ routes/
COPY resources/views/ resources/views/
# Developer guides read these files at render time, beyond the compiled Vite assets.
COPY resources/examples/ resources/examples/
COPY public/ public/
COPY artisan composer.json composer.lock ./
COPY docker/apache.conf /etc/apache2/sites-enabled/aether.conf
COPY docker/php.ini /usr/local/etc/php/conf.d/aether.ini
COPY docker/entrypoint.sh docker/web.sh /usr/local/bin/
COPY docker/database-probe.php docker/database-probe.php
RUN apt-get purge -y --auto-remove $PHPIZE_DEPS \
    && apt-get clean \
    && printf 'Listen ${PORT}\n' > /etc/apache2/ports.conf \
    && mkdir -p bootstrap/cache storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs storage/app/private \
    && chown -R www-data:www-data bootstrap/cache storage /var/run/apache2 /var/lock/apache2 \
    && chmod 700 bootstrap/cache storage \
    && chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/web.sh \
    && php -r 'exit(in_array("argon2id", password_algos(), true) && extension_loaded("pcntl") ? 0 : 1);'
ENV PORT=10000 APACHE_RUN_USER=www-data APACHE_RUN_GROUP=www-data APACHE_PID_FILE=/var/run/aether/apache.pid APACHE_RUN_DIR=/var/run/aether APACHE_LOCK_DIR=/var/lock/aether APACHE_LOG_DIR=/tmp
USER www-data
STOPSIGNAL SIGTERM
EXPOSE 10000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["web"]
