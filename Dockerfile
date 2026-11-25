FROM php:8.4-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends libcurl4-openssl-dev \
    && docker-php-ext-install curl \
    && rm -rf /var/lib/apt/lists/* \
    && sed -ri 's!/var/www/html!/var/www/html/public!g' \
        /etc/apache2/sites-available/000-default.conf /etc/apache2/apache2.conf

COPY public/ /var/www/html/public/
COPY src/ /var/www/html/src/

EXPOSE 80
